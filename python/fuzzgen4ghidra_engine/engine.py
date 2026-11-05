import logging
import os

from .harness import HarnessGenerator
from .models import FuzzTarget
from .params import recover_params_from_ghidra
from .platform import (
    TargetInfo,
    detect_target,
    exported_vaddrs,
    normalize_vaddr,
    rebased_to_vaddr,
)
from .scorer import TargetScorer

logger = logging.getLogger("fuzzgen4ghidra")


class FuzzGenEngine:
    def __init__(self):
        self.project = None
        self.binary_path: str | None = None
        self.target_info: TargetInfo | None = None
        self._scorer: TargetScorer | None = None
        self._harness_gen = HarnessGenerator()
        self._exported_raw: set[int] = set()

    def init(self, binary_path: str) -> dict:
        import angr

        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.binary_path = binary_path
        self.target_info = detect_target(self.project, binary_path)

        main_obj = self.project.loader.main_object
        self._exported_raw = exported_vaddrs(main_obj)
        mapped_base = int(getattr(main_obj, "mapped_base", 0) or 0)
        exported_rebased = {v + mapped_base for v in self._exported_raw}

        self._scorer = TargetScorer(
            exported_addrs=exported_rebased,
            entry_addr=self.project.entry,
        )

        info = self.target_info
        logger.info(
            "Loaded binary: %s (%s, %s, %d exported symbols)",
            binary_path, self.project.arch.name, info.platform, len(self._exported_raw),
        )
        return {
            "arch": self.project.arch.name,
            "entry": hex(self.project.entry),
            "binary": binary_path,
            "target_binary": os.path.basename(binary_path),
            "platform": info.platform,
            "android": info.is_android,
            "binary_format": info.binary_format,
            "bits": info.bits,
            "triple": info.triple,
            "android_abi": info.android_abi,
            "ndk_api": info.ndk_api,
            "soname": info.soname,
            "deps": info.deps,
            "anchor_symbol": info.anchor_symbol,
            "exported_functions": len(self._exported_raw),
        }

    def scan_targets(self, ghidra_functions: list[dict], progress_callback=None) -> list[dict]:
        if self.project is None:
            raise RuntimeError("Binary not loaded — call init first")

        self.project.analyses.CFGFast(normalize=True, show_progressbar=False)
        kb_funcs = self.project.kb.functions

        ghidra_map = {}
        for gf in ghidra_functions:
            addr = int(gf["address"], 16) if isinstance(gf["address"], str) else gf["address"]
            ghidra_map[addr] = gf

        targets: list[FuzzTarget] = []
        total = len(kb_funcs)
        main_obj = self.project.loader.main_object

        for i, (addr, func) in enumerate(kb_funcs.items()):
            if func.is_simprocedure or func.is_plt:
                continue
            if len(func.graph) < 2:
                continue

            callee_names = []
            for site in func.get_call_sites():
                target_addr = func.get_call_target(site)
                if target_addr is not None and target_addr in kb_funcs:
                    callee_names.append(kb_funcs[target_addr].name)

            # kb_funcs is keyed by CLE's rebased address; Ghidra speaks raw
            # ELF virtual addresses.
            raw_addr = normalize_vaddr(self.binary_path, main_obj, addr)

            gf = ghidra_map.get(raw_addr, {})
            has_buffer = gf.get("has_buffer_param", False)
            param_count = gf.get("param_count", func.num_arguments or 0)
            name = gf.get("name", func.name)
            is_exported = raw_addr in self._exported_raw

            target = self._scorer.score_function(
                addr=raw_addr, name=name, num_blocks=len(func.graph),
                callee_names=callee_names, param_count=param_count,
                is_exported=is_exported, call_depth=0,
                ghidra_has_buffer_param=has_buffer,
            )
            targets.append(target)

            if progress_callback and i % 50 == 0:
                progress_callback({"scanned": i, "total": total})

        targets.sort(key=lambda t: t.score, reverse=True)
        return [t.to_dict() for t in targets]

    def analyze_params(self, func_addr: int, ghidra_signature: dict) -> list[dict]:
        params = recover_params_from_ghidra(ghidra_signature)
        return [p.to_dict() for p in params]

    def _symbol_vaddr(self, name: str | None) -> int | None:
        if not name or self.project is None:
            return None
        obj = self.project.loader.main_object
        for sym in obj.symbols:
            if sym.name == name and sym.is_function:
                return rebased_to_vaddr(obj, int(sym.rebased_addr))
        return None

    def generate_harness(
        self,
        func_addr: int,
        func_name: str,
        ghidra_signature: dict,
        target_binary: str,
        fmt: str = "afl",
        output_dir: str | None = None,
        target_platform: str = "auto",
        ndk_api: int | None = None,
        call_mode: str = "auto",
        jni_mode: str = "auto",
        run_jni_onload: bool | None = None,
    ) -> dict:
        info = (self.target_info or TargetInfo()).with_overrides(target_platform, ndk_api)

        if self.project is None:
            # Degraded mode: no binary was loaded, so emit a host harness and
            # treat the supplied address as the ELF virtual address.
            raw_addr = func_addr
            is_exported = False
        else:
            obj = self.project.loader.main_object
            raw_addr = normalize_vaddr(self.binary_path, obj, func_addr)
            is_exported = raw_addr in self._exported_raw

        params = recover_params_from_ghidra(ghidra_signature)
        jni = self._harness_gen.resolve_jni_mode(jni_mode, func_name)
        if jni != "off" and not info.is_android:
            # jni.h comes from the NDK; a host JVM library would need its own
            # include path, which we cannot assume, so emit a plain harness.
            logger.warning(
                "JNI stubs are Android-only; ignoring jni_mode=%s for a %s target",
                jni, info.platform,
            )
            jni = "off"
        if jni == "onload":
            # JNI_OnLoad(JavaVM*, void*) - nothing fuzzable in the signature.
            params = []
        elif jni == "env":
            # Java_* natives start with (JNIEnv*, jobject|jclass); the harness
            # synthesises those and fuzzes everything after them.
            params = recover_params_from_ghidra({
                **ghidra_signature, "params": ghidra_signature.get("params", [])[2:]
            })

        if run_jni_onload is None:
            run_jni_onload = jni != "onload"
        # JNI only exists on Android; a host build must not include <jni.h>.
        run_jni_onload = bool(run_jni_onload) and info.is_android and jni != "onload"

        anchor = info.anchor_symbol
        anchor_vaddr = self._symbol_vaddr(anchor)

        harness_code = self._harness_gen.generate(
            func_name, raw_addr, params, target_binary, fmt,
            target_info=info,
            func_vaddr=raw_addr,
            is_exported=is_exported,
            anchor_symbol=anchor,
            anchor_vaddr=anchor_vaddr,
            call_mode=call_mode,
            jni_mode=jni,
            run_jni_onload=run_jni_onload,
        )
        types_header = self._harness_gen.generate_types_header([], params)
        makefile = self._harness_gen.generate_makefile(
            func_name, target_binary, fmt, target_info=info,
            jni_mode=jni, include_jni=(jni != "off" or run_jni_onload),
        )
        jni_header = self._harness_gen.generate_jni_header()

        result = {
            "harness_code": harness_code,
            "types_header": types_header,
            "makefile": makefile,
            "func_name": func_name,
            "fmt": fmt,
            "platform": info.platform,
            "android": info.is_android,
            "android_abi": info.android_abi,
            "triple": info.triple,
            "ndk_api": info.ndk_api,
            "call_mode": self._harness_gen.resolve_call_mode(call_mode, is_exported),
            "jni_mode": jni,
            "run_jni_onload": run_jni_onload,
            "func_vaddr": hex(raw_addr),
            "is_exported": is_exported,
            "anchor_symbol": anchor,
        }

        if info.is_android:
            result["build_script"] = self._harness_gen.generate_build_script(
                func_name, target_binary, fmt, target_info=info,
            )
            result["run_script"] = self._harness_gen.generate_run_script(
                func_name, target_binary, fmt, target_info=info,
            )

        if output_dir:
            files = {
                f"harness_{func_name}.c": harness_code,
                "types.h": types_header,
                "Makefile": makefile,
            }
            if jni != "off" or run_jni_onload:
                files["jni_stub.h"] = jni_header
            if info.is_android:
                files["build_android.sh"] = result["build_script"]
                files["run_on_device.sh"] = result["run_script"]

            os.makedirs(output_dir, exist_ok=True)
            for name, content in files.items():
                mode = 0o755 if name.endswith(".sh") else None
                path = os.path.join(output_dir, name)
                with open(path, "w") as f:
                    f.write(content)
                if mode:
                    os.chmod(path, mode)

            seeds_dir = os.path.join(output_dir, "seeds")
            os.makedirs(seeds_dir, exist_ok=True)
            with open(os.path.join(seeds_dir, "seed_000"), "wb") as f:
                min_size = sum(p.size for p in params if p.type.value != "func_ptr")
                f.write(b"\x00" * max(min_size, 16))

            result["files"] = sorted(files) + ["seeds/seed_000"]
            result["output_dir"] = output_dir

        return result
