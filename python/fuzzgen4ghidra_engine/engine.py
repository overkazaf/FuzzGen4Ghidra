import logging
import os

from .harness import HarnessGenerator
from .models import FuzzTarget
from .params import recover_params_from_ghidra
from .scorer import TargetScorer

logger = logging.getLogger("fuzzgen4ghidra")


class FuzzGenEngine:
    def __init__(self):
        self.project = None
        self.binary_path: str | None = None
        self._scorer: TargetScorer | None = None
        self._harness_gen = HarnessGenerator()

    def init(self, binary_path: str) -> dict:
        import angr
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.binary_path = binary_path

        main_obj = self.project.loader.main_object
        exported = set()
        for sym in main_obj.symbols:
            if sym.is_export and sym.is_function:
                exported.add(sym.rebased_addr)

        self._scorer = TargetScorer(
            exported_addrs=exported,
            entry_addr=self.project.entry,
        )

        logger.info("Loaded binary: %s (%s)", binary_path, self.project.arch.name)
        return {
            "arch": self.project.arch.name,
            "entry": hex(self.project.entry),
            "binary": binary_path,
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

            gf = ghidra_map.get(addr, {})
            has_buffer = gf.get("has_buffer_param", False)
            param_count = gf.get("param_count", func.num_arguments or 0)
            name = gf.get("name", func.name)
            is_exported = addr in self._scorer.exported_addrs

            target = self._scorer.score_function(
                addr=addr, name=name, num_blocks=len(func.graph),
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

    def generate_harness(
        self,
        func_addr: int,
        func_name: str,
        ghidra_signature: dict,
        target_binary: str,
        fmt: str = "afl",
        output_dir: str | None = None,
    ) -> dict:
        params = recover_params_from_ghidra(ghidra_signature)
        harness_code = self._harness_gen.generate(func_name, func_addr, params, target_binary, fmt)
        types_header = self._harness_gen.generate_types_header([])
        makefile = self._harness_gen.generate_makefile(func_name, target_binary, fmt)

        result = {
            "harness_code": harness_code,
            "types_header": types_header,
            "makefile": makefile,
            "func_name": func_name,
            "fmt": fmt,
        }

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            seeds_dir = os.path.join(output_dir, "seeds")
            os.makedirs(seeds_dir, exist_ok=True)
            with open(os.path.join(output_dir, f"harness_{func_name}.c"), "w") as f:
                f.write(harness_code)
            with open(os.path.join(output_dir, "types.h"), "w") as f:
                f.write(types_header)
            with open(os.path.join(output_dir, "Makefile"), "w") as f:
                f.write(makefile)
            with open(os.path.join(seeds_dir, "seed_000"), "wb") as f:
                min_size = sum(p.size for p in params if p.type.value != "func_ptr")
                f.write(b"\x00" * max(min_size, 16))
            result["output_dir"] = output_dir

        return result
