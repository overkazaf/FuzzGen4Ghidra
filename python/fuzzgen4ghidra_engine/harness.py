from pathlib import Path
from dataclasses import replace
import re

from jinja2 import Environment, FileSystemLoader

from .models import ParamInfo, ParamType
from .platform import TargetInfo
from .params import INT_TYPES, FLOAT_TYPES

TEMPLATE_DIR = Path(__file__).parent / "templates"

JNI_MODES = ("off", "env", "onload")
CALL_MODES = ("auto", "dlsym", "address")


class _ParamRenderer:
    """Generates C code snippets for one parameter's deserialization and cleanup."""

    def __init__(self, param: ParamInfo, all_params: list[ParamInfo]):
        self.p = param
        self.all_params = all_params

    @property
    def deserialize_code(self) -> str:
        p = self.p
        indent = "    "
        if p.type == ParamType.BUFFER:
            remaining = sum(other.type == ParamType.BUFFER for other in self.all_params
                            if other.index >= p.index)
            return (
                f"{indent}/* {p.name} (buffer) */\n"
                f"{indent}size_t {p.name}_len = (_fz_len > _fz_off) ? (_fz_len - _fz_off) / {remaining} : 0;\n"
                f"{indent}uint8_t *{p.name} = NULL;\n"
                f"{indent}if ({p.name}_len > 0 && _fz_off + {p.name}_len <= _fz_len) {{\n"
                f"{indent}    {p.name} = (uint8_t *)(_fz_buf + _fz_off);\n"
                f"{indent}    _fz_off += {p.name}_len;\n"
                f"{indent}}}"
            )
        elif p.type == ParamType.INT:
            if self._is_length_for_buffer():
                return f"{indent}/* {p.name} (length - derived from buffer) */"
            return (
                f"{indent}/* {p.name} */\n"
                f"{indent}{p.c_type} {p.name} = 0;\n"
                f"{indent}consume_bytes(_fz_buf, _fz_len, &_fz_off, &{p.name}, sizeof({p.name}));"
            )
        elif p.type == ParamType.FLOAT:
            return (
                f"{indent}/* {p.name} */\n"
                f"{indent}{p.c_type} {p.name} = 0;\n"
                f"{indent}consume_bytes(_fz_buf, _fz_len, &_fz_off, &{p.name}, sizeof({p.name}));"
            )
        elif p.type == ParamType.STRUCT_PTR:
            return (
                f"{indent}/* {p.name} (struct pointer - treat as raw bytes for MVP) */\n"
                f"{indent}uint8_t {p.name}_buf[256] = {{0}};\n"
                f"{indent}size_t {p.name}_avail = (_fz_len > _fz_off) ? _fz_len - _fz_off : 0;\n"
                f"{indent}if ({p.name}_avail > 256) {p.name}_avail = 256;\n"
                f"{indent}if ({p.name}_avail > 0) memcpy({p.name}_buf, _fz_buf + _fz_off, {p.name}_avail);\n"
                f"{indent}_fz_off += {p.name}_avail;\n"
                f"{indent}void *{p.name} = {p.name}_buf;"
            )
        elif p.type == ParamType.FUNC_PTR:
            return f"{indent}/* {p.name} (function pointer - stubbed to NULL) */\n{indent}void *{p.name} = NULL;"
        else:
            return (
                f"{indent}/* {p.name} (unknown type: {p.c_type}) */\n"
                f"{indent}uint8_t {p.name}_raw[{p.size}] = {{0}};\n"
                f"{indent}consume_bytes(_fz_buf, _fz_len, &_fz_off, {p.name}_raw, {p.size});\n"
                f"{indent}void *{p.name} = {p.name}_raw;"
            )

    @property
    def cleanup_code(self) -> str:
        return ""

    @property
    def call_arg(self) -> str:
        p = self.p
        if p.type == ParamType.BUFFER:
            return f"({p.c_type}){p.name}"
        elif p.type == ParamType.INT:
            if self._is_length_for_buffer():
                buf_param = self._find_buffer_owner()
                if buf_param:
                    return f"({p.c_type}){buf_param.name}_len"
            return p.name
        elif p.type == ParamType.STRUCT_PTR:
            return f"({p.c_type}){p.name}"
        elif p.type == ParamType.FUNC_PTR:
            return "NULL"
        elif p.type == ParamType.FLOAT:
            return p.name
        return f"*({p.c_type} *)({p.name}_raw)"

    def _is_length_for_buffer(self) -> bool:
        for other in self.all_params:
            if other.type == ParamType.BUFFER and other.length_param == self.p.index:
                return True
        return False

    def _find_buffer_owner(self) -> ParamInfo | None:
        for other in self.all_params:
            if other.type == ParamType.BUFFER and other.length_param == self.p.index:
                return other
        return None


class HarnessGenerator:
    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            keep_trailing_newline=True,
        )

    @staticmethod
    def resolve_call_mode(call_mode: str, is_exported: bool) -> str:
        if call_mode not in CALL_MODES:
            raise ValueError(f"call_mode must be one of {CALL_MODES}, got {call_mode!r}")
        if call_mode == "auto":
            return "dlsym" if is_exported else "address"
        return call_mode

    @staticmethod
    def resolve_jni_mode(jni_mode: str, func_name: str) -> str:
        if jni_mode not in ("auto",) + JNI_MODES:
            raise ValueError(f"jni_mode must be one of auto/{JNI_MODES}, got {jni_mode!r}")
        if jni_mode != "auto":
            return jni_mode
        if func_name == "JNI_OnLoad":
            return "onload"
        if func_name.startswith("Java_"):
            return "env"
        return "off"

    def generate(
        self,
        func_name: str,
        func_addr: int,
        params: list[ParamInfo],
        target_binary: str,
        fmt: str = "afl",
        target_info: TargetInfo | None = None,
        func_vaddr: int | None = None,
        is_exported: bool = False,
        anchor_symbol: str | None = None,
        anchor_vaddr: int | None = None,
        call_mode: str = "auto",
        jni_mode: str = "off",
        run_jni_onload: bool = False,
        return_type: str = "int",
    ) -> str:
        """Render one harness.

        ``jni_mode="env"`` expects ``params`` to already exclude the leading
        ``JNIEnv*``/``jobject`` arguments (the engine filters them); the
        generated signature re-adds them in front of the fuzzed parameters.
        """
        info = target_info or TargetInfo()
        mode = self.resolve_call_mode(call_mode, is_exported)
        jni = self.resolve_jni_mode(jni_mode, func_name)
        vaddr = func_vaddr if func_vaddr is not None else func_addr

        # Generated locals must not inherit arbitrary names from the target.
        local_params = [replace(p, name=f"_fz_arg{p.index}") for p in params]
        renderers = [_ParamRenderer(p, local_params) for p in local_params]
        # Scalars first, then fixed-size pointer storage, then split the
        # remaining bytes equally between buffers. Calls keep signature order.
        deserialize_order = sorted(renderers, key=lambda r:
            (2 if r.p.type == ParamType.BUFFER else
             1 if r.p.type == ParamType.STRUCT_PTR else 0, r.p.index))
        tpl = self.env.get_template(f"{fmt}_harness.c.j2")

        if jni == "onload":
            param_signature = "JavaVM *vm, void *reserved"
            call_args = "fz_jni_vm(), NULL"
        elif jni == "env":
            param_sig_parts = [f"{p.c_type} {p.name}" for p in params]
            rest = ", " + ", ".join(param_sig_parts) if param_sig_parts else ""
            param_signature = f"JNIEnv *env, jobject thiz{rest}"
            rest_args = ", " + ", ".join(r.call_arg for r in renderers) if renderers else ""
            call_args = f"&_fz_env, _fz_thiz{rest_args}"
        else:
            param_sig_parts = [f"{p.c_type} {p.name}" for p in params]
            param_signature = ", ".join(param_sig_parts) if param_sig_parts else "void"
            call_args = ", ".join(r.call_arg for r in renderers)

        return tpl.render(
            func_name=func_name,
            func_addr=hex(func_addr),
            target_binary=target_binary,
            return_type=return_type,
            param_signature=param_signature,
            params=deserialize_order,
            call_args=call_args,
            platform=info.platform,
            android=info.is_android,
            arch=info.arch,
            triple=info.triple or "",
            android_abi=info.android_abi or "",
            ndk_api=info.ndk_api,
            func_vaddr_hex=hex(vaddr),
            is_exported=is_exported,
            anchor_symbol=anchor_symbol or info.anchor_symbol or "",
            anchor_vaddr_hex=hex(anchor_vaddr or 0),
            call_mode=mode,
            jni_mode=jni,
            run_jni_onload=run_jni_onload,
        )

    def generate_types_header(self, structs: list, params: list[ParamInfo] | None = None) -> str:
        tpl = self.env.get_template("types.h.j2")
        opaque_types = set()
        defined = {getattr(s, "name", "") for s in structs}
        for p in params or []:
            if p.type != ParamType.STRUCT_PTR:
                continue
            base = re.sub(r"\b(const|volatile|restrict)\b", "", p.c_type).replace("*", "").strip()
            if (re.fullmatch(r"[A-Za-z_]\w*", base) and base not in defined
                    and base not in INT_TYPES | FLOAT_TYPES | {"void"}):
                opaque_types.add(base)
        return tpl.render(structs=structs, opaque_types=sorted(opaque_types))

    def generate_jni_header(self) -> str:
        tpl = self.env.get_template("jni_stub.h.j2")
        return tpl.render()

    def generate_makefile(
        self,
        func_name: str,
        target_binary: str,
        fmt: str = "afl",
        target_info: TargetInfo | None = None,
        jni_mode: str = "off",
        include_jni: bool | None = None,
    ) -> str:
        info = target_info or TargetInfo()
        if include_jni is None:
            include_jni = jni_mode != "off"
        tpl = self.env.get_template("Makefile.j2")
        return tpl.render(
            func_name=func_name,
            target_binary=target_binary,
            fmt=fmt,
            platform=info.platform,
            android=info.is_android,
            triple=info.triple or "aarch64-linux-android",
            android_abi=info.android_abi or "arm64-v8a",
            ndk_api=info.ndk_api,
            jni_mode=jni_mode,
            include_jni=include_jni,
        )

    def generate_build_script(
        self, func_name: str, target_binary: str, fmt: str,
        target_info: TargetInfo | None = None,
    ) -> str:
        info = target_info or TargetInfo()
        tpl = self.env.get_template("build_android.sh.j2")
        return tpl.render(
            func_name=func_name,
            target_binary=target_binary,
            fmt=fmt,
            triple=info.triple or "aarch64-linux-android",
            android_abi=info.android_abi or "arm64-v8a",
            ndk_api=info.ndk_api,
        )

    def generate_run_script(
        self, func_name: str, target_binary: str, fmt: str,
        target_info: TargetInfo | None = None,
    ) -> str:
        info = target_info or TargetInfo()
        tpl = self.env.get_template("run_on_device.sh.j2")
        return tpl.render(
            func_name=func_name,
            target_binary=target_binary,
            fmt=fmt,
            android_abi=info.android_abi or "arm64-v8a",
        )
