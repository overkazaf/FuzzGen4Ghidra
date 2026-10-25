from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from .models import ParamInfo, ParamType

TEMPLATE_DIR = Path(__file__).parent / "templates"


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
            return (
                f"{indent}/* {p.name} (buffer) */\n"
                f"{indent}size_t {p.name}_len = (_fz_len > _fz_off) ? _fz_len - _fz_off : 0;\n"
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

    def generate(
        self,
        func_name: str,
        func_addr: int,
        params: list[ParamInfo],
        target_binary: str,
        fmt: str = "afl",
    ) -> str:
        renderers = [_ParamRenderer(p, params) for p in params]
        tpl = self.env.get_template(f"{fmt}_harness.c.j2")

        param_sig_parts = [f"{p.c_type} {p.name}" for p in params]
        param_signature = ", ".join(param_sig_parts) if param_sig_parts else "void"
        call_args = ", ".join(r.call_arg for r in renderers)

        return tpl.render(
            func_name=func_name,
            func_addr=hex(func_addr),
            target_binary=target_binary,
            return_type="int",
            param_signature=param_signature,
            params=renderers,
            call_args=call_args,
        )

    def generate_types_header(self, structs: list) -> str:
        tpl = self.env.get_template("types.h.j2")
        return tpl.render(structs=structs)

    def generate_makefile(self, func_name: str, target_binary: str, fmt: str = "afl") -> str:
        tpl = self.env.get_template("Makefile.j2")
        return tpl.render(func_name=func_name, target_binary=target_binary, fmt=fmt)
