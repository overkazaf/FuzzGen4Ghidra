import re
from .models import ParamInfo, ParamType

GHIDRA_TO_C_TYPE = {
    "undefined": "uint8_t",
    "undefined1": "uint8_t",
    "undefined2": "uint16_t",
    "undefined4": "uint32_t",
    "undefined8": "uint64_t",
}

INT_TYPES = frozenset({
    "int", "uint", "long", "ulong", "short", "ushort", "char", "uchar",
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
    "int64_t", "uint64_t", "size_t", "ssize_t", "off_t", "bool",
    "BOOL", "DWORD", "WORD", "BYTE",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
})

FLOAT_TYPES = frozenset({"float", "double"})

BUFFER_PTR_TYPES = frozenset({
    "void *", "byte *", "char *", "uchar *",
    "uint8_t *", "int8_t *", "unsigned char *",
})

LENGTH_NAMES = re.compile(r"(len|length|size|count|num|sz|cb|n|nbytes)", re.IGNORECASE)


def _classify_type(type_str: str) -> ParamType:
    stripped = type_str.strip()
    if stripped in BUFFER_PTR_TYPES:
        return ParamType.BUFFER
    if stripped == "code *" or stripped.startswith("code *"):
        return ParamType.FUNC_PTR
    if stripped.endswith(" *") or stripped.endswith(" * *"):
        base = stripped.rstrip(" *").strip()
        if base in INT_TYPES:
            return ParamType.BUFFER
        return ParamType.STRUCT_PTR
    if stripped in INT_TYPES:
        return ParamType.INT
    if stripped in FLOAT_TYPES:
        return ParamType.FLOAT
    return ParamType.UNKNOWN


def _find_length_param(params_raw: list[dict], buffer_index: int) -> int | None:
    for i, p in enumerate(params_raw):
        if i == buffer_index:
            continue
        if LENGTH_NAMES.search(p.get("name", "")):
            t = _classify_type(p.get("type", ""))
            if t == ParamType.INT:
                return i
    return None


def recover_params_from_ghidra(ghidra_sig: dict) -> list[ParamInfo]:
    params_raw = ghidra_sig.get("params", [])
    results: list[ParamInfo] = []
    for i, p in enumerate(params_raw):
        raw_type = p.get("type", "int")
        c_type = GHIDRA_TO_C_TYPE.get(raw_type, raw_type)
        ptype = _classify_type(raw_type)
        length_param = None
        if ptype == ParamType.BUFFER:
            length_param = _find_length_param(params_raw, i)
        results.append(ParamInfo(
            index=i,
            name=p.get("name", f"arg{i}"),
            type=ptype,
            c_type=c_type,
            size=p.get("size", 4),
            length_param=length_param,
        ))
    return results
