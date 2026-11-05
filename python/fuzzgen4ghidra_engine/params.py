import re
from .models import ParamInfo, ParamType

GHIDRA_TO_C_TYPE = {
    "undefined": "uint8_t",
    "undefined1": "uint8_t",
    "undefined2": "uint16_t",
    "undefined4": "uint32_t",
    "undefined8": "uint64_t",
    "uchar": "unsigned char",
    "ushort": "unsigned short",
    "uint": "unsigned int",
    "ulong": "unsigned long",
    "byte": "uint8_t",
    "word": "uint16_t",
    "dword": "uint32_t",
    "qword": "uint64_t",
}

INT_TYPES = frozenset({
    "int", "uint", "long", "ulong", "short", "ushort", "char", "uchar",
    "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
    "int64_t", "uint64_t", "size_t", "ssize_t", "off_t", "bool",
    "BOOL", "DWORD", "WORD", "BYTE",
    "unsigned int", "unsigned short", "unsigned long", "unsigned char",
    "signed int", "signed short", "signed long", "signed char",
    "long long", "unsigned long long",
    "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
})

FLOAT_TYPES = frozenset({"float", "double"})

BUFFER_PTR_TYPES = frozenset({
    "void *", "byte *", "char *", "uchar *",
    "uint8_t *", "int8_t *", "unsigned char *",
})

LENGTH_NAMES = frozenset({"len", "length", "size", "count", "num", "sz", "cb", "n", "nbytes"})


def _normalize_type(type_str: str) -> str:
    return " ".join(type_str.replace("*", " * ").split())


def _unqualified(type_str: str) -> str:
    return " ".join(t for t in _normalize_type(type_str).split()
                    if t not in {"const", "volatile", "restrict"})


def _classify_type(type_str: str) -> ParamType:
    stripped = _unqualified(type_str)
    if stripped == "code *":
        return ParamType.FUNC_PTR
    if stripped in BUFFER_PTR_TYPES:
        return ParamType.BUFFER
    if stripped.endswith(" *"):
        base = stripped[:-2]
        if base in INT_TYPES:
            return ParamType.BUFFER
        return ParamType.STRUCT_PTR
    if stripped in INT_TYPES:
        return ParamType.INT
    if stripped in FLOAT_TYPES:
        return ParamType.FLOAT
    return ParamType.UNKNOWN


def _name_tokens(name: str) -> list[str]:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower().split("_")


def _pair_lengths(params: list[ParamInfo]) -> None:
    buffers = [p for p in params if p.type == ParamType.BUFFER]
    lengths = [p for p in params if p.type == ParamType.INT
               and _name_tokens(p.name)[-1] in LENGTH_NAMES]
    used = set()
    # Explicit buffer-name prefixes win even when parameters are non-adjacent.
    for buf in buffers:
        for length in lengths:
            if length.index not in used and _name_tokens(length.name)[:-1] == _name_tokens(buf.name):
                buf.length_param = length.index
                used.add(length.index)
                break
    # Generic lengths pair with the nearest buffer; never reuse a length.
    for buf in buffers:
        if buf.length_param is not None:
            continue
        candidates = [p for p in lengths if p.index not in used
                      and len(_name_tokens(p.name)) == 1]
        if candidates:
            length = min(candidates, key=lambda p: (abs(p.index-buf.index), p.index < buf.index))
            buf.length_param = length.index
            used.add(length.index)


def recover_params_from_ghidra(ghidra_sig: dict) -> list[ParamInfo]:
    params_raw = ghidra_sig.get("params", [])
    results: list[ParamInfo] = []
    for i, p in enumerate(params_raw):
        raw_type = _normalize_type(p.get("type", "int"))
        c_type = re.sub(r"\b\w+\b", lambda m: GHIDRA_TO_C_TYPE.get(m[0], m[0]), raw_type)
        ptype = _classify_type(raw_type)
        if ptype == ParamType.FUNC_PTR:
            c_type = "fz_callback_t"
        results.append(ParamInfo(
            index=i,
            name=p.get("name", f"arg{i}"),
            type=ptype,
            c_type=c_type,
            size=p.get("size", 4),
            length_param=None,
        ))
    _pair_lengths(results)
    return results
