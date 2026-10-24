from dataclasses import dataclass, field
from enum import Enum


class ParamType(Enum):
    INT = "int"
    FLOAT = "float"
    POINTER = "pointer"
    BUFFER = "buffer"
    STRUCT_PTR = "struct_ptr"
    FUNC_PTR = "func_ptr"
    UNKNOWN = "unknown"


@dataclass
class StructField:
    offset: int
    size: int
    name: str
    c_type: str
    is_pointer: bool
    pointee: "StructLayout | None" = None


@dataclass
class StructLayout:
    total_size: int
    alignment: int
    fields: list[StructField]
    gaps: list[tuple[int, int]]
    confidence: float


@dataclass
class ParamInfo:
    index: int
    name: str
    type: ParamType
    c_type: str
    size: int
    register: str | None = None
    stack_offset: int | None = None
    length_param: int | None = None
    struct_layout: StructLayout | None = None

    def to_dict(self) -> dict:
        d = {
            "index": self.index,
            "name": self.name,
            "type": self.type.value,
            "c_type": self.c_type,
            "size": self.size,
        }
        if self.register:
            d["register"] = self.register
        if self.stack_offset is not None:
            d["stack_offset"] = self.stack_offset
        if self.length_param is not None:
            d["length_param"] = self.length_param
        return d


@dataclass
class FuzzTarget:
    address: int
    name: str
    score: float
    complexity: int
    param_count: int
    has_buffer_params: bool
    dangerous_calls: list[str]
    is_exported: bool
    call_depth: int
    reasons: list[str]

    def to_dict(self) -> dict:
        return {
            "address": hex(self.address),
            "name": self.name,
            "score": round(self.score, 1),
            "complexity": self.complexity,
            "param_count": self.param_count,
            "has_buffer_params": self.has_buffer_params,
            "dangerous_calls": self.dangerous_calls,
            "is_exported": self.is_exported,
            "call_depth": self.call_depth,
            "reasons": self.reasons,
        }
