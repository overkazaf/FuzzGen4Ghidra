from fuzzgen4ghidra_engine.models import (
    FuzzTarget, ParamInfo, ParamType, StructField, StructLayout
)

def test_fuzz_target_creation():
    t = FuzzTarget(
        address=0x401000, name="parse_packet", score=87.3,
        complexity=42, param_count=3, has_buffer_params=True,
        dangerous_calls=["memcpy", "malloc"], is_exported=True,
        call_depth=2, reasons=["high complexity", "calls memcpy"],
    )
    assert t.score == 87.3
    assert "memcpy" in t.dangerous_calls

def test_fuzz_target_to_dict():
    t = FuzzTarget(
        address=0x401000, name="parse_packet", score=87.3,
        complexity=42, param_count=3, has_buffer_params=True,
        dangerous_calls=["memcpy"], is_exported=True,
        call_depth=2, reasons=["high complexity"],
    )
    d = t.to_dict()
    assert d["address"] == "0x401000"
    assert d["name"] == "parse_packet"

def test_param_info():
    p = ParamInfo(
        index=0, name="buf", type=ParamType.BUFFER,
        c_type="uint8_t *", size=8, register="rdi",
    )
    assert p.type == ParamType.BUFFER
    assert p.c_type == "uint8_t *"

def test_struct_layout():
    fields = [
        StructField(offset=0, size=4, name="magic", c_type="uint32_t", is_pointer=False),
        StructField(offset=4, size=4, name="length", c_type="uint32_t", is_pointer=False),
    ]
    layout = StructLayout(total_size=8, alignment=4, fields=fields, gaps=[], confidence=0.9)
    assert layout.total_size == 8
    assert len(layout.fields) == 2
