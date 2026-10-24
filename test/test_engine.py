import pytest
from fuzzgen4ghidra_engine.engine import FuzzGenEngine

def test_init_nonexistent_binary():
    engine = FuzzGenEngine()
    with pytest.raises(Exception):
        engine.init("/nonexistent/binary")

def test_scan_targets_requires_init():
    engine = FuzzGenEngine()
    with pytest.raises(RuntimeError, match="not loaded"):
        engine.scan_targets([])

def test_generate_harness_basic():
    engine = FuzzGenEngine()
    ghidra_sig = {
        "params": [
            {"name": "buf", "type": "byte *", "size": 8},
            {"name": "len", "type": "int", "size": 4},
        ]
    }
    result = engine.generate_harness(
        func_addr=0x401000, func_name="parse_packet",
        ghidra_signature=ghidra_sig, target_binary="libparser.so", fmt="afl",
    )
    assert "harness_code" in result
    assert "parse_packet" in result["harness_code"]
    assert "types_header" in result
    assert "makefile" in result
