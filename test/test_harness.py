from fuzzgen4ghidra_engine.harness import HarnessGenerator
from fuzzgen4ghidra_engine.models import ParamInfo, ParamType

def _make_params():
    return [
        ParamInfo(index=0, name="buf", type=ParamType.BUFFER, c_type="uint8_t *", size=8, length_param=1),
        ParamInfo(index=1, name="len", type=ParamType.INT, c_type="uint32_t", size=4),
    ]

def test_afl_harness():
    gen = HarnessGenerator()
    code = gen.generate("parse_packet", 0x401000, _make_params(), "libparser.so", "afl")
    assert "parse_packet" in code
    assert "main(" in code
    assert "dlopen" in code

def test_libfuzzer_harness():
    gen = HarnessGenerator()
    code = gen.generate("parse_packet", 0x401000, _make_params(), "libparser.so", "libfuzzer")
    assert "LLVMFuzzerTestOneInput" in code
    assert "parse_packet" in code

def test_types_header():
    gen = HarnessGenerator()
    header = gen.generate_types_header([])
    assert "#ifndef" in header

def test_makefile():
    gen = HarnessGenerator()
    makefile = gen.generate_makefile("parse_packet", "libparser.so", "afl")
    assert "libparser.so" in makefile

def test_int_only_params():
    params = [
        ParamInfo(index=0, name="flags", type=ParamType.INT, c_type="int", size=4),
        ParamInfo(index=1, name="mode", type=ParamType.INT, c_type="int", size=4),
    ]
    gen = HarnessGenerator()
    code = gen.generate("process", 0x402000, params, "libtarget.so", "afl")
    assert "process" in code
