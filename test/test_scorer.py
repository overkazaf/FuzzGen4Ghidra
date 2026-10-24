from fuzzgen4ghidra_engine.scorer import TargetScorer
from fuzzgen4ghidra_engine.models import FuzzTarget

DANGEROUS_FUNCTIONS = {"memcpy", "strcpy", "sprintf", "strcat", "gets", "malloc", "free", "realloc"}

def test_score_complex_dangerous_function():
    scorer = TargetScorer(exported_addrs={0x401000}, entry_addr=0x400000)
    result = scorer.score_function(
        addr=0x401000, name="parse_packet",
        num_blocks=42, callee_names=["memcpy", "malloc", "printf"],
        param_count=3, is_exported=True, call_depth=2,
        ghidra_has_buffer_param=True,
    )
    assert isinstance(result, FuzzTarget)
    assert result.score > 70
    assert "memcpy" in result.dangerous_calls
    assert result.is_exported is True

def test_score_trivial_function():
    scorer = TargetScorer(exported_addrs=set(), entry_addr=0x400000)
    result = scorer.score_function(
        addr=0x402000, name="get_version",
        num_blocks=2, callee_names=[],
        param_count=0, is_exported=False, call_depth=5,
        ghidra_has_buffer_param=False,
    )
    assert result.score < 30

def test_score_sorting():
    scorer = TargetScorer(exported_addrs={0x401000}, entry_addr=0x400000)
    high = scorer.score_function(0x401000, "parse", 42, ["memcpy"], 3, True, 2, True)
    low = scorer.score_function(0x402000, "nop", 1, [], 0, False, 10, False)
    targets = sorted([low, high], key=lambda t: t.score, reverse=True)
    assert targets[0].name == "parse"
