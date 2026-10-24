import logging
from .models import FuzzTarget

logger = logging.getLogger("fuzzgen4ghidra")

DANGEROUS_FUNCTIONS = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets", "scanf", "sscanf", "fscanf",
    "malloc", "calloc", "realloc", "free",
    "read", "recv", "recvfrom", "fread",
})

W_COMPLEXITY = 0.25
W_INPUT_SURFACE = 0.30
W_DANGER = 0.25
W_FEASIBILITY = 0.20


class TargetScorer:
    def __init__(self, exported_addrs: set[int], entry_addr: int):
        self.dangerous_fns = DANGEROUS_FUNCTIONS
        self.exported_addrs = exported_addrs
        self.entry_addr = entry_addr

    def score_function(
        self,
        addr: int,
        name: str,
        num_blocks: int,
        callee_names: list[str],
        param_count: int,
        is_exported: bool,
        call_depth: int,
        ghidra_has_buffer_param: bool,
    ) -> FuzzTarget:
        reasons: list[str] = []

        # Complexity (0-100)
        if num_blocks >= 50:
            complexity_score = 100.0
        elif num_blocks >= 20:
            complexity_score = 60.0 + (num_blocks - 20) / 30 * 40
        elif num_blocks >= 5:
            complexity_score = 20.0 + (num_blocks - 5) / 15 * 40
        else:
            complexity_score = num_blocks / 5 * 20
        if complexity_score >= 60:
            reasons.append(f"high complexity ({num_blocks} blocks)")

        # Input surface (0-100)
        input_score = 0.0
        if ghidra_has_buffer_param:
            input_score += 50
            reasons.append("accepts buffer parameter")
        if param_count >= 2:
            input_score += min(param_count * 10, 30)
        input_callers = [c for c in callee_names if c in {"read", "recv", "recvfrom", "fread", "fgets", "gets", "scanf", "fscanf", "sscanf"}]
        if input_callers:
            input_score += 20
            reasons.append(f"calls input functions: {', '.join(input_callers)}")
        input_score = min(input_score, 100)

        # Danger (0-100)
        dangerous_hits = [c for c in callee_names if c in self.dangerous_fns]
        danger_score = min(len(dangerous_hits) * 25, 100)
        if dangerous_hits:
            reasons.append(f"calls {', '.join(sorted(set(dangerous_hits)))}")

        # Feasibility (0-100)
        feasibility_score = 0.0
        if is_exported:
            feasibility_score += 50
            reasons.append("exported symbol")
        if param_count > 0:
            feasibility_score += 20
        if call_depth <= 3:
            feasibility_score += 30
        elif call_depth <= 6:
            feasibility_score += 15
        feasibility_score = min(feasibility_score, 100)

        total = (
            W_COMPLEXITY * complexity_score
            + W_INPUT_SURFACE * input_score
            + W_DANGER * danger_score
            + W_FEASIBILITY * feasibility_score
        )

        return FuzzTarget(
            address=addr, name=name, score=round(total, 1),
            complexity=num_blocks, param_count=param_count,
            has_buffer_params=ghidra_has_buffer_param,
            dangerous_calls=sorted(set(dangerous_hits)),
            is_exported=is_exported, call_depth=call_depth,
            reasons=reasons,
        )
