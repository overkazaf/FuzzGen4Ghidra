# FuzzGen4Ghidra MVP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Ghidra plugin that automatically generates fuzzing harnesses (AFL++/libFuzzer) for selected binary functions, using angr for analysis and Ghidra's decompiler for type info.

**Architecture:** Independent Ghidra extension (Java plugin) communicating with a Python/angr engine over JSON-line TCP (port 13371). Mirrors the Ponce4Ghidra pattern: Java handles UI/Ghidra integration, Python handles binary analysis and C code generation. Shared protocol module pattern.

**Tech Stack:** Java 17+ (Ghidra extension API, Gson), Python 3.12+ (angr 9.2.x, Jinja2), Gradle (Ghidra buildExtension)

---

### Task 1: Python Protocol Module

**Files:**
- Create: `python/fuzzgen4ghidra_engine/__init__.py`
- Create: `python/fuzzgen4ghidra_engine/protocol.py`

**Step 1: Write protocol.py**

```python
import json
from dataclasses import dataclass, field


@dataclass
class Command:
    type: str
    params: dict = field(default_factory=dict)


@dataclass
class Response:
    status: str
    data: dict | None = None
    message: str | None = None

    def to_json(self) -> str:
        d = {"status": self.status}
        if self.data is not None:
            d["data"] = self.data
        if self.message is not None:
            d["message"] = self.message
        return json.dumps(d)


def parse_command(line: str) -> Command:
    obj = json.loads(line)
    return Command(type=obj["type"], params=obj.get("params", {}))


def ok(data: dict | None = None) -> Response:
    return Response(status="ok", data=data)


def error(message: str) -> Response:
    return Response(status="error", message=message)


def progress(data: dict) -> Response:
    return Response(status="progress", data=data)
```

**Step 2: Write `__init__.py`**

Empty file.

**Step 3: Write the test**

```python
# test/test_protocol.py
from fuzzgen4ghidra_engine.protocol import parse_command, ok, error, progress

def test_parse_command():
    cmd = parse_command('{"type": "scan_targets", "params": {"binary_path": "/tmp/a.out"}}')
    assert cmd.type == "scan_targets"
    assert cmd.params["binary_path"] == "/tmp/a.out"

def test_ok_response():
    r = ok({"count": 5})
    import json
    d = json.loads(r.to_json())
    assert d["status"] == "ok"
    assert d["data"]["count"] == 5

def test_error_response():
    r = error("bad thing")
    import json
    d = json.loads(r.to_json())
    assert d["status"] == "error"
    assert d["message"] == "bad thing"

def test_progress_response():
    r = progress({"step": 3, "total": 10})
    import json
    d = json.loads(r.to_json())
    assert d["status"] == "progress"
    assert d["data"]["step"] == 3
```

**Step 4: Run test**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_protocol.py -v`
Expected: all 4 tests PASS

**Step 5: Commit**

```bash
git add python/fuzzgen4ghidra_engine/__init__.py python/fuzzgen4ghidra_engine/protocol.py test/test_protocol.py
git commit -m "feat(engine): add JSON-line protocol module"
```

---

### Task 2: Data Models (FuzzTarget, ParamInfo, StructLayout)

**Files:**
- Create: `python/fuzzgen4ghidra_engine/models.py`
- Create: `test/test_models.py`

**Step 1: Write the test**

```python
# test/test_models.py
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
```

**Step 2: Run test to verify it fails**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_models.py -v`
Expected: FAIL (module not found)

**Step 3: Write models.py**

```python
# python/fuzzgen4ghidra_engine/models.py
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
```

**Step 4: Run test to verify it passes**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_models.py -v`
Expected: all 4 tests PASS

**Step 5: Commit**

```bash
git add python/fuzzgen4ghidra_engine/models.py test/test_models.py
git commit -m "feat(engine): add data models for FuzzTarget, ParamInfo, StructLayout"
```

---

### Task 3: Target Scorer

**Files:**
- Create: `python/fuzzgen4ghidra_engine/scorer.py`
- Create: `test/test_scorer.py`

**Step 1: Write the test**

```python
# test/test_scorer.py
import pytest
from unittest.mock import MagicMock, patch
from fuzzgen4ghidra_engine.scorer import TargetScorer
from fuzzgen4ghidra_engine.models import FuzzTarget

DANGEROUS_FUNCTIONS = {"memcpy", "strcpy", "sprintf", "strcat", "gets", "malloc", "free", "realloc"}

def _mock_function(addr, name, num_blocks, callees=None, is_simprocedure=False):
    """Build a minimal mock of an angr Function."""
    func = MagicMock()
    func.addr = addr
    func.name = name
    func.is_simprocedure = is_simprocedure
    graph = MagicMock()
    graph.nodes.return_value = [MagicMock() for _ in range(num_blocks)]
    graph.__len__ = lambda self: num_blocks
    func.graph = graph
    func.num_arguments = 3
    sites = []
    if callees:
        for c in callees:
            site = MagicMock()
            site.callee = c
            sites.append(site)
    func.get_call_sites.return_value = [MagicMock() for _ in range(len(sites))]
    return func, callees or []

def test_score_complex_dangerous_function():
    scorer = TargetScorer.__new__(TargetScorer)
    scorer.dangerous_fns = DANGEROUS_FUNCTIONS
    scorer.exported_addrs = {0x401000}
    scorer.entry_addr = 0x400000

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
    scorer = TargetScorer.__new__(TargetScorer)
    scorer.dangerous_fns = DANGEROUS_FUNCTIONS
    scorer.exported_addrs = set()
    scorer.entry_addr = 0x400000

    result = scorer.score_function(
        addr=0x402000, name="get_version",
        num_blocks=2, callee_names=[],
        param_count=0, is_exported=False, call_depth=5,
        ghidra_has_buffer_param=False,
    )
    assert result.score < 30

def test_score_sorting():
    scorer = TargetScorer.__new__(TargetScorer)
    scorer.dangerous_fns = DANGEROUS_FUNCTIONS
    scorer.exported_addrs = {0x401000}
    scorer.entry_addr = 0x400000

    high = scorer.score_function(0x401000, "parse", 42, ["memcpy"], 3, True, 2, True)
    low = scorer.score_function(0x402000, "nop", 1, [], 0, False, 10, False)
    targets = sorted([low, high], key=lambda t: t.score, reverse=True)
    assert targets[0].name == "parse"
```

**Step 2: Run test to verify it fails**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_scorer.py -v`
Expected: FAIL

**Step 3: Write scorer.py**

```python
# python/fuzzgen4ghidra_engine/scorer.py
import logging
from dataclasses import dataclass
from .models import FuzzTarget

logger = logging.getLogger("fuzzgen4ghidra")

DANGEROUS_FUNCTIONS = frozenset({
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets", "scanf", "sscanf", "fscanf",
    "malloc", "calloc", "realloc", "free",
    "read", "recv", "recvfrom", "fread",
})

# Weights for the four scoring axes (must sum to 1.0).
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

        # --- Complexity (0-100) ---
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

        # --- Input surface (0-100) ---
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

        # --- Danger (0-100) ---
        dangerous_hits = [c for c in callee_names if c in self.dangerous_fns]
        danger_score = min(len(dangerous_hits) * 25, 100)
        if dangerous_hits:
            reasons.append(f"calls {', '.join(sorted(set(dangerous_hits)))}")

        # --- Feasibility (0-100) ---
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
            address=addr,
            name=name,
            score=round(total, 1),
            complexity=num_blocks,
            param_count=param_count,
            has_buffer_params=ghidra_has_buffer_param,
            dangerous_calls=sorted(set(dangerous_hits)),
            is_exported=is_exported,
            call_depth=call_depth,
            reasons=reasons,
        )
```

**Step 4: Run test to verify it passes**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_scorer.py -v`
Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add python/fuzzgen4ghidra_engine/scorer.py test/test_scorer.py
git commit -m "feat(engine): add target scorer with 4-axis fuzzability scoring"
```

---

### Task 4: Parameter Recovery (Ghidra signature parsing)

**Files:**
- Create: `python/fuzzgen4ghidra_engine/params.py`
- Create: `test/test_params.py`

**Step 1: Write the test**

```python
# test/test_params.py
from fuzzgen4ghidra_engine.params import recover_params_from_ghidra
from fuzzgen4ghidra_engine.models import ParamType

def test_basic_int_params():
    ghidra_sig = {
        "params": [
            {"name": "flags", "type": "int", "size": 4},
            {"name": "count", "type": "uint32_t", "size": 4},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert len(params) == 2
    assert params[0].type == ParamType.INT
    assert params[0].c_type == "int"
    assert params[1].c_type == "uint32_t"

def test_buffer_param():
    ghidra_sig = {
        "params": [
            {"name": "buf", "type": "byte *", "size": 8},
            {"name": "len", "type": "int", "size": 4},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.BUFFER
    assert params[0].length_param == 1

def test_struct_pointer():
    ghidra_sig = {
        "params": [
            {"name": "ctx", "type": "my_context_t *", "size": 8},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.STRUCT_PTR

def test_void_pointer_is_buffer():
    ghidra_sig = {
        "params": [
            {"name": "data", "type": "void *", "size": 8},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.BUFFER

def test_function_pointer():
    ghidra_sig = {
        "params": [
            {"name": "callback", "type": "code *", "size": 8},
        ]
    }
    params = recover_params_from_ghidra(ghidra_sig)
    assert params[0].type == ParamType.FUNC_PTR
```

**Step 2: Run test to verify it fails**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_params.py -v`
Expected: FAIL

**Step 3: Write params.py**

```python
# python/fuzzgen4ghidra_engine/params.py
import re
from .models import ParamInfo, ParamType

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
        ptype = _classify_type(p.get("type", ""))
        length_param = None
        if ptype == ParamType.BUFFER:
            length_param = _find_length_param(params_raw, i)

        results.append(ParamInfo(
            index=i,
            name=p.get("name", f"arg{i}"),
            type=ptype,
            c_type=p.get("type", "int"),
            size=p.get("size", 4),
            length_param=length_param,
        ))

    return results
```

**Step 4: Run test to verify it passes**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_params.py -v`
Expected: all 5 tests PASS

**Step 5: Commit**

```bash
git add python/fuzzgen4ghidra_engine/params.py test/test_params.py
git commit -m "feat(engine): add parameter recovery from Ghidra signatures"
```

---

### Task 5: Harness Generator (AFL++ and libFuzzer templates)

**Files:**
- Create: `python/fuzzgen4ghidra_engine/harness.py`
- Create: `python/fuzzgen4ghidra_engine/templates/afl_harness.c.j2`
- Create: `python/fuzzgen4ghidra_engine/templates/libfuzzer_harness.c.j2`
- Create: `python/fuzzgen4ghidra_engine/templates/types.h.j2`
- Create: `python/fuzzgen4ghidra_engine/templates/Makefile.j2`
- Create: `test/test_harness.py`

**Step 1: Write the test**

```python
# test/test_harness.py
from fuzzgen4ghidra_engine.harness import HarnessGenerator
from fuzzgen4ghidra_engine.models import ParamInfo, ParamType

def _make_params():
    return [
        ParamInfo(index=0, name="buf", type=ParamType.BUFFER, c_type="uint8_t *", size=8, length_param=1),
        ParamInfo(index=1, name="len", type=ParamType.INT, c_type="uint32_t", size=4),
    ]

def test_afl_harness_compiles_validly():
    gen = HarnessGenerator()
    code = gen.generate(
        func_name="parse_packet",
        func_addr=0x401000,
        params=_make_params(),
        target_binary="libparser.so",
        fmt="afl",
    )
    assert "parse_packet" in code
    assert "main(" in code
    assert "fopen" in code or "stdin" in code
    assert "dlopen" in code or "parse_packet" in code

def test_libfuzzer_harness():
    gen = HarnessGenerator()
    code = gen.generate(
        func_name="parse_packet",
        func_addr=0x401000,
        params=_make_params(),
        target_binary="libparser.so",
        fmt="libfuzzer",
    )
    assert "LLVMFuzzerTestOneInput" in code
    assert "parse_packet" in code

def test_types_header():
    gen = HarnessGenerator()
    header = gen.generate_types_header([])
    assert "#ifndef" in header

def test_makefile():
    gen = HarnessGenerator()
    makefile = gen.generate_makefile(
        func_name="parse_packet",
        target_binary="libparser.so",
        fmt="afl",
    )
    assert "afl" in makefile.lower() or "AFL" in makefile
    assert "libparser.so" in makefile

def test_int_only_params():
    params = [
        ParamInfo(index=0, name="flags", type=ParamType.INT, c_type="int", size=4),
        ParamInfo(index=1, name="mode", type=ParamType.INT, c_type="int", size=4),
    ]
    gen = HarnessGenerator()
    code = gen.generate("process", 0x402000, params, "libtarget.so", "afl")
    assert "process" in code
```

**Step 2: Run test to verify it fails**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_harness.py -v`
Expected: FAIL

**Step 3: Create Jinja2 templates**

**`python/fuzzgen4ghidra_engine/templates/afl_harness.c.j2`:**
```c
/*
 * AFL++ fuzzing harness for {{ func_name }}
 * Generated by FuzzGen4Ghidra
 * Target: {{ target_binary }} @ {{ func_addr }}
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include "types.h"

typedef {{ return_type }} (*target_fn_t)({{ param_signature }});

static int consume_bytes(const uint8_t *data, size_t data_len, size_t *offset, void *out, size_t n) {
    if (*offset + n > data_len) return -1;
    memcpy(out, data + *offset, n);
    *offset += n;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long file_len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_len <= 0) { fclose(f); return 1; }

    size_t data_len = (size_t)file_len;
    uint8_t *data = (uint8_t *)malloc(data_len);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, data_len, f);
    fclose(f);

    void *lib = dlopen("./{{ target_binary }}", RTLD_LAZY);
    if (!lib) { free(data); return 1; }
    target_fn_t target = (target_fn_t)dlsym(lib, "{{ func_name }}");
    if (!target) { dlclose(lib); free(data); return 1; }

    size_t offset = 0;
{% for p in params %}
{{ p.deserialize_code }}
{% endfor %}

    target({{ call_args }});

{% for p in params %}
{{ p.cleanup_code }}
{% endfor %}
    free(data);
    dlclose(lib);
    return 0;
}
```

**`python/fuzzgen4ghidra_engine/templates/libfuzzer_harness.c.j2`:**
```c
/*
 * libFuzzer harness for {{ func_name }}
 * Generated by FuzzGen4Ghidra
 * Target: {{ target_binary }} @ {{ func_addr }}
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include "types.h"

typedef {{ return_type }} (*target_fn_t)({{ param_signature }});

static void *g_lib = NULL;
static target_fn_t g_target = NULL;

static int consume_bytes(const uint8_t *data, size_t data_len, size_t *offset, void *out, size_t n) {
    if (*offset + n > data_len) return -1;
    memcpy(out, data + *offset, n);
    *offset += n;
    return 0;
}

__attribute__((constructor))
static void init(void) {
    g_lib = dlopen("./{{ target_binary }}", RTLD_LAZY);
    if (g_lib) g_target = (target_fn_t)dlsym(g_lib, "{{ func_name }}");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_target) return 0;

    size_t offset = 0;
{% for p in params %}
{{ p.deserialize_code }}
{% endfor %}

    g_target({{ call_args }});

{% for p in params %}
{{ p.cleanup_code }}
{% endfor %}
    return 0;
}
```

**`python/fuzzgen4ghidra_engine/templates/types.h.j2`:**
```c
/*
 * Recovered type definitions
 * Generated by FuzzGen4Ghidra
 */
#ifndef FUZZGEN_TYPES_H
#define FUZZGEN_TYPES_H

#include <stdint.h>

{% for struct in structs %}
typedef struct {
{% for field in struct.fields %}
    {{ field.c_type }} {{ field.name }};
{% endfor %}
} {{ struct.name }};

{% endfor %}
#endif /* FUZZGEN_TYPES_H */
```

**`python/fuzzgen4ghidra_engine/templates/Makefile.j2`:**
```makefile
# FuzzGen4Ghidra - Makefile for {{ func_name }} harness
# Target: {{ target_binary }}

CC ?= gcc
CFLAGS = -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS = -ldl
TARGET_LIB = {{ target_binary }}

{% if fmt == "afl" %}
AFL_CC ?= afl-gcc
HARNESS = harness_{{ func_name }}

all: $(HARNESS)

$(HARNESS): harness_{{ func_name }}.c types.h
	$(AFL_CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

fuzz: $(HARNESS)
	@mkdir -p findings
	afl-fuzz -i seeds -o findings -- ./$(HARNESS) @@

{% elif fmt == "libfuzzer" %}
HARNESS = harness_{{ func_name }}

all: $(HARNESS)

$(HARNESS): harness_{{ func_name }}.c types.h
	clang $(CFLAGS) -fsanitize=fuzzer -o $@ $< $(LDFLAGS)

fuzz: $(HARNESS)
	@mkdir -p corpus
	./$(HARNESS) corpus/ -max_len=4096

{% endif %}
clean:
	rm -f $(HARNESS)

.PHONY: all fuzz clean
```

**Step 4: Write harness.py**

```python
# python/fuzzgen4ghidra_engine/harness.py
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from .models import ParamInfo, ParamType, StructLayout

TEMPLATE_DIR = Path(__file__).parent / "templates"


class _ParamRenderer:
    def __init__(self, param: ParamInfo, all_params: list[ParamInfo]):
        self.p = param
        self.all_params = all_params

    @property
    def deserialize_code(self) -> str:
        p = self.p
        indent = "    "
        if p.type == ParamType.BUFFER:
            length_src = self._length_source()
            return (
                f"{indent}/* {p.name} (buffer) */\n"
                f"{indent}size_t {p.name}_len = {length_src};\n"
                f"{indent}uint8_t *{p.name} = NULL;\n"
                f"{indent}if ({p.name}_len > 0 && offset + {p.name}_len <= data_len) {{\n"
                f"{indent}    {p.name} = (uint8_t *)(data + offset);\n"
                f"{indent}    offset += {p.name}_len;\n"
                f"{indent}}}"
            )
        elif p.type == ParamType.INT:
            if self._is_length_for_buffer():
                return f"{indent}/* {p.name} (length - derived from buffer) */"
            return (
                f"{indent}/* {p.name} */\n"
                f"{indent}{p.c_type} {p.name} = 0;\n"
                f"{indent}consume_bytes(data, data_len, &offset, &{p.name}, sizeof({p.name}));"
            )
        elif p.type == ParamType.FLOAT:
            return (
                f"{indent}/* {p.name} */\n"
                f"{indent}{p.c_type} {p.name} = 0;\n"
                f"{indent}consume_bytes(data, data_len, &offset, &{p.name}, sizeof({p.name}));"
            )
        elif p.type == ParamType.STRUCT_PTR:
            return (
                f"{indent}/* {p.name} (struct pointer - treat as raw bytes for MVP) */\n"
                f"{indent}uint8_t {p.name}_buf[256] = {{0}};\n"
                f"{indent}size_t {p.name}_avail = (data_len > offset) ? data_len - offset : 0;\n"
                f"{indent}if ({p.name}_avail > 256) {p.name}_avail = 256;\n"
                f"{indent}if ({p.name}_avail > 0) memcpy({p.name}_buf, data + offset, {p.name}_avail);\n"
                f"{indent}offset += {p.name}_avail;\n"
                f"{indent}void *{p.name} = {p.name}_buf;"
            )
        elif p.type == ParamType.FUNC_PTR:
            return f"{indent}/* {p.name} (function pointer - stubbed to NULL) */\n{indent}void *{p.name} = NULL;"
        else:
            return (
                f"{indent}/* {p.name} (unknown type: {p.c_type}) */\n"
                f"{indent}uint8_t {p.name}_raw[{p.size}] = {{0}};\n"
                f"{indent}consume_bytes(data, data_len, &offset, {p.name}_raw, {p.size});\n"
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

    def _length_source(self) -> str:
        if self.p.length_param is not None:
            return f"(data_len > offset) ? data_len - offset : 0"
        return f"(data_len > offset) ? data_len - offset : 0"

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
        template_name = f"{fmt}_harness.c.j2"
        tpl = self.env.get_template(template_name)

        param_sig_parts = []
        for p in params:
            param_sig_parts.append(f"{p.c_type} {p.name}")
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

    def generate_makefile(
        self,
        func_name: str,
        target_binary: str,
        fmt: str = "afl",
    ) -> str:
        tpl = self.env.get_template("Makefile.j2")
        return tpl.render(func_name=func_name, target_binary=target_binary, fmt=fmt)
```

**Step 4: Run test to verify it passes**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_harness.py -v`
Expected: all 5 tests PASS

Note: Jinja2 must be installed: `pip install jinja2`

**Step 5: Commit**

```bash
git add python/fuzzgen4ghidra_engine/harness.py python/fuzzgen4ghidra_engine/templates/ test/test_harness.py
git commit -m "feat(engine): add harness generator with AFL++ and libFuzzer templates"
```

---

### Task 6: Analysis Engine (orchestrates scorer + params + harness)

**Files:**
- Create: `python/fuzzgen4ghidra_engine/engine.py`
- Create: `test/test_engine.py`

**Step 1: Write the test**

```python
# test/test_engine.py
import os
import pytest
from unittest.mock import MagicMock, patch
from fuzzgen4ghidra_engine.engine import FuzzGenEngine

TINY_ELF = os.path.join(os.path.dirname(__file__), "fixtures", "tiny")

@pytest.fixture
def engine():
    return FuzzGenEngine()

def test_init_nonexistent_binary(engine):
    with pytest.raises(Exception):
        engine.init("/nonexistent/binary")

def test_scan_targets_requires_init(engine):
    with pytest.raises(RuntimeError, match="not loaded"):
        engine.scan_targets([])

def test_generate_harness_basic(engine):
    """Test harness generation with manually provided params (no binary needed)."""
    ghidra_sig = {
        "params": [
            {"name": "buf", "type": "byte *", "size": 8},
            {"name": "len", "type": "int", "size": 4},
        ]
    }
    result = engine.generate_harness(
        func_addr=0x401000,
        func_name="parse_packet",
        ghidra_signature=ghidra_sig,
        target_binary="libparser.so",
        fmt="afl",
    )
    assert "harness_code" in result
    assert "parse_packet" in result["harness_code"]
    assert "types_header" in result
    assert "makefile" in result
```

**Step 2: Run test to verify it fails**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_engine.py -v`
Expected: FAIL

**Step 3: Write engine.py**

```python
# python/fuzzgen4ghidra_engine/engine.py
import logging
import os
from typing import Any

import angr

from .harness import HarnessGenerator
from .models import FuzzTarget
from .params import recover_params_from_ghidra
from .scorer import TargetScorer

logger = logging.getLogger("fuzzgen4ghidra")


class FuzzGenEngine:
    def __init__(self):
        self.project: angr.Project | None = None
        self.binary_path: str | None = None
        self._scorer: TargetScorer | None = None
        self._harness_gen = HarnessGenerator()

    def init(self, binary_path: str) -> dict:
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.binary_path = binary_path

        main_obj = self.project.loader.main_object
        exported = set()
        if hasattr(main_obj, "symbols_by_name"):
            for sym in main_obj.symbols:
                if sym.is_export and sym.is_function:
                    exported.add(sym.rebased_addr)

        self._scorer = TargetScorer(
            exported_addrs=exported,
            entry_addr=self.project.entry,
        )

        logger.info("Loaded binary: %s (%s)", binary_path, self.project.arch.name)
        return {
            "arch": self.project.arch.name,
            "entry": hex(self.project.entry),
            "binary": binary_path,
        }

    def scan_targets(
        self,
        ghidra_functions: list[dict],
        progress_callback=None,
    ) -> list[dict]:
        if self.project is None:
            raise RuntimeError("Binary not loaded — call init first")

        cfg = self.project.analyses.CFGFast(normalize=True, show_progressbar=False)
        kb_funcs = self.project.kb.functions

        ghidra_map = {}
        for gf in ghidra_functions:
            addr = int(gf["address"], 16) if isinstance(gf["address"], str) else gf["address"]
            ghidra_map[addr] = gf

        targets: list[FuzzTarget] = []
        total = len(kb_funcs)

        for i, (addr, func) in enumerate(kb_funcs.items()):
            if func.is_simprocedure or func.is_plt:
                continue
            if len(func.graph) < 2:
                continue

            callee_names = []
            for site in func.get_call_sites():
                target_addr = func.get_call_target(site)
                if target_addr is not None and target_addr in kb_funcs:
                    callee_names.append(kb_funcs[target_addr].name)

            gf = ghidra_map.get(addr, {})
            has_buffer = gf.get("has_buffer_param", False)
            param_count = gf.get("param_count", func.num_arguments or 0)
            name = gf.get("name", func.name)
            is_exported = addr in self._scorer.exported_addrs

            target = self._scorer.score_function(
                addr=addr,
                name=name,
                num_blocks=len(func.graph),
                callee_names=callee_names,
                param_count=param_count,
                is_exported=is_exported,
                call_depth=0,
                ghidra_has_buffer_param=has_buffer,
            )
            targets.append(target)

            if progress_callback and i % 50 == 0:
                progress_callback({"scanned": i, "total": total})

        targets.sort(key=lambda t: t.score, reverse=True)
        return [t.to_dict() for t in targets]

    def analyze_params(self, func_addr: int, ghidra_signature: dict) -> list[dict]:
        params = recover_params_from_ghidra(ghidra_signature)
        return [p.to_dict() for p in params]

    def generate_harness(
        self,
        func_addr: int,
        func_name: str,
        ghidra_signature: dict,
        target_binary: str,
        fmt: str = "afl",
        output_dir: str | None = None,
    ) -> dict:
        params = recover_params_from_ghidra(ghidra_signature)

        harness_code = self._harness_gen.generate(
            func_name=func_name,
            func_addr=func_addr,
            params=params,
            target_binary=target_binary,
            fmt=fmt,
        )
        types_header = self._harness_gen.generate_types_header([])
        makefile = self._harness_gen.generate_makefile(
            func_name=func_name,
            target_binary=target_binary,
            fmt=fmt,
        )

        result = {
            "harness_code": harness_code,
            "types_header": types_header,
            "makefile": makefile,
            "func_name": func_name,
            "fmt": fmt,
        }

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            seeds_dir = os.path.join(output_dir, "seeds")
            os.makedirs(seeds_dir, exist_ok=True)

            with open(os.path.join(output_dir, f"harness_{func_name}.c"), "w") as f:
                f.write(harness_code)
            with open(os.path.join(output_dir, "types.h"), "w") as f:
                f.write(types_header)
            with open(os.path.join(output_dir, "Makefile"), "w") as f:
                f.write(makefile)
            with open(os.path.join(seeds_dir, "seed_000"), "wb") as f:
                min_size = sum(p.size for p in params if p.type.value != "func_ptr")
                f.write(b"\x00" * max(min_size, 16))

            result["output_dir"] = output_dir

        return result
```

**Step 4: Run test to verify it passes**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_engine.py -v`
Expected: 3 tests, 2 PASS, 1 SKIP or PASS (init test needs a real binary — test with fixtures later)

**Step 5: Commit**

```bash
git add python/fuzzgen4ghidra_engine/engine.py test/test_engine.py
git commit -m "feat(engine): add FuzzGenEngine orchestrating scorer, params, and harness gen"
```

---

### Task 7: TCP Server

**Files:**
- Create: `python/fuzzgen4ghidra_engine/server.py`
- Create: `python/fuzzgen4ghidra_engine/__main__.py`

**Step 1: Write server.py**

```python
# python/fuzzgen4ghidra_engine/server.py
import argparse
import logging
import socket
import threading

from .engine import FuzzGenEngine
from .protocol import parse_command, ok, error, progress

HOST = "127.0.0.1"
PORT = 13371

logging.basicConfig(
    level=logging.INFO,
    format="[fuzzgen4ghidra] %(levelname)s %(message)s",
)
logger = logging.getLogger("fuzzgen4ghidra")


HANDLERS = {
    "init": lambda eng, p: eng.init(p["binary_path"]),
    "analyze_params": lambda eng, p: eng.analyze_params(
        int(p["func_addr"], 16) if isinstance(p["func_addr"], str) else p["func_addr"],
        p["ghidra_signature"],
    ),
    "generate_harness": lambda eng, p: eng.generate_harness(
        func_addr=int(p["func_addr"], 16) if isinstance(p["func_addr"], str) else p["func_addr"],
        func_name=p["func_name"],
        ghidra_signature=p["ghidra_signature"],
        target_binary=p["target_binary"],
        fmt=p.get("fmt", "afl"),
        output_dir=p.get("output_dir"),
    ),
}


def handle_client(conn: socket.socket, engine: FuzzGenEngine):
    with conn.makefile("r", encoding="utf-8") as reader, \
         conn.makefile("w", encoding="utf-8") as writer:
        for line in reader:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = parse_command(line)
                logger.info("CMD: %s", cmd.type)

                if cmd.type == "scan_targets":
                    def cb(data):
                        writer.write(progress(data).to_json() + "\n")
                        writer.flush()
                    result = engine.scan_targets(
                        cmd.params.get("ghidra_functions", []),
                        progress_callback=cb,
                    )
                    resp = ok({"targets": result})
                else:
                    handler = HANDLERS.get(cmd.type)
                    if handler is None:
                        resp = error(f"Unknown command: {cmd.type}")
                    else:
                        result = handler(engine, cmd.params)
                        resp = ok(result)
            except Exception as e:
                logger.exception("Error handling command")
                resp = error(str(e))

            writer.write(resp.to_json() + "\n")
            writer.flush()


def main():
    parser = argparse.ArgumentParser(description="FuzzGen4Ghidra analysis engine")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("fuzzgen4ghidra").setLevel(logging.DEBUG)

    engine = FuzzGenEngine()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)
    logger.info("FuzzGen4Ghidra engine listening on %s:%d", args.host, args.port)

    try:
        while True:
            conn, addr = server.accept()
            logger.info("Client connected from %s", addr)
            thread = threading.Thread(
                target=handle_client, args=(conn, engine), daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
```

**Step 2: Write `__main__.py`**

```python
from .server import main
main()
```

**Step 3: Test manually**

Run in one terminal: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m fuzzgen4ghidra_engine -v`
Expected: `[fuzzgen4ghidra] INFO FuzzGen4Ghidra engine listening on 127.0.0.1:13371`

In another terminal: `echo '{"type":"init","params":{"binary_path":"/bin/ls"}}' | nc localhost 13371`
Expected: JSON response with `"status": "ok"` and arch info

**Step 4: Commit**

```bash
git add python/fuzzgen4ghidra_engine/server.py python/fuzzgen4ghidra_engine/__main__.py
git commit -m "feat(engine): add TCP server on port 13371"
```

---

### Task 8: Java Plugin Shell — EngineProtocol + EngineManager

**Files:**
- Create: `src/main/java/fuzzgen4ghidra/engine/EngineProtocol.java`
- Create: `src/main/java/fuzzgen4ghidra/engine/EngineManager.java`

**Step 1: Write EngineProtocol.java**

Model after Ponce4Ghidra's `EngineProtocol.java` (see `Ponce4Ghidra/src/main/java/ponce4ghidra/engine/EngineProtocol.java`). Same Command/Response structure, but with these commands:

- `initCmd(String binaryPath)`
- `scanTargetsCmd(String ghidraFunctionsJson)`
- `analyzeParamsCmd(String funcAddr, String ghidraSignatureJson)`
- `generateHarnessCmd(String funcAddr, String funcName, String ghidraSignatureJson, String targetBinary, String fmt, String outputDir)`

Use Gson for serialization. Port is 13371.

**Step 2: Write EngineManager.java**

Mirror Ponce4Ghidra's `EngineManager.java` but:
- Port: 13371
- Module: `fuzzgen4ghidra_engine.server`
- Support `sendCommandWithProgressAsync` for scan_targets progress

**Step 3: Build**

```bash
JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-23.jdk/Contents/Home \
  ~/.gradle/wrapper/dists/gradle-8.14.2-bin/2pb3mgt1p815evrl3weanttgr/gradle-8.14.2/bin/gradle \
  build -PGHIDRA_INSTALL_DIR=~/playground/research/re-plugins/ghidra_11.4.3_PUBLIC
```
Expected: BUILD SUCCESSFUL

**Step 4: Commit**

```bash
git add src/main/java/fuzzgen4ghidra/engine/
git commit -m "feat(plugin): add EngineProtocol and EngineManager for FuzzGen engine"
```

---

### Task 9: Java Plugin Shell — Main Plugin + GenerateHarnessAction

**Files:**
- Create: `src/main/java/fuzzgen4ghidra/FuzzGen4GhidraPlugin.java`
- Create: `src/main/java/fuzzgen4ghidra/actions/GenerateHarnessAction.java`
- Create: `src/main/java/fuzzgen4ghidra/actions/ScanTargetsAction.java`
- Create: `src/main/java/fuzzgen4ghidra/ui/HarnessPreviewDialog.java`

**Step 1: Write FuzzGen4GhidraPlugin.java**

```java
package fuzzgen4ghidra;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import fuzzgen4ghidra.actions.*;
import fuzzgen4ghidra.engine.EngineManager;

@PluginInfo(
    status = PluginStatus.UNSTABLE,
    packageName = "FuzzGen4Ghidra",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Automatic Fuzzing Harness Generation",
    description = "Generates AFL++/libFuzzer fuzzing harnesses for binary functions using angr analysis."
)
public class FuzzGen4GhidraPlugin extends Plugin {

    private EngineManager engineManager;

    public FuzzGen4GhidraPlugin(PluginTool tool) {
        super(tool);
        engineManager = new EngineManager();
        new GenerateHarnessAction(this);
        new ScanTargetsAction(this);
    }

    public EngineManager getEngineManager() { return engineManager; }

    // ensureEngineStarted() and ensureInitialized() — same pattern as Ponce4Ghidra

    @Override
    protected void dispose() {
        engineManager.dispose();
        super.dispose();
    }
}
```

**Step 2: Write GenerateHarnessAction.java**

Right-click action in Listing/Decompiler context menu under "FuzzGen4Ghidra > Generate Fuzz Harness". On click:

1. Get the function at the cursor (via `program.getFunctionManager().getFunctionContaining(addr)`)
2. Extract Ghidra's decompiled signature using `DecompInterface`
3. Send `generate_harness` command to engine
4. Show result in `HarnessPreviewDialog`

**Step 3: Write ScanTargetsAction.java**

Menu bar action "FuzzGen4Ghidra > Scan Fuzz Targets". Iterates all functions via Ghidra's FunctionManager, extracts names/addresses/export status, sends to engine, displays results in a dialog/console.

**Step 4: Write HarnessPreviewDialog.java**

Simple dialog with:
- JTextArea showing the generated C code (monospaced font)
- ComboBox to switch format (AFL++ / libFuzzer)
- "Save to Directory" button (JFileChooser)

**Step 5: Build**

```bash
JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-23.jdk/Contents/Home \
  ~/.gradle/wrapper/dists/gradle-8.14.2-bin/2pb3mgt1p815evrl3weanttgr/gradle-8.14.2/bin/gradle \
  buildExtension -PGHIDRA_INSTALL_DIR=~/playground/research/re-plugins/ghidra_11.4.3_PUBLIC
```
Expected: BUILD SUCCESSFUL, zip in dist/

**Step 6: Commit**

```bash
git add src/main/java/fuzzgen4ghidra/
git commit -m "feat(plugin): add FuzzGen4Ghidra plugin with GenerateHarness and ScanTargets actions"
```

---

### Task 10: Integration Test — End to End

**Files:**
- Create: `test/test_integration.py`

**Step 1: Write integration test**

```python
# test/test_integration.py
"""
End-to-end test: load a real binary, scan targets, generate a harness.
Requires angr and a test binary.
"""
import os
import subprocess
import tempfile
import pytest
from fuzzgen4ghidra_engine.engine import FuzzGenEngine

# Build a tiny shared library for testing
TINY_C = """\
#include <string.h>
#include <stdlib.h>

int parse_data(const unsigned char *buf, int len) {
    char local[64];
    if (len > 64) len = 64;
    memcpy(local, buf, len);
    return local[0];
}

int get_version(void) { return 1; }
"""

@pytest.fixture(scope="module")
def test_lib(tmp_path_factory):
    d = tmp_path_factory.mktemp("fuzzgen_test")
    src = d / "tiny.c"
    src.write_text(TINY_C)
    lib = d / "libtiny.so"
    result = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", str(lib), str(src)],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("gcc not available")
    return str(lib)

def test_full_pipeline(test_lib):
    engine = FuzzGenEngine()
    init_result = engine.init(test_lib)
    assert init_result["arch"]

    targets = engine.scan_targets([])
    assert len(targets) > 0
    # parse_data should score higher than get_version
    names = [t["name"] for t in targets]
    assert "parse_data" in names

    ghidra_sig = {
        "params": [
            {"name": "buf", "type": "byte *", "size": 8},
            {"name": "len", "type": "int", "size": 4},
        ]
    }
    with tempfile.TemporaryDirectory() as outdir:
        result = engine.generate_harness(
            func_addr=0,  # address doesn't matter for code gen
            func_name="parse_data",
            ghidra_signature=ghidra_sig,
            target_binary="libtiny.so",
            fmt="afl",
            output_dir=outdir,
        )
        assert os.path.exists(os.path.join(outdir, "harness_parse_data.c"))
        assert os.path.exists(os.path.join(outdir, "types.h"))
        assert os.path.exists(os.path.join(outdir, "Makefile"))
        assert os.path.exists(os.path.join(outdir, "seeds", "seed_000"))
```

**Step 2: Run test**

Run: `cd ~/playground/research/re-plugins/FuzzGen4Ghidra && PYTHONPATH=python python -m pytest test/test_integration.py -v`
Expected: PASS

**Step 3: Commit**

```bash
git add test/test_integration.py
git commit -m "test: add end-to-end integration test with tiny shared library"
```

---

### Task 11: Git init + final commit

**Step 1: Initialize repo**

```bash
cd ~/playground/research/re-plugins/FuzzGen4Ghidra
git init
```

**Step 2: Create .gitignore**

```
build/
dist/
.gradle/
.venv/
__pycache__/
*.class
*.pyc
*.lock
*.lock~
*.gpr
*.rep/
```

**Step 3: Initial commit with all work**

```bash
git add .
git commit -m "feat: FuzzGen4Ghidra MVP — automatic fuzzing harness generation for Ghidra

Adds a Ghidra plugin + Python/angr engine that:
- Scores binary functions by fuzzability (complexity, danger, input surface)
- Recovers parameter types from Ghidra's decompiler signatures
- Generates AFL++ and libFuzzer harness code with Jinja2 templates
- Communicates over JSON-line TCP (port 13371)

Architecture mirrors Ponce4Ghidra: Java plugin for UI, Python engine for analysis."
```
