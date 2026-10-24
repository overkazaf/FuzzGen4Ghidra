"""
End-to-end test: load a real binary, scan targets, generate a harness.
Requires angr and a test binary.
"""
import os
import platform
import subprocess
import tempfile
import pytest
from fuzzgen4ghidra_engine.engine import FuzzGenEngine

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
    if platform.system() == "Darwin":
        lib = d / "libtiny.dylib"
        cmd = ["cc", "-dynamiclib", "-o", str(lib), str(src)]
    else:
        lib = d / "libtiny.so"
        cmd = ["gcc", "-shared", "-fPIC", "-o", str(lib), str(src)]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        pytest.skip("compiler not available")
    return str(lib)

def test_full_pipeline(test_lib):
    engine = FuzzGenEngine()
    init_result = engine.init(test_lib)
    assert init_result["arch"]

    targets = engine.scan_targets([])
    assert len(targets) > 0
    # On macOS, angr's Mach-O backend may not preserve symbol names
    if platform.system() != "Darwin":
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
            func_addr=0,
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
