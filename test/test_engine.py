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


def test_jni_stub_ignored_for_host_target():
    """jni.h only ships with the NDK, so a host build must not require it."""
    engine = FuzzGenEngine()
    result = engine.generate_harness(
        func_addr=0x400560, func_name="JNI_OnLoad",
        ghidra_signature={"params": []}, target_binary="libtest.dylib", fmt="afl",
        target_platform="host", jni_mode="auto", output_dir=None,
    )
    assert result["platform"] == "host"
    assert result["jni_mode"] == "off"
    assert "jni_stub.h" not in result["makefile"]
    assert "#include <jni.h>" not in result["harness_code"]
    assert "fz_jni_vm" not in result["harness_code"]


def test_android_jni_onload_still_gated_on_platform():
    engine = FuzzGenEngine()
    sig = {"params": [
        {"name": "env", "type": "void *", "size": 8},
        {"name": "thiz", "type": "void *", "size": 8},
        {"name": "data", "type": "byte *", "size": 8},
        {"name": "len", "type": "int", "size": 4},
    ]}
    result = engine.generate_harness(
        func_addr=0x1234, func_name="Java_com_x_Y_z",
        ghidra_signature=sig, target_binary="libcrypto.so", fmt="afl",
        target_platform="android", jni_mode="auto",
    )
    assert result["platform"] == "android"
    assert result["jni_mode"] == "env"
    # JNIEnv*/jobject are synthesised, only the trailing params stay fuzzable.
    assert "JNIEnv *env, jobject thiz, uint8_t * data, int len" in result["harness_code"]
    assert "jni_stub.h" in result["makefile"]
