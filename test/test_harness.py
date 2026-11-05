import pytest

from fuzzgen4ghidra_engine.harness import HarnessGenerator
from fuzzgen4ghidra_engine.models import ParamInfo, ParamType
from fuzzgen4ghidra_engine.platform import TargetInfo

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


# --- Android / NDK / JNI ---

def _android_info():
    return TargetInfo(platform="android", arch="AARCH64", bits=64,
                      triple="aarch64-linux-android", android_abi="arm64-v8a",
                      ndk_api=21, anchor_symbol="JNI_OnLoad")


def test_call_mode_resolution():
    gen = HarnessGenerator()
    assert gen.resolve_call_mode("auto", True) == "dlsym"
    assert gen.resolve_call_mode("auto", False) == "address"
    assert gen.resolve_call_mode("address", True) == "address"
    with pytest.raises(ValueError):
        gen.resolve_call_mode("nonsense", True)


def test_jni_mode_resolution():
    gen = HarnessGenerator()
    assert gen.resolve_jni_mode("auto", "JNI_OnLoad") == "onload"
    assert gen.resolve_jni_mode("auto", "Java_com_x_Y_z") == "env"
    assert gen.resolve_jni_mode("auto", "parse_packet") == "off"
    assert gen.resolve_jni_mode("off", "JNI_OnLoad") == "off"


def test_generate_resolves_auto_jni_mode():
    gen = HarnessGenerator()
    code = gen.generate("JNI_OnLoad", 0x597b0, [], "libmetasec.so", "afl",
                        target_info=_android_info(), jni_mode="auto")
    assert "fz_jni_vm()" in code
    with pytest.raises(ValueError):
        gen.generate("f", 0x1000, [], "lib.so", "afl", jni_mode="bogus")


def test_android_local_function_uses_load_bias():
    gen = HarnessGenerator()
    code = gen.generate(
        "parse_packet", 0x12345, _make_params(), "libtarget.so", "libfuzzer",
        target_info=_android_info(), func_vaddr=0x12345,
        is_exported=False, anchor_symbol="JNI_OnLoad", anchor_vaddr=0x597B0,
        jni_mode="off", run_jni_onload=False,
    )
    assert 'FZ_CALL_MODE    "address"' in code
    assert 'FZ_FUNC_VADDR   ((uintptr_t)0x12345)' in code
    assert 'FZ_ANCHOR_VADDR ((uintptr_t)0x597b0)' in code
    assert "load_bias" in code
    assert "dl_iterate_phdr" in code
    # Never silently skip the call: initialisation failures are fatal.
    assert "if (!g_target) return 0;" not in code
    assert "FATAL" in code


def test_android_makefile_uses_ndk():
    gen = HarnessGenerator()
    makefile = gen.generate_makefile(
        "parse_packet", "libtarget.so", "libfuzzer", target_info=_android_info())
    assert "ANDROID_NDK_HOME" in makefile
    assert "TRIPLE ?= aarch64-linux-android" in makefile
    assert "$(TRIPLE)$(API)-clang" in makefile
    assert "darwin-x86_64" in makefile
    assert "-fsanitize=fuzzer,address" in makefile
    assert "-lm" in makefile
    assert "afl-gcc" not in makefile


def test_host_makefile_stays_native():
    gen = HarnessGenerator()
    makefile = gen.generate_makefile("parse_packet", "libtarget.so", "afl")
    assert "afl-gcc" in makefile
    assert "ANDROID_NDK_HOME" not in makefile


def test_jni_env_mode_signature():
    gen = HarnessGenerator()
    params = [ParamInfo(index=2, name="data", type=ParamType.BUFFER,
                        c_type="uint8_t *", size=8, length_param=3),
              ParamInfo(index=3, name="len", type=ParamType.INT,
                        c_type="uint32_t", size=4)]
    code = gen.generate(
        "Java_com_luna_Native_do", 0x2000, params, "libluna.so", "libfuzzer",
        target_info=_android_info(), jni_mode="env", run_jni_onload=False,
    )
    assert "JNIEnv *env, jobject thiz" in code
    assert "_fz_env, _fz_thiz" in code
    assert '#include "jni_stub.h"' in code


def test_jni_onload_mode():
    gen = HarnessGenerator()
    code = gen.generate(
        "JNI_OnLoad", 0x597B0, [], "libluna.so", "libfuzzer",
        target_info=_android_info(), jni_mode="onload",
    )
    assert "fz_jni_vm()" in code
    assert "_fz_ran_onload" in code
    assert "JavaVM *vm, void *reserved" in code


def test_run_jni_onload_preinit():
    gen = HarnessGenerator()
    code = gen.generate(
        "parse_packet", 0x12345, _make_params(), "libtarget.so", "libfuzzer",
        target_info=_android_info(), jni_mode="off", run_jni_onload=True,
    )
    assert "fz_run_jni_onload(g_lib)" in code
    assert "fz_init_jni()" in code


def test_jni_stub_header():
    gen = HarnessGenerator()
    header = gen.generate_jni_header()
    for needle in ("fz_jni_env", "fz_jni_vm", "RegisterNatives",
                   "JNI_VERSION_1_6", "GetByteArrayElements", "AttachCurrentThread"):
        assert needle in header
    # must compile as a C header
    assert "#ifndef FUZZGEN_JNI_STUB_H" in header


def test_android_scripts():
    gen = HarnessGenerator()
    build = gen.generate_build_script("parse_packet", "libtarget.so", "libfuzzer",
                                      target_info=_android_info())
    assert "ANDROID_NDK_HOME" in build
    assert "aarch64-linux-android" in build

    run = gen.generate_run_script("parse_packet", "libtarget.so", "afl",
                                  target_info=_android_info())
    # DT_NEEDED siblings must be pushed or dlopen fails on device.
    assert "pushing dependency" in run
    assert "LD_LIBRARY_PATH" in run
    assert "arm64-v8a" in run

    run = gen.generate_run_script("parse_packet", "libtarget.so", "libfuzzer",
                                  target_info=_android_info())
    assert "adb push" in run
    assert "/data/local/tmp/fuzzgen_parse_packet" in run
    assert "arm64-v8a" in run
