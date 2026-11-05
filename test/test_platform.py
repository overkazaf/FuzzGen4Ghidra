import os

import pytest

from fuzzgen4ghidra_engine.platform import (
    TargetInfo,
    normalize_vaddr,
    vaddr_in_elf,
)

SAMPLE = os.path.join(
    os.path.dirname(__file__), "..", "data", "qishui", "metasec",
    "libmetasec_ml_REAL_RESTORED.so",
)


class _FakeObj:
    def __init__(self, mapped_base):
        self.mapped_base = mapped_base


def test_target_info_defaults():
    info = TargetInfo()
    assert info.platform == "host"
    assert info.is_android is False
    assert info.ndk_api == 21


def test_with_overrides_forces_android_and_fills_triple():
    info = TargetInfo(arch="AARCH64", bits=64)
    forced = info.with_overrides(platform="android", ndk_api=23)
    assert forced.is_android
    assert forced.triple == "aarch64-linux-android"
    assert forced.android_abi == "arm64-v8a"
    assert forced.ndk_api == 23
    # the original is untouched
    assert info.platform == "host"
    assert info.triple is None


def test_with_overrides_auto_is_a_noop():
    info = TargetInfo(arch="X86", bits=32)
    assert info.with_overrides(platform="auto") is info


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample .so not present")
def test_vaddr_in_elf_raw_vs_rebased():
    # Ghidra reports raw ELF virtual addresses; CLE rebases by 0x400000.
    assert vaddr_in_elf(SAMPLE, 0x597B0)
    assert not vaddr_in_elf(SAMPLE, 0x4597B0)


@pytest.mark.skipif(not os.path.exists(SAMPLE), reason="sample .so not present")
def test_normalize_vaddr_accepts_both_spaces():
    obj = _FakeObj(0x400000)
    assert normalize_vaddr(SAMPLE, obj, 0x597B0) == 0x597B0
    assert normalize_vaddr(SAMPLE, obj, 0x4597B0) == 0x597B0


def test_normalize_vaddr_without_project_data():
    # No PT_LOAD matches anywhere: the value is returned unchanged.
    assert normalize_vaddr("/nonexistent.so", _FakeObj(0x400000), 0x1234) == 0x1234


def test_soname_from_string_or_set():
    """CLE gives ELF a plain string; iterating it would yield one character."""
    from types import SimpleNamespace
    from fuzzgen4ghidra_engine.platform import _soname

    assert _soname(SimpleNamespace(provides="libmedecrypter.so")) == "libmedecrypter.so"
    assert _soname(SimpleNamespace(provides={"libx.so"})) == "libx.so"
    assert _soname(SimpleNamespace(provides=None)) is None
    assert _soname(SimpleNamespace()) is None
