"""Target platform detection and address helpers.

The engine works on two address spaces:

* **Ghidra** reports the raw ELF virtual address (image base 0 for shared
  objects).
* **angr/CLE** maps ELF objects at a non-zero base (``0x400000`` by default),
  so ``func.rebased_addr`` = ``mapped_base + vaddr``.

Everything below converts between the two and decides whether a target is an
Android ELF, which is what drives the NDK cross-compilation path.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace


NDK_TRIPLES = {
    "AARCH64": "aarch64-linux-android",
    "ARMEL": "armv7a-linux-androideabi",
    "ARMHF": "armv7a-linux-androideabi",
    "X86": "i686-linux-android",
    "AMD64": "x86_64-linux-android",
}

ANDROID_ABIS = {
    "AARCH64": "arm64-v8a",
    "ARMEL": "armeabi-v7a",
    "ARMHF": "armeabi-v7a",
    "X86": "x86",
    "AMD64": "x86_64",
}

ANDROID_MARKER_DEPS = frozenset({"liblog.so", "libandroid.so"})


@dataclass
class TargetInfo:
    """What the harness generator needs to know about the loaded binary."""

    platform: str = "host"          # "host" | "android"
    binary_format: str = "elf"      # "elf" | "mach-o" | "pe"
    arch: str = ""                  # angr arch name, e.g. AARCH64
    bits: int = 64
    triple: str | None = None       # aarch64-linux-android
    android_abi: str | None = None  # arm64-v8a
    ndk_api: int = 21
    soname: str | None = None
    deps: list[str] = field(default_factory=list)
    mapped_base: int = 0            # CLE load base
    min_vaddr: int = 0              # raw ELF min vaddr
    anchor_symbol: str | None = None

    @property
    def is_android(self) -> bool:
        return self.platform == "android"

    def with_overrides(self, platform: str | None = None, ndk_api: int | None = None) -> "TargetInfo":
        updates = {}
        new_platform = self.platform
        if platform and platform != "auto":
            new_platform = platform
            updates["platform"] = platform
        if ndk_api:
            updates["ndk_api"] = int(ndk_api)
        if new_platform == "android":
            if not self.triple and self.arch in NDK_TRIPLES:
                updates["triple"] = NDK_TRIPLES[self.arch]
            if not self.android_abi and self.arch in ANDROID_ABIS:
                updates["android_abi"] = ANDROID_ABIS[self.arch]
        return replace(self, **updates) if updates else self

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "binary_format": self.binary_format,
            "arch": self.arch,
            "bits": self.bits,
            "triple": self.triple,
            "android_abi": self.android_abi,
            "ndk_api": self.ndk_api,
            "soname": self.soname,
            "deps": self.deps,
        }


def _binary_format(obj) -> str:
    try:
        from cle.backends.elf import ELF
        if isinstance(obj, ELF):
            return "elf"
    except Exception:
        pass
    try:
        from cle.backends.macho import MachO
        if isinstance(obj, MachO):
            return "mach-o"
    except Exception:
        pass
    try:
        from cle.backends.pe import PE
        if isinstance(obj, PE):
            return "pe"
    except Exception:
        pass
    return "unknown"


def _has_android_note(binary_path: str) -> bool:
    try:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            return elf.get_section_by_name(".note.android.ident") is not None
    except Exception:
        return False


def _is_android(obj, binary_path: str) -> bool:
    deps = set(getattr(obj, "deps", []) or [])
    if deps & ANDROID_MARKER_DEPS:
        return True
    return _has_android_note(binary_path)


def _anchor_symbol(obj) -> str | None:
    """An exported function used to recover the shared object's load bias."""
    candidates = []
    for sym in getattr(obj, "symbols", []):
        if sym.is_export and sym.is_function and sym.name:
            candidates.append(sym.name)
    if not candidates:
        return None
    # JNI_OnLoad is present in almost every Android native library and is
    # exported, so it is the most reliable anchor.
    if "JNI_OnLoad" in candidates:
        return "JNI_OnLoad"
    return candidates[0]


def _soname(obj) -> str | None:
    """The object's SONAME.

    CLE stores ``provides`` as a plain string for ELF (PE backends use a set).
    A string is iterable, so ``next(iter(provides))`` would return its first
    character rather than the name.
    """
    provides = getattr(obj, "provides", None)
    if isinstance(provides, str):
        return provides or None
    if provides:
        return next(iter(provides))
    return None


def detect_target(project, binary_path: str) -> TargetInfo:
    obj = project.loader.main_object
    fmt = _binary_format(obj)
    arch = project.arch.name
    bits = project.arch.bits
    mapped_base = int(getattr(obj, "mapped_base", 0) or 0)
    min_addr = int(getattr(obj, "min_addr", mapped_base) or mapped_base)
    linked_base = int(getattr(obj, "linked_base", 0) or 0)
    min_vaddr = max(0, min_addr - mapped_base + linked_base)
    soname = _soname(obj)

    platform = "host"
    triple = None
    abi = None
    if fmt == "elf" and _is_android(obj, binary_path):
        platform = "android"
        triple = NDK_TRIPLES.get(arch)
        abi = ANDROID_ABIS.get(arch)

    return TargetInfo(
        platform=platform,
        binary_format=fmt,
        arch=arch,
        bits=bits,
        triple=triple,
        android_abi=abi,
        soname=soname,
        deps=list(getattr(obj, "deps", []) or []),
        mapped_base=mapped_base,
        min_vaddr=min_vaddr,
        anchor_symbol=_anchor_symbol(obj),
    )


def raw_vaddr(obj, addr: int) -> int:
    """Normalize a Ghidra/angr address to the raw ELF virtual address.

    Ghidra hands over the raw vaddr (image base 0), while angr's
    ``rebased_addr`` includes CLE's load base. Accept both.
    """
    mapped_base = int(getattr(obj, "mapped_base", 0) or 0)
    min_addr = int(getattr(obj, "min_addr", mapped_base) or mapped_base)
    max_addr = int(getattr(obj, "max_addr", min_addr) or min_addr)
    if mapped_base and min_addr <= addr <= max_addr:
        return addr - mapped_base
    return addr


_SEGMENT_CACHE: dict[str, tuple[tuple[int, int], ...]] = {}


def elf_segments(binary_path: str) -> tuple[tuple[int, int], ...]:
    """(vaddr, memsz) of every PT_LOAD segment, sorted."""
    if binary_path in _SEGMENT_CACHE:
        return _SEGMENT_CACHE[binary_path]
    segs: list[tuple[int, int]] = []
    try:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                start = int(seg["p_vaddr"])
                segs.append((start, start + int(seg["p_memsz"])))
    except Exception:
        pass
    result = tuple(sorted(segs))
    _SEGMENT_CACHE[binary_path] = result
    return result


def vaddr_in_elf(binary_path: str, addr: int) -> bool:
    """True when ``addr`` is a raw ELF virtual address inside a PT_LOAD."""
    return any(lo <= addr < hi for lo, hi in elf_segments(binary_path))


def normalize_vaddr(binary_path: str, obj, addr: int) -> int:
    """Return the raw ELF virtual address for ``addr``.

    Ghidra gives us raw virtual addresses; angr/CLE gives rebased ones. Both
    are accepted, and which one we have is decided by the program headers
    rather than by guessing from the value (a large library can legitimately
    have raw addresses above CLE's 0x400000 mapping base).
    """
    if vaddr_in_elf(binary_path, addr):
        return addr
    mapped_base = int(getattr(obj, "mapped_base", 0) or 0)
    linked_base = int(getattr(obj, "linked_base", 0) or 0)
    if mapped_base:
        # rebased_addr = st_value - linked_base + mapped_base
        raw = addr - mapped_base + linked_base
        if vaddr_in_elf(binary_path, raw):
            return raw
    return addr


def rebased_to_vaddr(obj, addr: int) -> int:
    """Convert a CLE rebased address to the raw ELF virtual address (st_value)."""
    mapped_base = int(getattr(obj, "mapped_base", 0) or 0)
    linked_base = int(getattr(obj, "linked_base", 0) or 0)
    return addr - mapped_base + linked_base


def exported_vaddrs(obj) -> set[int]:
    """Raw ELF virtual addresses of all dynamically exported functions."""
    out = set()
    for sym in getattr(obj, "symbols", []):
        if sym.is_export and sym.is_function:
            out.add(rebased_to_vaddr(obj, int(sym.rebased_addr)))
    return out


def is_exported_address(obj, addr: int) -> bool:
    """True when ``addr`` is a dynamically exported function."""
    raw = raw_vaddr(obj, addr)
    mapped_base = int(getattr(obj, "mapped_base", 0) or 0)
    rebased = raw + mapped_base
    for sym in getattr(obj, "symbols", []):
        if sym.is_export and sym.is_function and sym.rebased_addr == rebased:
            return True
    return False
