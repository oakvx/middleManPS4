"""Bounded, read-only dynamic-segment inventory for x86-64 ELF / Orbis ELF.

The Orbis dynamic tags are kept as raw values on purpose. Their interpretation
can depend on the file format and the dynamic-linking context; this module
never treats an observed tag as proof of a valid import or authentication call.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
from pathlib import Path
import re
import struct

from .binary import (
    ELF_HEADER, PROGRAM_HEADER, BinaryFormatError, inspect_bytes as inspect_elf_bytes, read_bounded,
)

DYNAMIC_ENTRY = struct.Struct("<QQ")
MAX_DYNAMIC_ENTRIES = 2048
MAX_REPORTED_ENTRIES = 256
MAX_LIBRARY_NAMES = 128
MAX_LIBRARY_NAME_LENGTH = 160

DYNAMIC_TAGS = {
    0: "DT_NULL", 1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT",
    4: "DT_HASH", 5: "DT_STRTAB", 6: "DT_SYMTAB", 7: "DT_RELA",
    8: "DT_RELASZ", 9: "DT_RELAENT", 10: "DT_STRSZ", 11: "DT_SYMENT",
    14: "DT_SONAME", 15: "DT_RPATH", 17: "DT_REL", 18: "DT_RELSZ",
    19: "DT_RELENT", 20: "DT_PLTREL", 21: "DT_DEBUG", 22: "DT_TEXTREL",
    23: "DT_JMPREL", 29: "DT_RUNPATH", 30: "DT_FLAGS",
    0x61000007: "DT_SCE_FINGERPRINT", 0x61000009: "DT_SCE_FILENAME",
    0x6100000D: "DT_SCE_MODULE_INFO", 0x6100000F: "DT_SCE_NEEDED_MODULE",
    0x61000011: "DT_SCE_MODULE_ATTR", 0x61000013: "DT_SCE_EXPORT_LIB",
    0x61000015: "DT_SCE_IMPORT_LIB", 0x61000017: "DT_SCE_EXPORT_LIB_ATTR",
    0x61000019: "DT_SCE_IMPORT_LIB_ATTR",
    0x6100001D: "DT_SCE_STUB_MODULE_NAME",
    0x6100001F: "DT_SCE_STUB_MODULE_VER",
    0x61000021: "DT_SCE_STUB_LIBRARY_NAME",
    0x61000023: "DT_SCE_STUB_LIBRARY_VER",
    0x61000025: "DT_SCE_HASH", 0x61000027: "DT_SCE_PLTGOT",
    0x61000029: "DT_SCE_JMPREL", 0x6100002B: "DT_SCE_PLTREL",
    0x6100002D: "DT_SCE_PLTRELSZ", 0x6100002F: "DT_SCE_RELA",
    0x61000031: "DT_SCE_RELASZ", 0x61000033: "DT_SCE_RELAENT",
    0x61000035: "DT_SCE_STRTAB", 0x61000037: "DT_SCE_STRSZ",
    0x61000039: "DT_SCE_SYMTAB", 0x6100003B: "DT_SCE_SYMENT",
    0x6100003D: "DT_SCE_HASHSZ", 0x6100003F: "DT_SCE_SYMTABSZ",
}
SAFE_LIB_NAME = re.compile(rb"[A-Za-z0-9_+./-]{1,160}\Z")


def _phdrs(data: bytes) -> list[dict[str, int]]:
    # inspect_bytes performs strict ELF64, x86-64 and table-bound checks.
    inspect_elf_bytes(data)
    header = ELF_HEADER.unpack_from(data)
    phoff, phentsize, phnum = header[5], header[9], header[10]
    headers = []
    for i in range(phnum):
        typ, flags, offset, vaddr, paddr, size, memsize, align = PROGRAM_HEADER.unpack_from(
            data, phoff + i * phentsize
        )
        headers.append({"type": typ, "offset": offset, "vaddr": vaddr,
                        "size": size, "memsize": memsize})
    return headers


def _virtual_to_file(address: int, count: int, phdrs: list[dict[str, int]], data: bytes) -> int | None:
    """Map a *file-backed* PT_LOAD virtual range; never read from BSS."""
    for p in phdrs:
        if p["type"] != 1 or address < p["vaddr"]:
            continue
        delta = address - p["vaddr"]
        if delta <= p["size"] and count <= p["size"] - delta:
            filepos = p["offset"] + delta
            if filepos <= len(data) and count <= len(data) - filepos:
                return filepos
    return None


def _needed_libraries(data: bytes, entries: list[tuple[int, int]],
                      phdrs: list[dict[str, int]]) -> list[str]:
    """Resolve standard DT_NEEDED strings; Orbis packed module IDs are excluded."""
    strtabs = [value for tag, value in entries if tag == 5]
    sizes = [value for tag, value in entries if tag == 10]
    if len(strtabs) != 1 or len(sizes) != 1 or not 0 < sizes[0] <= 1024 * 1024:
        return []
    table_off = _virtual_to_file(strtabs[0], sizes[0], phdrs, data)
    if table_off is None:
        return []
    table = data[table_off:table_off + sizes[0]]
    libraries = []
    for tag, value in entries:
        if tag != 1 or len(libraries) == MAX_LIBRARY_NAMES or value >= len(table):
            continue
        end = table.find(b"\0", value, min(len(table), value + MAX_LIBRARY_NAME_LENGTH + 1))
        if end == -1:
            continue
        item = table[value:end]
        if SAFE_LIB_NAME.fullmatch(item):
            name = item.decode("ascii")
            if name not in libraries:
                libraries.append(name)
    return libraries


def inspect_bytes(data: bytes) -> dict:
    head = inspect_elf_bytes(data)
    if head["format"] == "PS4 SELF container":
        raise BinaryFormatError("SELF container is not an unpacked ELF; no dynamic table available")
    phdrs = _phdrs(data)
    dynamic = []
    counts: Counter[str] = Counter()
    raw_entries: list[tuple[int, int]] = []
    terminated = True
    for p in phdrs:
        if p["type"] != 2:
            continue
        if p["size"] % DYNAMIC_ENTRY.size:
            raise BinaryFormatError("PT_DYNAMIC has a partial 16-byte entry")
        count = p["size"] // DYNAMIC_ENTRY.size
        if count > MAX_DYNAMIC_ENTRIES:
            raise BinaryFormatError("PT_DYNAMIC exceeds entry safety limit")
        found_null = False
        for i in range(count):
            tag, value = DYNAMIC_ENTRY.unpack_from(data, p["offset"] + i * DYNAMIC_ENTRY.size)
            name = DYNAMIC_TAGS.get(tag, hex(tag))
            counts[name] += 1
            if len(dynamic) < MAX_REPORTED_ENTRIES:
                dynamic.append({"tag": name, "raw_value": hex(value)})
            if tag == 0:
                found_null = True
                break
            raw_entries.append((tag, value))
        if not found_null:
            terminated = False
    orbis_segments = [p for p in phdrs if p["type"] in (0x61000000, 0x61000001, 0x61000010)]
    return {
        "format": "middleManPS4-dynamic-v1", "file_sha256": sha256(data).hexdigest(),
        "elf_type": head["elf_type"], "is_orbis_elf_type": head["format"] == "Orbis ELF64",
        "dynamic_tag_counts": dict(sorted(counts.items())),
        "dynamic_entries": dynamic, "dynamic_entries_truncated": sum(counts.values()) > len(dynamic),
        "dynamic_terminated": terminated, "standard_dt_needed": _needed_libraries(data, raw_entries, phdrs),
        "orbis_segments": [{"type": hex(p["type"]), "file_offset": hex(p["offset"]),
                            "size": p["size"]} for p in orbis_segments],
        "note": "Raw Orbis dynamic tags are metadata, not validated imports/exports; "
                "DT_NEEDED covers only standard ELF string tables.",
    }


def inspect_path(path: Path) -> dict:
    return inspect_bytes(read_bounded(path))
