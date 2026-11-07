"""Read-only identification and bounded inspection of ELF64 and PS4 SELF files.

Do not mistake a SELF container for a decrypted ELF; the original PS4
container may have encrypted payloads. This parser reads only public headers.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import struct

MAX_BINARY_SIZE = 64 * 1024 * 1024
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
PS4_SELF_MAGIC = b"\x4f\x15\x3d\x1d"
PS4_ELF_TYPES = {0xFE00: "ET_SCE_EXEC", 0xFE10: "ET_SCE_EXEC_ASLR", 0xFE18: "ET_SCE_DYNAMIC"}
SEGMENT_TYPES = {
    0: "PT_NULL", 1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP",
    4: "PT_NOTE", 6: "PT_PHDR", 0x61000000: "PT_SCE_DYNLIBDATA",
    0x61000001: "PT_SCE_PROCPARAM", 0x61000010: "PT_SCE_RELRO",
}


class BinaryFormatError(ValueError):
    """Malformed, unsupported or oversized input."""


def read_bounded(path: Path, *, limit: int = MAX_BINARY_SIZE) -> bytes:
    """Read at most limit+1 bytes; never permit unbounded reads."""
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise BinaryFormatError(f"File exceeds {limit} bytes")
    return data


def inspect_bytes(data: bytes) -> dict:
    base = {"bytes": len(data), "sha256": sha256(data).hexdigest()}
    if data.startswith(PS4_SELF_MAGIC):
        if len(data) < 32:
            raise BinaryFormatError("Truncated PS4 SELF header")
        return {
            **base,
            "format": "PS4 SELF container",
            "encrypted_content": "unknown; not inspected",
            "note": "Only container magic was identified. No ELF/decryption claim.",
        }
    if len(data) < ELF_HEADER.size or data[:4] != b"\x7fELF":
        raise BinaryFormatError("Not an ELF64 or recognizable PS4 SELF header")
    ident, elf_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = ELF_HEADER.unpack_from(data)
    if ident[4] != 2 or ident[5] != 1 or ident[6] != 1:
        raise BinaryFormatError("Only ELF64 little-endian version 1 is supported")
    if version != 1 or ehsize != 64 or machine != 62:
        raise BinaryFormatError("Expected ELF64 x86-64 with a 64-byte header")
    if phnum > 1024 or shnum > 4096:
        raise BinaryFormatError("Too many ELF headers")
    if phnum and (phentsize != PROGRAM_HEADER.size or phoff < ELF_HEADER.size or
                  phoff + phnum * phentsize > len(data)):
        raise BinaryFormatError("Invalid ELF program-header table")
    if shnum and (shentsize != 64 or shoff < ELF_HEADER.size or
                  shoff + shnum * shentsize > len(data)):
        raise BinaryFormatError("Invalid ELF section-header table")
    if shnum and shstrndx not in (0, 0xFFFF) and shstrndx >= shnum:
        raise BinaryFormatError("Invalid ELF section-name index")
    segments = []
    counts: dict[str, int] = {}
    for idx in range(phnum):
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = PROGRAM_HEADER.unpack_from(
            data, phoff + idx * phentsize
        )
        if p_filesz and (p_offset > len(data) or p_filesz > len(data) - p_offset):
            raise BinaryFormatError(f"Program header {idx} points outside file")
        if p_type == 1 and p_filesz > p_memsz:
            raise BinaryFormatError(f"PT_LOAD {idx} has p_filesz > p_memsz")
        typ = SEGMENT_TYPES.get(p_type, hex(p_type))
        counts[typ] = counts.get(typ, 0) + 1
        if len(segments) < 48:
            segments.append({
                "type": typ, "flags": p_flags, "offset": hex(p_offset),
                "vaddr": hex(p_vaddr), "filesz": p_filesz, "memsz": p_memsz,
            })
    return {
        **base,
        "format": "Orbis ELF64" if elf_type in PS4_ELF_TYPES else "ELF64",
        "elf_type": PS4_ELF_TYPES.get(elf_type, hex(elf_type)),
        "entry_point": hex(entry), "machine": "x86-64", "flags": flags,
        "program_headers": phnum, "section_headers": shnum,
        "program_header_types": counts, "segments": segments,
        "segments_truncated": phnum > len(segments),
        "note": "Static header inspection only; no runtime compatibility guaranteed.",
    }


def inspect_path(path: Path) -> dict:
    return inspect_bytes(read_bounded(path))
