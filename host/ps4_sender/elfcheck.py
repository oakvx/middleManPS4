"""Static checks for SDK-style PS4 ELF64 ET_DYN payloads targeting elfldr v0.7.

The upstream v0.7 ELF TCP reader relies on an ELF *section header table* to
find the number of bytes to read. The native loader then indexes PT_LOAD
virtual addresses from a zero-based mapping. These additional constraints are
not universal ELF rules: they model this particular loader's limitations.
Passing these checks never proves a payload will run on a PS4.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

MAX_ELF_SIZE = 64 * 1024 * 1024
MAX_IMAGE_SIZE = 64 * 1024 * 1024


class ELFError(ValueError):
    """Payload does not meet the supported loader's static requirements."""


def inspect_elf(data: bytes) -> dict[str, int | str]:
    if not 64 <= len(data) <= MAX_ELF_SIZE or data[:4] != b"\x7fELF":
        raise ELFError("invalid ELF signature, minimum size or size limit")
    if data[4] != 2 or data[5] != 1 or data[6] != 1:
        raise ELFError("expected ELF64, little-endian, current ELF version")

    e_type, e_machine, e_version = struct.unpack_from("<HHI", data, 16)
    entry, phoff, shoff = struct.unpack_from("<QQQ", data, 24)
    ehsize = struct.unpack_from("<H", data, 52)[0]
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 54)
    if e_type != 3:
        raise ELFError(f"expected ET_DYN (3), got {e_type}")
    if e_machine != 62:
        raise ELFError(f"expected EM_X86_64 (62), got {e_machine}")
    if e_version != 1 or ehsize != 64 or phentsize != 56 or not 1 <= phnum <= 128:
        raise ELFError("invalid ELF version or ELF/program header dimensions")
    if phoff < 64 or phoff + phnum * phentsize > len(data):
        raise ELFError("program header table outside file")
    # elfldr v0.7 reads up to e_shoff + e_shnum * 64 bytes before examining
    # sections. With e_shoff=e_shnum=0 it would allocate 0 and memcpy 64.
    if not 1 <= shnum <= 1024 or shentsize != 64 or shoff < 64 or shoff + shnum * 64 > len(data):
        raise ELFError("elfldr v0.7 requires a valid nonempty section header table")
    if shstrndx not in (0, 0xFFFF) and shstrndx >= shnum:
        raise ELFError("invalid section name table index")

    stream_size = shoff + shnum * shentsize
    relocation_sections: list[tuple[int, int, int]] = []
    for index in range(shnum):
        base = shoff + index * shentsize
        _, shtype, _, _, sec_offset, sec_size, _, _, _, sec_entsize = struct.unpack_from(
            "<IIQQQQIIQQ", data, base
        )
        if shtype != 8:  # SHT_NOBITS has no corresponding file content
            if sec_offset > len(data) or sec_size > len(data) - sec_offset:
                raise ELFError(f"section[{index}] content outside file")
            stream_size = max(stream_size, sec_offset + sec_size)
        if shtype == 4:  # SHT_RELA, entries are Elf64_Rela: 24 bytes
            if sec_size % 24 or sec_entsize not in (0, 24):
                raise ELFError(f"SHT_RELA[{index}] invalid relocation entry size")
            relocation_sections.append((index, sec_offset, sec_size))

    # The v0.7 reader only receives data through the end of the section
    # headers / referenced section contents, not necessarily the full file.
    if phoff + phnum * phentsize > stream_size:
        raise ELFError("program headers not fully received by elfldr v0.7")

    load_count = 0
    native_min_vaddr = 1 << 64
    native_max_vaddr = 0
    dynamic_count = 0
    executable_entry = False
    min_vaddr = 1 << 64
    max_vaddr = 0
    load_ranges: list[tuple[int, int]] = []
    external_relative_addends = 0
    for n in range(phnum):
        offset = phoff + n * phentsize
        ptype, pflags, poff, pvaddr, _, pfilesz, pmemsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset
        )
        # The native elfldr.c allocator computes its address range using ALL
        # program headers, including PT_NOTE/GNU_STACK; verify those too.
        if pvaddr + pmemsz > 2**64:
            raise ELFError(f"program header[{n}] virtual address overflow")
        native_min_vaddr = min(native_min_vaddr, pvaddr)
        native_max_vaddr = max(native_max_vaddr, pvaddr + pmemsz)
        if ptype not in (1, 2):
            continue
        if poff > len(data) or pfilesz > len(data) - poff:
            raise ELFError(f"PT_{'LOAD' if ptype == 1 else 'DYNAMIC'}[{n}] data outside file")
        if poff + pfilesz > stream_size:
            raise ELFError(f"PT_{'LOAD' if ptype == 1 else 'DYNAMIC'}[{n}] not fully received by elfldr")
        if ptype == 2:
            dynamic_count += 1
            continue
        load_count += 1
        if pfilesz > pmemsz:
            raise ELFError(f"PT_LOAD[{n}] file size exceeds memory size")
        if pvaddr + pmemsz > 2**64:
            raise ELFError(f"PT_LOAD[{n}] virtual address overflow")
        if pmemsz:
            min_vaddr = min(min_vaddr, pvaddr)
            max_vaddr = max(max_vaddr, pvaddr + pmemsz)
            load_ranges.append((pvaddr, pvaddr + pmemsz))
            if (pflags & 1) and pvaddr <= entry < pvaddr + pfilesz:
                executable_entry = True

    if not load_count or not load_ranges:
        raise ELFError("no PT_LOAD segments with memory")
    # elfldr v0.7 allocates max-min bytes but accesses memory as base+p_vaddr.
    if min_vaddr != 0:
        raise ELFError("elfldr v0.7 requires PT_LOAD minimum virtual address 0")
    if native_min_vaddr != 0:
        raise ELFError("elfldr v0.7 requires minimum virtual address 0 across all headers")
    if max_vaddr > MAX_IMAGE_SIZE or native_max_vaddr > MAX_IMAGE_SIZE:
        raise ELFError(f"ELF image exceeds configured {MAX_IMAGE_SIZE} byte limit")
    if not executable_entry:
        raise ELFError("entry point is not inside an executable PT_LOAD segment")

    for index, sec_offset, sec_size in relocation_sections:
        for cursor in range(sec_offset, sec_offset + sec_size, 24):
            target, info, addend = struct.unpack_from("<QQq", data, cursor)
            if (info & 0xFFFFFFFF) != 8:  # elfldr only processes R_X86_64_RELATIVE
                continue
            # The loader writes one 64-bit pointer into its mapped image.
            if not any(start <= target and target + 8 <= end for start, end in load_ranges):
                raise ELFError(f"SHT_RELA[{index}] relative relocation target outside PT_LOAD")
            # R_X86_64_RELATIVE stores (load_base + signed addend) *at* target.
            # Only the *write destination* must lie in mapped writable memory
            # for the loader to apply the relocation safely. The resulting
            # pointer can legally be a sentinel, an offset outside the ELF
            # image, or a value interpreted only at runtime. Rejecting the
            # addend merely for not pointing into PT_LOAD caused false
            # negatives for genuine SDK-built ELF files (v7 regression).
            if not any(start <= addend < end for start, end in load_ranges):
                external_relative_addends += 1

    # elfldr v0.7 stops reading once all section-referenced bytes have
    # arrived. Sending additional bytes leaves them queued on the same socket
    # later inherited as stdin by the spawned process. Reject that ambiguity.
    if stream_size != len(data):
        raise ELFError(
            f"unread ELF trailing bytes: elfldr consumes {stream_size}, "
            f"but file contains {len(data)} (unexpected stdin contamination)"
        )

    return {
        "format": "ELF64 little-endian x86-64",
        "type": "ET_DYN",
        "entry": hex(entry),
        "program_headers": phnum,
        "section_headers": shnum,
        "load_segments": load_count,
        "dynamic_segments": dynamic_count,
        "bytes": len(data),
        "elfldr_read_bytes": stream_size,
        "image_bytes": max_vaddr,
        "relative_addends_outside_load": external_relative_addends,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def inspect_path(path: Path) -> dict[str, int | str]:
    return inspect_elf(path.read_bytes())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check PS4 ELF64 x86-64 ET_DYN against elfldr v0.7 reader")
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = inspect_path(args.file)
    except (OSError, ELFError) as e:
        print(f"ELF CHECK FAILED: {e}")
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True, indent=2))
    else:
        print(f"ELF structurally compatible with checked v0.7 assumptions: {args.file}")
        for key, value in report.items():
            print(f"  {key}: {value}")
        if report["relative_addends_outside_load"]:
            print("NOTE: relative relocation addends outside PT_LOAD are not forbidden by ELF ABI;")
            print("the resulting pointers cannot be validated statically.")
        print("Static checks ONLY: on-console execution has NOT been verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
