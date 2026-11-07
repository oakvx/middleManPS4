"""Strict, bounded PS4 dynlib-string-table metadata extraction.

For *unpacked* Orbis ELFs only. Addresses in DT_SCE_STRTAB are treated as
file offsets relative to PT_SCE_DYNLIBDATA per the OpenOrbis specification.
No function-name recovery, SELF decryption, or binary modification is done.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
import struct

from .binary import BinaryFormatError, read_bounded
from .orbis import _phdrs, DYNAMIC_ENTRY
from . import nids

MAX_DYNLIB_STRTAB = 1024 * 1024
MAX_DYNLIB_RECORDS = 256
MAX_DYNAMIC_ENTRIES = 2048
MAX_NAME_LEN = 160
SAFE_NAME = re.compile(rb"[A-Za-z0-9_+./-]{1,160}\Z")
# SCE dynamic tags; packed values: low 32-bit string-table offset, high
# 32-bit metadata (version/index), which is *not* decoded heuristically.
DT_SCE_STRTAB = 0x61000035
DT_SCE_STRSZ = 0x61000037
PACKED_NAME_TAGS = {
    0x6100000D: "DT_SCE_MODULE_INFO",
    0x6100000F: "DT_SCE_NEEDED_MODULE",
    0x61000013: "DT_SCE_EXPORT_LIB",
    0x61000015: "DT_SCE_IMPORT_LIB",
}
SIMPLE_NAME_TAGS = {0x61000009: "DT_SCE_FILENAME"}


def _dynamic_entries(data: bytes, headers: list[dict]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for header in headers:
        if header["type"] != 2:
            continue
        if header["size"] % DYNAMIC_ENTRY.size:
            raise BinaryFormatError("PT_DYNAMIC has a partial 16-byte entry")
        count = header["size"] // DYNAMIC_ENTRY.size
        if count > MAX_DYNAMIC_ENTRIES or len(result) + count > MAX_DYNAMIC_ENTRIES:
            raise BinaryFormatError("PT_DYNAMIC exceeds aggregate entry limit")
        for index in range(count):
            tag, value = DYNAMIC_ENTRY.unpack_from(
                data, header["offset"] + index * DYNAMIC_ENTRY.size
            )
            if tag == 0:
                break
            result.append((tag, value))
    return result


def _exactly_one(entries: list[tuple[int, int]], tag: int) -> int | None:
    values = [value for t, value in entries if t == tag]
    if not values:
        return None
    if len(values) != 1:
        raise BinaryFormatError(f"Duplicate Orbis dynamic tag {tag:#x}")
    return values[0]


def _read_cstr(table: bytes, offset: int) -> str | None:
    if offset >= len(table):
        return None
    end = table.find(b"\0", offset, min(len(table), offset + MAX_NAME_LEN + 1))
    if end == -1 or not SAFE_NAME.fullmatch(table[offset:end]):
        return None
    return table[offset:end].decode("ascii")


def inspect_bytes(data: bytes) -> dict:
    headers = _phdrs(data)  # validated ELF header + all program-header bounds
    # Generic ELF / Orbis ELFs without an SCE string table are valid inputs.
    entries = _dynamic_entries(data, headers)
    segments = [h for h in headers if h["type"] == 0x61000000]
    str_offset = _exactly_one(entries, DT_SCE_STRTAB)
    str_size = _exactly_one(entries, DT_SCE_STRSZ)
    result = {
        "format": "middleManPS4-dynlib-v1", "file_sha256": sha256(data).hexdigest(),
        "string_table": None, "table_validated": False, "named_records": [],
        "invalid_named_records": 0, "named_records_truncated": False,
        "scoped_nids": [], "scoped_nids_found": 0, "scoped_nids_truncated": False,
        "note": "Names are bounded table records; NIDs are only syntactic candidates "
                "inside the validated string-table range, not proven imports.",
    }
    if not segments and str_offset is None and str_size is None:
        return result
    if len(segments) != 1 or str_offset is None or str_size is None:
        raise BinaryFormatError("Incomplete or ambiguous SCE dynlib string-table mapping")
    seg = segments[0]
    if not 0 < str_size <= MAX_DYNLIB_STRTAB:
        raise BinaryFormatError("Invalid Orbis string-table size")
    if str_offset > seg["size"] or str_size > seg["size"] - str_offset:
        raise BinaryFormatError("Orbis string table extends outside PT_SCE_DYNLIBDATA")
    file_offset = seg["offset"] + str_offset
    if file_offset > len(data) or str_size > len(data) - file_offset:
        raise BinaryFormatError("Orbis string table extends outside file")
    table = data[file_offset:file_offset + str_size]
    result["table_validated"] = True
    result["string_table"] = {"file_offset": hex(file_offset), "bytes": str_size,
                              "sha256": sha256(table).hexdigest()}
    total_named = 0
    for tag, value in entries:
        if tag not in PACKED_NAME_TAGS and tag not in SIMPLE_NAME_TAGS:
            continue
        name_offset = value & 0xffffffff if tag in PACKED_NAME_TAGS else value
        name = _read_cstr(table, name_offset)
        if name is None:
            result["invalid_named_records"] += 1
            continue
        total_named += 1
        if len(result["named_records"]) >= MAX_DYNLIB_RECORDS:
            continue
        entry = {"tag": PACKED_NAME_TAGS.get(tag, SIMPLE_NAME_TAGS.get(tag)),
                 "name": name, "string_table_offset": hex(name_offset)}
        if tag in PACKED_NAME_TAGS:
            entry["packed_high_32"] = hex(value >> 32)
        result["named_records"].append(entry)
    result["named_records_truncated"] = total_named > len(result["named_records"])
    scanned = nids.inventory_bytes(table)
    result["scoped_nids_found"] = scanned["records_found"]
    result["scoped_nids_truncated"] = scanned["truncated"]
    result["scoped_nids"] = [
        {**rec, "file_offset": hex(file_offset + int(rec["file_offset"], 16))}
        for rec in scanned["records"]
    ]
    return result


def inspect_path(path: Path) -> dict:
    return inspect_bytes(read_bounded(path))
