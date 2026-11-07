"""Bounded, read-only PARAM.SFO/PSF metadata parser for offline analysis.

References: psdevwiki PARAM.SFO and shadPS4 PSFHeader/PSFRawEntry.
Does not parse PSAR save containers (which embed an inner PSF).
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import struct

MAGIC = b"\x00PSF"
HEADER = struct.Struct("<4sIIII")
ENTRY = struct.Struct("<HHIII")
MAX_PSF_SIZE = 16 * 1024 * 1024
MAX_ENTRIES = 1024
FORMATS = {0x0004: "binary", 0x0204: "text", 0x0404: "integer"}


class PSFFormatError(ValueError):
    """An input is not a structurally valid raw PSF file."""


def _span(data: bytes, offset: int, count: int) -> bytes:
    if offset > len(data) or count > len(data) - offset:
        raise PSFFormatError("PSF table or entry points outside file")
    return data[offset:offset + count]


def parse_psf(data: bytes) -> dict:
    if len(data) > MAX_PSF_SIZE:
        raise PSFFormatError("PSF exceeds 16 MiB limit")
    if len(data) < HEADER.size:
        raise PSFFormatError("PSF header truncated")
    magic, version, key_table, data_table, count = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise PSFFormatError("Not a raw PSF (expected 00 50 53 46)")
    if version not in (0x0100, 0x0101):
        raise PSFFormatError(f"Unsupported PSF version: {version:#x}")
    if count > MAX_ENTRIES:
        raise PSFFormatError("PSF entry limit exceeded")
    entries_end = HEADER.size + count * ENTRY.size
    if not entries_end <= key_table <= data_table <= len(data):
        raise PSFFormatError("Invalid PSF table boundaries")
    decoded = {}
    formats = {}
    for idx in range(count):
        keyoff, kind, size, maxlen, dataoff = ENTRY.unpack_from(data, HEADER.size + idx * ENTRY.size)
        if kind not in FORMATS or size > maxlen:
            raise PSFFormatError(f"Invalid format or length in PSF entry {idx}")
        key_start = key_table + keyoff
        if key_start >= data_table:
            raise PSFFormatError("PSF key offset out of bounds")
        key_end = data.find(b"\x00", key_start, data_table)
        if key_end < 0 or key_end == key_start or key_end - key_start > 128:
            raise PSFFormatError("PSF key missing NUL or too long")
        try:
            key = data[key_start:key_end].decode("ascii", errors="strict")
        except UnicodeError as exc:
            raise PSFFormatError("PSF key is not ASCII") from exc
        if key in decoded or any(not (c.isalnum() or c in "_.-") for c in key):
            raise PSFFormatError("Invalid or duplicate PSF key")
        start = data_table + dataoff
        if start < data_table:
            raise PSFFormatError("PSF negative data offset")
        item = _span(data, start, size)
        _span(data, start, maxlen)
        if kind == 0x0404:
            if len(item) != 4:
                raise PSFFormatError("Integer entry must be four bytes")
            value: object = struct.unpack("<i", item)[0]
        elif kind == 0x0204:
            try:
                value = item.rstrip(b"\x00").decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise PSFFormatError("PSF text is invalid UTF-8") from exc
        else:
            value = {"bytes": len(item), "sha256": sha256(item).hexdigest(),
                     "preview_hex": item[:16].hex(), "preview_truncated": len(item) > 16}
        decoded[key] = value
        formats[key] = FORMATS[kind]
    return {"format": "PSF", "version": f"{version >> 8}.{version & 0xff}",
            "entry_count": count, "values": decoded, "value_types": formats,
            "sha256": sha256(data).hexdigest(), "bytes": len(data)}


def inspect_path(path: Path) -> dict:
    with path.open("rb") as stream:
        data = stream.read(MAX_PSF_SIZE + 1)
    return parse_psf(data)
