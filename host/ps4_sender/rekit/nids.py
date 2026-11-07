"""Validate and inventory Orbis NID-shaped string-table records.

NID validation is syntactic, not an assertion that a given hash resolves to
an API. The hash's original function name cannot be recovered from the record.
"""
from __future__ import annotations

import base64
from binascii import Error as BinasciiError
from hashlib import sha256
from pathlib import Path
import re

from .binary import read_bounded

ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
MAX_RECORDS = 1024
# A complete record is 11 hash characters, '#', library index, '#', module
# index, then NUL. The 16-byte layout comes from OpenOrbis OELF notes.
NID_RECORD = re.compile(rb"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+\-]{11})#([A-Za-z0-9+\-])#([A-Za-z0-9+\-])\x00")


def inventory_bytes(data: bytes) -> dict:
    records = []
    valid_count = 0
    for match in NID_RECORD.finditer(data):
        digest, lib, module = match.group(1, 2, 3)
        # Only alphabet-valid indices are meaningful. '#' delimiters do not
        # establish whether the record is actually in .sce_dynlib_data.
        if lib[0] not in ALPHABET or module[0] not in ALPHABET:
            continue
        try:
            raw_hash = base64.b64decode(digest.replace(b"-", b"/") + b"=", validate=True)
        except (ValueError, BinasciiError):
            continue
        if len(raw_hash) != 8:
            continue
        valid_count += 1
        if len(records) < MAX_RECORDS:
            records.append({"nid": digest.decode("ascii"), "file_offset": hex(match.start()),
                            "library_index": ALPHABET.index(lib[0]),
                            "module_index": ALPHABET.index(module[0])})
    return {"format": "middleManPS4-nid-inventory-v1", "sha256": sha256(data).hexdigest(),
            "records_found": valid_count, "records": records,
            "truncated": valid_count > len(records),
            "note": "Syntactic NID candidates only. Indexes and offsets require dynlib-table validation."}


def inspect_path(path: Path) -> dict:
    return inventory_bytes(read_bounded(path))
