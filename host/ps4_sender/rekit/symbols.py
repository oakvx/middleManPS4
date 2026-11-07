"""Conservative scanner of recognizable Orbis library/symbol identifiers.

This deliberately extracts *only* matching names/NID-like identifiers;
it does not dump arbitrary strings, credentials or memory.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from pathlib import Path
import re

from .binary import read_bounded

# Conservative recognizers, not a claim that a candidate is a valid import.
SYMBOL_RE = re.compile(rb"(?<![A-Za-z0-9_])(?:sce[A-Z][A-Za-z0-9_]{3,95}|libSce[A-Za-z0-9_]{2,95}(?:\.sprx|\.prx)?|Sce[A-Z][A-Za-z0-9_]{2,95})(?![A-Za-z0-9_])")
NID_RE = re.compile(rb"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+\-]{11}#[A-Za-z0-9+\-]{1,4}#[A-Za-z0-9+\-]{1,4}(?![A-Za-z0-9+/_-])")
MAX_MATCHES = 400


def scan_bytes(data: bytes) -> dict:
    seen: dict[str, dict[str, int]] = defaultdict(dict)
    counts = {"symbol": 0, "nid_candidate": 0}
    for kind, matcher in (("symbol", SYMBOL_RE), ("nid_candidate", NID_RE)):
        for match in matcher.finditer(data):
            counts[kind] += 1
            name = match.group().decode("ascii")
            if len(seen[kind]) < MAX_MATCHES:
                seen[kind].setdefault(name, match.start())
    return {
        "format": "fwSpoofer-symbolscan-v1", "sha256": sha256(data).hexdigest(),
        "bytes": len(data), "total_matches": counts,
        "symbols": [{"name": k, "offset": hex(v)} for k, v in sorted(seen["symbol"].items())],
        "nid_candidates": [{"name": k, "offset": hex(v)} for k, v in sorted(seen["nid_candidate"].items())],
        "truncated": any(counts[k] > len(seen[k]) for k in counts),
        "note": "Heuristic strings only; they are not validated imports, exports or NIDs.",
    }


def scan_path(path: Path) -> dict:
    return scan_bytes(read_bounded(path))
