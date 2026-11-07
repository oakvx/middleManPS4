"""Offline timeline reconstruction from existing sanitized netdiag summaries.

Does not contact PSN, read payloads, inspect credentials or capture packets.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..psn_netdiag import DiagnosticError, capture_visibility, load_summary, comparison

VALID_KINDS = frozenset({"dns", "tcp_syn", "tls_clienthello", "tcp_rst", "tls_alert"})


def build_map(report: dict) -> dict:
    if report.get("format") != "fwSpoofer-netmeta-v1":
        raise DiagnosticError("Network map requires netmeta-v1 (not tunnel JSONL)")
    visibility = capture_visibility(report)
    per_window: dict[int, Counter] = {}
    destinations: Counter[str] = Counter()
    events = report.get("events")
    if not isinstance(events, list):
        raise DiagnosticError("Invalid or missing events array")
    for event in events[:5000]:
        if not isinstance(event, dict) or event.get("kind") not in VALID_KINDS:
            continue
        t = event.get("t")
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not 0 <= t <= 1e9:
            continue
        kind = event["kind"]
        interval = int(t // 5) * 5
        per_window.setdefault(interval, Counter())[kind] += 1
        dst = event.get("dst")
        if isinstance(dst, str) and len(dst) <= 45 and dst:
            destinations[dst] += 1
    return {
        "format": "fwSpoofer-networkmap-v1", "ps4_ip": report.get("ps4_ip"),
        "capture_visibility": visibility,
        "timeline": [{"start_s": start, "end_s": start + 5, "events": dict(per_window[start])}
                     for start in sorted(per_window)[:1000]],
        "destinations": [{"ip": k, "events": n} for k, n in destinations.most_common(50)],
        "dns_names": report.get("dns_names", [])[:250],
        "tls_sni": report.get("tls_sni", [])[:250],
        "bounded_events": min(len(events), 5000),
        "note": "Temporal association cannot establish PSN authentication outcome or firmware validation.",
    }


def diff_maps(baseline: dict, attempt: dict) -> dict:
    delta = comparison(baseline, attempt)
    return {"format": "fwSpoofer-networkmap-diff-v1", "difference": delta,
            "baseline": build_map(baseline), "attempt": build_map(attempt)}


def inspect_path(path: Path) -> dict:
    return build_map(load_summary(path))
