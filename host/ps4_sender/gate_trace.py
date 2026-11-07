"""Offline, metadata-only PS4 observer/PSN-prompt timeline correlation.

Does not connect to PSN, inspect authentication data or establish causality.
Only allowlisted fields from untrusted logs and sanitized netdiag JSON are kept.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import sys

from .psn_netdiag import DiagnosticError, load_summary

MAX_TRACE_BYTES = 256 * 1024
MAX_NETWORK_EVENTS = 5000
PREFIX = "[middleManPS4/observer] "
START = re.compile(r"event=start pid=([0-9]{1,10}) firmware=([0-9. ]{3,24}\(raw 0x[0-9a-fA-F]{8}\))$")
HEARTBEAT = re.compile(r"event=heartbeat sample=([0-9]{1,3})$")
COMPLETE = re.compile(r"event=complete samples=([0-9]{1,3})$")
ERROR = re.compile(r"event=error stage=(firmware|sleep)(?: sample=([0-9]{1,3}))? code=(-?[0-9]{1,10})$")
EVENT_KINDS = frozenset({"dns", "tcp_syn", "tls_clienthello", "tcp_rst", "tls_alert"})
EXPECTED_HEARTBEATS = 12


class GateTraceError(ValueError):
    """Malformed input or invalid experimental parameters."""


def parse_observer(text: str) -> dict:
    """Extract only bounded, known fields from elfldr stdout (never echo raw text)."""
    if len(text.encode("utf-8")) > MAX_TRACE_BYTES:
        raise GateTraceError("Observer log exceeds 256 KiB")
    start = None
    heartbeats: list[int] = []
    complete = None
    errors: list[dict] = []
    invalid = 0
    for line in text.splitlines():
        if not line.startswith(PREFIX):
            continue
        value = line[len(PREFIX):]
        if len(value) > 160:
            invalid += 1
            continue
        if match := START.fullmatch(value):
            if start is not None or heartbeats or complete is not None or errors:
                invalid += 1
                continue
            start = {"pid": int(match[1]), "firmware": match[2]}
        elif match := HEARTBEAT.fullmatch(value):
            if start is None or complete is not None or errors:
                invalid += 1
                continue
            if len(heartbeats) < EXPECTED_HEARTBEATS + 1:
                heartbeats.append(int(match[1]))
            else:
                invalid += 1
        elif match := COMPLETE.fullmatch(value):
            if complete is None:
                if start is None or len(heartbeats) != EXPECTED_HEARTBEATS or errors:
                    invalid += 1
                complete = int(match[1])
            else:
                invalid += 1
        elif match := ERROR.fullmatch(value):
            if len(errors) < 4:
                errors.append({"stage": match[1], "sample": int(match[2]) if match[2] else None,
                               "code": int(match[3])})
            else:
                invalid += 1
        else:
            invalid += 1
    if start is None and not heartbeats and complete is None and not errors:
        raise GateTraceError("No recognized Observer events found")
    expected = list(range(1, EXPECTED_HEARTBEATS + 1))
    intact = (start is not None and heartbeats == expected and
              complete == EXPECTED_HEARTBEATS and not errors and invalid == 0)
    state = "error" if errors else ("complete" if intact else "incomplete")
    return {"status": state, "start": start,
            "heartbeats": heartbeats, "completion_samples": complete,
            "error_events": errors, "unrecognized_observer_lines": invalid,
            "sequence_verified": intact,
            "note": "Self-process stdout only; it cannot observe PSN processes or authenticate a timeline."}


def _visibility(network: dict) -> dict:
    counts = network.get("counts", {})
    if not isinstance(counts, dict):
        raise GateTraceError("Invalid network counters")
    if "ipv4_packets" not in counts:
        return {"status": "not_measured", "ipv4_packets": None, "outbound_public_packets": None}
    total = counts["ipv4_packets"]
    outbound = counts.get("ps4_outbound_public_ipv4")
    if (type(total) is not int or type(outbound) is not int or
            total < 0 or outbound < 0 or outbound > total):
        raise GateTraceError("Invalid network visibility counters")
    status = ("public_destination_observed" if outbound else
              "only_nonpublic_or_inbound_observed" if total else
              "no_ipv4_packets_observed")
    return {"status": status, "ipv4_packets": total, "outbound_public_packets": outbound}


def _window_counts(events: list, lower: float, upper: float) -> dict:
    counts: Counter[str] = Counter()
    for entry in events:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        if not isinstance(kind, str) or kind not in EVENT_KINDS:
            continue
        timestamp = entry.get("t")
        if (isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or
                not math.isfinite(timestamp) or timestamp < 0):
            continue
        if lower <= timestamp < upper:
            counts[kind] += 1
    return dict(sorted(counts.items()))


def build_report(observer: dict, network: dict | None = None,
                 *, prompt_second: float | None = None, window_seconds: float = 5.0) -> dict:
    if (not math.isfinite(window_seconds) or not 1 <= window_seconds <= 30):
        raise GateTraceError("Window must be 1..30 seconds")
    if prompt_second is not None and (not math.isfinite(prompt_second) or not 0 <= prompt_second <= 3600):
        raise GateTraceError("Prompt time must be 0..3600 seconds")
    if prompt_second is not None and network is None:
        raise GateTraceError("Prompt offset requires a network summary")
    result = {"format": "middleManPS4-gate-trace-v1", "observer": observer,
              "network": None, "limitations": [
                  "Only the observer's own process is measured; PSN process activity is unknown.",
                  "A user-entered prompt time is not an independently synchronized timestamp.",
                  "No TLS plaintext, credentials or session tokens are recorded.",
                  "Network metadata cannot prove the cause of a firmware update prompt.",
              ]}
    if network is not None:
        if network.get("format") != "fwSpoofer-netmeta-v1":
            raise GateTraceError("Require a packet-metadata JSON summary, not CONNECT logs")
        events = network.get("events")
        if not isinstance(events, list) or len(events) > MAX_NETWORK_EVENTS:
            raise GateTraceError("Invalid or oversized network event list")
        info: dict = {"capture_visibility": _visibility(network),
                      "metadata_events": len(events), "prompt_second_manual": prompt_second,
                      "window_seconds": window_seconds, "before_prompt": None,
                      "after_prompt": None}
        if prompt_second is not None:
            info["before_prompt"] = _window_counts(events, max(0.0, prompt_second - window_seconds),
                                                    prompt_second)
            info["after_prompt"] = _window_counts(events, prompt_second,
                                                   prompt_second + window_seconds)
        result["network"] = info
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Offline, read-only Observer / network gate timeline")
    p.add_argument("--observer", required=True, type=Path, help="Saved elfldr stdout (kept private)")
    p.add_argument("--network", type=Path, help="Sanitized psn_netdiag summary JSON")
    p.add_argument("--prompt-second", type=float, help="Manual UI prompt offset since capture start")
    p.add_argument("--window-seconds", type=float, default=5.0)
    p.add_argument("--output", type=Path, help="New JSON report file; never overwrite")
    args = p.parse_args(argv)
    try:
        if args.observer.stat().st_size > MAX_TRACE_BYTES:
            raise GateTraceError("Observer log exceeds 256 KiB")
        trace = parse_observer(args.observer.read_text(encoding="utf-8", errors="replace"))
        network = load_summary(args.network) if args.network is not None else None
        report = build_report(trace, network, prompt_second=args.prompt_second,
                              window_seconds=args.window_seconds)
        payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(payload)
            print(f"Wrote sanitized report: {args.output}")
        else:
            print(payload, end="")
        return 0
    except (OSError, GateTraceError, DiagnosticError, UnicodeError) as exc:
        print(f"Gate trace error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
