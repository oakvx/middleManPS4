"""Offline PS4 research workbench: observable evidence, not PSN authentication.

All inputs are local. No active console access, TLS plaintext handling,
credential collection, firmware modification or Sony service communication.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import math
from pathlib import Path
import re
import sys
from urllib import request

from .gate_trace import build_report, parse_observer
from .psn_netdiag import load_summary
from .rekit import report as re_report

SCHEMA = "middleManPS4-workbench-v1"
MAX_REPORT = 4 * 1024 * 1024
MAX_OBSERVER = 256 * 1024
KINDS = frozenset(("dns", "tcp_syn", "tls_clienthello", "tcp_rst", "tls_alert"))
MODEL_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


class WorkbenchError(ValueError):
    """Untrusted or incompatible case input."""


def _read_bytes(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise WorkbenchError("Input exceeds documented size limit")
    return content


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _source(path: Path, kind: str, limit: int) -> dict:
    raw = _read_bytes(path, limit)
    return {"kind": kind, "sha256": sha256(raw).hexdigest(), "bytes": len(raw)}


def _seal(body: dict) -> dict:
    if "integrity" in body:
        raise WorkbenchError("Already sealed")
    result = dict(body)
    result["integrity"] = {
        "algorithm": "SHA-256", "payload_sha256": sha256(_canonical(body)).hexdigest(),
        "note": "Detects accidental changes; not a signature or proof of provenance.",
    }
    return result


def verify_case(value: dict) -> bool:
    if not isinstance(value, dict) or value.get("format") != SCHEMA:
        return False
    record = value.get("integrity")
    if not isinstance(record, dict) or record.get("algorithm") != "SHA-256":
        return False
    expected = record.get("payload_sha256")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    return sha256(_canonical({k: v for k, v in value.items() if k != "integrity"})).hexdigest() == expected


def load_case(path: Path) -> dict:
    data = json.loads(_read_bytes(path, MAX_REPORT))
    if not verify_case(data):
        raise WorkbenchError("Invalid or modified workbench report")
    return data


def save_new(path: Path, payload: dict) -> None:
    data = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      indent=2, allow_nan=False) + "\n"
    if len(data.encode("utf-8")) > MAX_REPORT:
        raise WorkbenchError("Report exceeds 4 MiB")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(data)


def _metadata_events(network: dict) -> list[dict]:
    """Discard addresses, SNI, HTTP content and all other unknown fields."""
    events = network.get("events")
    if not isinstance(events, list) or len(events) > 5000:
        raise WorkbenchError("Expected at most 5000 sanitized metadata events")
    result = []
    for entry in events:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        if not isinstance(kind, str) or kind not in KINDS:
            continue
        time = entry.get("t")
        if type(time) not in (float, int) or not math.isfinite(time) or not 0 <= time <= 3600:
            continue
        result.append({"t": round(time, 3), "kind": entry["kind"]})
    return sorted(result, key=lambda e: (e["t"], e["kind"]))


def replay_metadata(events: list[dict], *, interval: int = 5) -> dict:
    """Deterministic offline bucket replay; never sends or reconstructs packets."""
    if not 1 <= interval <= 60 or len(events) > 5000:
        raise WorkbenchError("Invalid replay parameters")
    counts: dict[int, Counter[str]] = {}
    for event in events:
        if (not isinstance(event, dict) or not isinstance(event.get("kind"), str)
                or event["kind"] not in KINDS):
            raise WorkbenchError("Replay accepts only known metadata kinds")
        t = event.get("t")
        if type(t) not in (float, int) or not math.isfinite(t) or not 0 <= t <= 3600:
            raise WorkbenchError("Invalid replay timestamp")
        bucket = int(t // interval) * interval
        counts.setdefault(bucket, Counter())[event["kind"]] += 1
    return {"format": "middleManPS4-replay-v1", "interval_seconds": interval,
            "events_count": len(events),
            "frames": [{"start_second": k, "end_second": k + interval,
                        "counts": dict(sorted(counts[k].items()))} for k in sorted(counts)],
            "limit": "Metadata-only reconstruction. No network traffic is replayed."}


def recommendations(body: dict) -> list[dict]:
    """Explain observations with explicit evidence level and next experiment."""
    results = []
    obs = body.get("observer")
    net = body.get("network")
    if obs is None:
        results.append({"level": "unknown", "finding": "No console observer input",
                        "next": "Provide an authorized Observer stdout sample."})
    elif not obs["sequence_verified"]:
        results.append({"level": "incomplete", "finding": "Observer lifecycle not verified",
                        "next": "Verify the on-console start, ordered heartbeat and completion sequence."})
    else:
        results.append({"level": "observed", "finding": "Observer self-process trace is complete",
                        "next": "Correlate separately collected gateway metadata; system processes remain unobserved."})
    if net is None:
        results.append({"level": "unknown", "finding": "No network capture summary",
                        "next": "Place the PC on the packet path before interpreting a PSN prompt."})
    else:
        status = net["visibility"]["status"]
        if status != "public_destination_observed":
            results.append({"level": "inconclusive", "finding": "PS4-to-public-IP path not demonstrated",
                            "next": "Capture on the gateway/ICS interface and verify outbound packets."})
        else:
            results.append({"level": "observed", "finding": "Some PS4 outbound public packets observed",
                            "next": "Repeat baseline/attempt captures with an independently recorded UI marker."})
        if body.get("prompt_second_manual") is not None:
            results.append({"level": "manual", "finding": "Prompt timestamp supplied by operator",
                            "next": "Record independent timestamps; manual alignment cannot identify gate origin."})
    return results


def build_case(observer_path: Path | None, network_path: Path | None,
               *, prompt_second: float | None = None, interval: int = 5) -> dict:
    if observer_path is None and network_path is None:
        raise WorkbenchError("At least one local data source is required")
    if prompt_second is not None and (not math.isfinite(prompt_second) or
                                      not 0 <= prompt_second <= 3600 or network_path is None):
        raise WorkbenchError("Prompt offset requires network data and 0..3600 seconds")
    sources = []
    parsed = None
    if observer_path is not None:
        content = _read_bytes(observer_path, MAX_OBSERVER)
        parsed = parse_observer(content.decode("utf-8", errors="replace"))
        sources.append({"kind": "observer_stdout", "sha256": sha256(content).hexdigest(),
                        "bytes": len(content)})
    network = None
    trace = None
    replay = None
    if network_path is not None:
        network = load_summary(network_path)
        if network.get("format") != "fwSpoofer-netmeta-v1":
            raise WorkbenchError("Expected netmeta-v1 metadata; CONNECT logs not supported")
        events = _metadata_events(network)
        replay = replay_metadata(events, interval=interval)
        trace = build_report(parsed or {"status": "absent"}, network,
                             prompt_second=prompt_second)
        sources.append(_source(network_path, "netmeta_json", MAX_REPORT))
    body = {"format": SCHEMA, "kind": "case", "sources": sources,
            "observer": parsed,
            "network": None if trace is None else {
                "visibility": trace["network"]["capture_visibility"],
                "metadata_events": len(events),
                "event_kinds": dict(sorted(Counter(e["kind"] for e in events).items())),
                "before_prompt": trace["network"]["before_prompt"],
                "after_prompt": trace["network"]["after_prompt"],
            },
            "prompt_second_manual": prompt_second,
            "replay": replay,
            "capabilities": {
                "observer_self_process": "supported_offline_ingestion",
                "system_process_enumeration_on_ps4": "not_implemented",
                "network_metadata": "supported_if_on_path",
                "firmware_policy_origin": "unresolved",
                "tls_plaintext": "not_implemented",
                "psn_bypass": "not_implemented",
            },
            "limitations": [
                "Manual prompt and network timestamps are not independently synchronized.",
                "Observer sees its own process, not the console's PSN authentication code.",
                "Traffic metadata cannot establish where a firmware check executes.",
                "No credentials, tokens, SNI, destination IPs or raw log lines in this report.",
            ]}
    body["recommendations"] = recommendations(body)
    return _seal(body)


def compare_firmware(before: Path, after: Path) -> dict:
    """Compare user-provided unpacked binary metadata, not encrypted firmware."""
    old = re_report.analyze_path(before)
    new = re_report.analyze_path(after)
    delta = re_report.compare_reports(old, new)
    return _seal({
        "format": SCHEMA, "kind": "firmware_diff",
        "sources": [_source(before, "before_binary", 64 * 1024 * 1024),
                    _source(after, "after_binary", 64 * 1024 * 1024)],
        "before": {"format": old["type"], "sha256": old["source"]["sha256"]},
        "after": {"format": new["type"], "sha256": new["source"]["sha256"]},
        "changes": delta.get("changes", {}),
        "limitations": [
            "Binary metadata and NID-string candidates are not semantic firmware policies.",
            "No SELF decryption, patches, PSN account checks or runtime attribution.",
        ],
    })


def rule_explain(case: dict) -> dict:
    if not verify_case(case):
        raise WorkbenchError("Case integrity check failed")
    if case.get("kind") != "case":
        raise WorkbenchError("Rule assistant requires a case report")
    return {"format": "middleManPS4-assistant-v1", "mode": "deterministic_rules",
            "observations": case["recommendations"],
            "limitations": ["Not a language model, and not a PSN authentication oracle.",
                            "Suggestions are based exclusively on sanitized input fields."]}


def local_model_explain(case: dict, model: str) -> dict:
    """Optional explicit localhost-only Ollama; never sends source files or metadata addresses."""
    if not MODEL_RE.fullmatch(model):
        raise WorkbenchError("Invalid local model name")
    base = rule_explain(case)
    prompt = ("Explain these offline PS4 research observations without assuming a PSN "
              "login, firmware bypass or causality. Give next read-only experiments.\n" +
              json.dumps(base["observations"], ensure_ascii=False))
    request_data = json.dumps({"model": model, "prompt": prompt, "stream": False,
                               "options": {"temperature": 0}}).encode("utf-8")
    req = request.Request("http://127.0.0.1:11434/api/generate", data=request_data,
                          headers={"Content-Type": "application/json"}, method="POST")
    # Explicitly disable environment proxies and redirects: even an unexpected
    # localhost HTTP response must never cause a request to a remote address.
    class NoRedirect(request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=20) as response:
            raw = response.read(16385)
        if len(raw) > 16384:
            raise WorkbenchError("Local model response exceeded 16 KiB")
        data = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise WorkbenchError("Local model unavailable or returned invalid data") from exc
    answer = data.get("response")
    if not isinstance(answer, str) or len(answer) > 6000:
        raise WorkbenchError("Invalid local model response")
    return {**base, "mode": "optional_local_ollama", "model": model,
            "text": answer, "warning": "Unverified model-generated interpretation."}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="middleManPS4 offline research workbench")
    commands = p.add_subparsers(dest="cmd", required=True)
    case = commands.add_parser("case", help="Observer+network evidence and replay report")
    case.add_argument("--observer", type=Path)
    case.add_argument("--network", type=Path)
    case.add_argument("--prompt-second", type=float)
    case.add_argument("--interval", type=int, default=5)
    case.add_argument("--output", type=Path, required=True)
    diff = commands.add_parser("diff", help="Offline unpacked ELF/PSF metadata comparison")
    diff.add_argument("--before", required=True, type=Path)
    diff.add_argument("--after", required=True, type=Path)
    diff.add_argument("--output", required=True, type=Path)
    for name in ("verify", "explain", "dashboard"):
        sub = commands.add_parser(name)
        sub.add_argument("--report", required=True, type=Path)
        if name == "explain":
            sub.add_argument("--ollama-model", help="Explicit opt-in; contacts only localhost:11434")
        if name == "dashboard":
            sub.add_argument("--port", type=int, default=8765)
    args = p.parse_args(argv)
    try:
        if args.cmd == "case":
            output = build_case(args.observer, args.network,
                                prompt_second=args.prompt_second, interval=args.interval)
            save_new(args.output, output)
        elif args.cmd == "diff":
            save_new(args.output, compare_firmware(args.before, args.after))
        elif args.cmd == "verify":
            output = load_case(args.report)
            print(json.dumps({"verified": True, "kind": output["kind"],
                              "sources": len(output["sources"])}, sort_keys=True))
        elif args.cmd == "explain":
            output = load_case(args.report)
            analysis = (local_model_explain(output, args.ollama_model)
                        if args.ollama_model else rule_explain(output))
            print(json.dumps(analysis, indent=2, ensure_ascii=False))
        else:
            from .workbench_ui import serve
            serve(load_case(args.report), port=args.port)
        return 0
    except (OSError, ValueError, UnicodeError, KeyError) as exc:
        print(f"Workbench: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
