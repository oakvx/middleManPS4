"""Integrated, reproducible, offline reverse-engineering case reports.

Read-only input inspection. All claims include their source and evidence level.
No network activity, PSN protocol modification, or Ghidra execution occurs.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from . import binary, dynlib, nids, orbis, psf, symbols
from .ghidra_bridge import load_inventory, summarize_inventory
from .netmap import build_map
from ..psn_netdiag import load_summary

SCHEMA = "middleManPS4-analysis-v1"
MAX_CASE_BYTES = 12 * 1024 * 1024
MAX_GHIDRA_NAMES = 100


class ReportError(ValueError):
    """Invalid report or analysis request."""


def _unique_names(entries: list[dict], key: str) -> list[str]:
    return sorted({e[key] for e in entries if isinstance(e.get(key), str)})


def analyze_bytes(data: bytes, *, ghidra: dict | None = None,
                  network: dict | None = None, path_name: str = "<memory>") -> dict:
    fingerprint = sha256(data).hexdigest()
    if data.startswith(psf.MAGIC):
        kind = "PSF"
        parsed_binary = None
        parsed_psf = psf.parse_psf(data)
        dynamic = scoped = names = candidates = None
    else:
        parsed_binary = binary.inspect_bytes(data)
        parsed_psf = None
        kind = parsed_binary["format"]
        if kind in ("ELF64", "Orbis ELF64"):
            dynamic = orbis.inspect_bytes(data)
            scoped = dynlib.inspect_bytes(data)
            names = symbols.scan_bytes(data)
            candidates = nids.inventory_bytes(data)
        else:
            dynamic = scoped = names = candidates = None
    evidence = [
        {"claim": "File fingerprint", "level": "verified-local-bytes",
         "source": "SHA-256 of bounded input file", "value": fingerprint},
        {"claim": "Binary format", "level": "validated-header",
         "source": "ELF64/SELF/PSF binary header parser", "value": kind},
    ]
    notes = []
    related = {"ghidra": None, "network": None}
    if scoped is not None:
        evidence.append({"claim": "Orbis dynlib string-table layout",
                         "level": "structurally-validated" if scoped["table_validated"] else "not-available",
                         "source": "PT_SCE_DYNLIBDATA + DT_SCE_STRTAB/STRSZ",
                         "value": scoped["string_table"]})
        evidence.append({"claim": "Candidate NIDs inside dynlib string table",
                         "level": "syntax-only",
                         "source": "Validated table range; pattern match, not symbol resolution",
                         "value": scoped["scoped_nids_found"]})
    if ghidra is not None:
        if kind not in ("ELF64", "Orbis ELF64"):
            raise ReportError("Ghidra inventory can only be joined to an ELF")
        program = ghidra.get("program", "")
        if not isinstance(program, str) or len(program) > 512:
            raise ReportError("Invalid Ghidra program metadata")
        ghidra_symbols = _unique_names(ghidra["external_functions"], "name")
        scan_names = set(_unique_names(names["symbols"], "name"))
        overlap = sorted(set(ghidra_symbols) & scan_names)
        related["ghidra"] = {
            "summary": summarize_inventory(ghidra),
            "external_names_also_in_raw_binary": overlap[:MAX_GHIDRA_NAMES],
            "external_name_matches_total": len(overlap),
            "external_name_matches_truncated": len(overlap) > MAX_GHIDRA_NAMES,
            "source_program_matches_filename": program == Path(path_name).name,
            "provenance": "Unverified: supplied inventory has no cryptographic binding to ELF",
        }
        evidence.append({"claim": "Ghidra import/function inventory joined",
                         "level": "unverified-provenance",
                         "source": "User-supplied Ghidra JSON; names correlated heuristically",
                         "value": len(ghidra_symbols)})
        if program != Path(path_name).name:
            notes.append("Ghidra program name differs from input filename; verify manually")
    if network is not None:
        # The network source has no proven correspondence to this ELF.
        netmap = build_map(network)
        related["network"] = {
            "capture_visibility": netmap["capture_visibility"],
            "event_count": netmap["bounded_events"],
            "timeline": netmap["timeline"],
            "destination_count": len(netmap["destinations"]),
            "attribution": "Not associated with this binary or with PSN authentication outcome",
        }
        evidence.append({"claim": "Network timeline attached",
                         "level": "not-attributed",
                         "source": "Supplied sanitized netmeta-v1 summary", "value": netmap["bounded_events"]})
    return {
        "format": SCHEMA, "source": {"file_name": Path(path_name).name,
                                     "sha256": fingerprint, "bytes": len(data)},
        "type": kind, "binary": parsed_binary, "psf": parsed_psf,
        "orbis": dynamic, "dynlib": scoped, "symbols": names, "nid_scan": candidates,
        "related": related, "evidence": evidence, "notes": notes,
        "limits": ["Offline and read-only", "Raw symbol strings are heuristic",
                   "NID candidates cannot recover symbol names",
                   "Ghidra inventory is not cryptographically bound to input",
                   "Network observations cannot prove PSN login or firmware eligibility"],
    }


def analyze_path(path: Path, *, ghidra_inventory: Path | None = None,
                 network_summary: Path | None = None) -> dict:
    data = binary.read_bounded(path)
    ghidra = load_inventory(ghidra_inventory) if ghidra_inventory is not None else None
    network = load_summary(network_summary) if network_summary is not None else None
    return analyze_bytes(data, ghidra=ghidra, network=network, path_name=path.name)


def save_report_exclusive(report: dict, output: Path) -> None:
    """Never replace an existing report; minimize risk of partial file writes."""
    if not output.parent.is_dir():
        raise ReportError("Report output parent directory does not exist")
    content = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if len(content.encode("utf-8")) > MAX_CASE_BYTES:
        raise ReportError("Report output exceeds size limit")
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def load_report(path: Path) -> dict:
    with path.open("rb") as f:
        content = f.read(MAX_CASE_BYTES + 1)
    if len(content) > MAX_CASE_BYTES:
        raise ReportError("Input report too large")
    try:
        report = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReportError("Invalid JSON report") from exc
    if not isinstance(report, dict) or report.get("format") != SCHEMA:
        raise ReportError("Unsupported analysis report format")
    src = report.get("source")
    if not isinstance(src, dict) or not isinstance(src.get("sha256"), str) or len(src["sha256"]) != 64:
        raise ReportError("Invalid analysis source")
    if not isinstance(report.get("type"), str) or not isinstance(report.get("evidence"), list):
        raise ReportError("Incomplete analysis report")
    return report


def compare_reports(before: dict, after: dict) -> dict:
    """Structural differences; never infer behavioral changes from static strings."""
    if before.get("format") != SCHEMA or after.get("format") != SCHEMA:
        raise ReportError("Analysis reports must use compatible schema")
    def sets_of(report: dict, category: str) -> set[str]:
        if category == "libraries":
            orbis_report = report.get("orbis") or {}
            scoped = report.get("dynlib") or {}
            return set(orbis_report.get("standard_dt_needed", [])) | {
                e["name"] for e in scoped.get("named_records", [])
                if e.get("tag") in ("DT_SCE_IMPORT_LIB", "DT_SCE_NEEDED_MODULE")
            }
        if category == "nid_candidates":
            return {e["nid"] for e in (report.get("dynlib") or {}).get("scoped_nids", [])}
        if category == "symbols":
            return {e["name"] for e in (report.get("symbols") or {}).get("symbols", [])}
        raise ReportError("Invalid compare category")
    changes = {}
    for category in ("libraries", "nid_candidates", "symbols"):
        removed = sets_of(before, category) - sets_of(after, category)
        added = sets_of(after, category) - sets_of(before, category)
        changes[category] = {"added": sorted(added)[:200], "removed": sorted(removed)[:200],
                             "added_total": len(added), "removed_total": len(removed),
                             "truncated": len(added) > 200 or len(removed) > 200}
    return {"format": "middleManPS4-analysis-diff-v1",
            "sha256_before": before["source"]["sha256"],
            "sha256_after": after["source"]["sha256"],
            "identical_file": before["source"]["sha256"] == after["source"]["sha256"],
            "changes": changes,
            "note": "Static metadata differences only; not proof of runtime behavior or PSN compatibility."}


def batch_directory(directory: Path, *, pattern: str = "*.elf", limit: int = 32) -> dict:
    """Scan at most 32 regular files, flat directory only, no symlink traversal."""
    import re
    if not directory.is_dir() or directory.is_symlink():
        raise ReportError("Batch input must be an existing non-symlink directory")
    if not re.fullmatch(r"[A-Za-z0-9_*?.-]{1,64}", pattern, flags=re.ASCII):
        raise ReportError("Batch pattern must be a simple filename glob")
    if not 1 <= limit <= 32:
        raise ReportError("Batch limit must be between 1 and 32")
    files = sorted(p for p in directory.glob(pattern) if p.is_file() and not p.is_symlink())
    if len(files) > limit:
        raise ReportError(f"Batch has {len(files)} files; the limit is {limit}")
    rows = []
    for file in files:
        try:
            result = analyze_path(file)
            dynamic = result.get("orbis") or {}
            scoped = result.get("dynlib") or {}
            scanned = result.get("symbols") or {}
            rows.append({"name": file.name, "status": "ok", "type": result["type"],
                         "sha256": result["source"]["sha256"],
                         "bytes": result["source"]["bytes"],
                         "standard_dt_needed": dynamic.get("standard_dt_needed", []),
                         "scoped_nids_found": scoped.get("scoped_nids_found", 0),
                         "string_table_validated": scoped.get("table_validated", False),
                         "raw_symbol_matches": scanned.get("total_matches", {}).get("symbol", 0)})
        except (OSError, ValueError, UnicodeError) as exc:
            # A malformed file does not prevent the other files being analyzed.
            rows.append({"name": file.name, "status": "error", "error": str(exc)[:300]})
    return {"format": "middleManPS4-analysis-batch-v1", "files_considered": len(rows),
            "ok": sum(r["status"] == "ok" for r in rows),
            "failed": sum(r["status"] == "error" for r in rows),
            "rows": rows, "note": "Local filenames and static metadata only; no PSN or runtime inference."}


def render_markdown(case: dict) -> str:
    """Human-reviewable digest with explicit evidence limitations."""
    if case.get("format") != SCHEMA:
        raise ReportError("Expected an integrated analysis report")
    source = case["source"]
    filename = str(source.get("file_name", "unknown")).replace("`", "'").replace("\n", " ")
    orbis_report = case.get("orbis") or {}
    dyn = case.get("dynlib") or {}
    sym = case.get("symbols") or {}
    related = case.get("related") or {}
    libraries = sorted(set(orbis_report.get("standard_dt_needed", [])) |
                       {e["name"] for e in dyn.get("named_records", [])
                        if e.get("tag") in ("DT_SCE_IMPORT_LIB", "DT_SCE_NEEDED_MODULE")})
    lines = ["# middleManPS4 — Offline RE Case", "",
             f"- **Input:** `{filename}`", f"- **SHA-256:** `{source['sha256']}`",
             f"- **Format:** {case['type']}",
             f"- **Bytes:** {source['bytes']}", "",
             "## Static evidence", "",
             f"- Validated Orbis string table: **{'yes' if dyn.get('table_validated') else 'no'}**",
             f"- Syntax-valid NID candidates within that table: **{dyn.get('scoped_nids_found', 0)}**",
             f"- Raw symbol string matches: **{sym.get('total_matches', {}).get('symbol', 0)}**",
             "", "## Library references (not proven runtime loads)", ""]
    lines.extend(f"- `{name}`" for name in libraries[:40])
    if len(libraries) > 40:
        lines.append(f"- ... and {len(libraries) - 40} more")
    if not libraries:
        lines.append("No safely resolved library references.")
    gh = related.get("ghidra")
    net = related.get("network")
    lines += ["", "## Correlated sources", "",
              f"- Ghidra inventory: **{'supplied (provenance unverified)' if gh else 'not supplied'}**",
              f"- Network metadata: **{'supplied (not attributed to this ELF)' if net else 'not supplied'}**"]
    if gh:
        lines.append(f"- Ghidra/raw-string overlapping external names: **{gh['external_name_matches_total']}**")
    if net:
        lines.append(f"- Capture visibility: **{net['capture_visibility']['status']}**")
    lines += ["", "## Limits", "",
              "This report is read-only static research. Strings/NIDs do not prove imports; "
              "Ghidra is not cryptographically tied to the binary; network metadata does "
              "not establish PSN sign-in, firmware validation, or bypass feasibility.", ""]
    return "\n".join(lines)


def save_markdown_exclusive(content: str, output: Path) -> None:
    if not output.parent.is_dir():
        raise ReportError("Markdown output parent directory does not exist")
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
