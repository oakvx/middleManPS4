"""Offline reverse-engineering inspection and optional Ghidra integration."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import binary, dynlib, netmap, nids, orbis, psf, symbols, report
from .ghidra_bridge import (
    GhidraBridgeError, diff_inventory, load_inventory, make_plan, run_plan,
    summarize_inventory,
)
from ..psn_netdiag import DiagnosticError, load_summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="middleManPS4 offline RE toolkit")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("binary", "orbis", "dynlib", "psf", "symbols", "nids", "net", "ghidra-summary"):
        sub.add_parser(command, help=f"Offline {command} inspection").add_argument("file", type=Path)
    analyze = sub.add_parser("analyze", help="One-pass integrated offline report")
    analyze.add_argument("file", type=Path)
    analyze.add_argument("--ghidra-inventory", type=Path)
    analyze.add_argument("--network-summary", type=Path)
    analyze.add_argument("--output", type=Path, help="Create new JSON file (never overwrite)")
    markdown = sub.add_parser("markdown", help="Render an existing analysis JSON as Markdown")
    markdown.add_argument("file", type=Path)
    markdown.add_argument("--output", type=Path, help="Write a new Markdown file without overwrite")
    batch = sub.add_parser("batch", help="Bounded offline inventory of a directory")
    batch.add_argument("directory", type=Path)
    batch.add_argument("--glob", default="*.elf")
    batch.add_argument("--limit", type=int, default=32)
    batch.add_argument("--output", type=Path, help="Create new JSON index file")
    for command in ("net-diff", "ghidra-diff", "analyze-diff"):
        cmp = sub.add_parser(command, help=f"Offline {command} comparison")
        cmp.add_argument("baseline", type=Path)
        cmp.add_argument("attempt", type=Path)
    for command in ("ghidra-plan", "ghidra-run"):
        gh = sub.add_parser(command, help="Ghidra headless export (plan/run)")
        gh.add_argument("file", type=Path, help="Unpacked ELF to import")
        gh.add_argument("--ghidra-home", type=Path, required=True)
        gh.add_argument("--output", type=Path, required=True, help="New JSON report filename")
        gh.add_argument("--project-dir", type=Path, required=True, help="Existing directory")
        gh.add_argument("--project-name", default="middleManPS4_RE")
    args = parser.parse_args(argv)
    try:
        if args.command == "binary":
            result = binary.inspect_path(args.file)
        elif args.command == "orbis":
            result = orbis.inspect_path(args.file)
        elif args.command == "markdown":
            content = report.render_markdown(report.load_report(args.file))
            if args.output is not None:
                report.save_markdown_exclusive(content, args.output)
                result = {"format": "middleManPS4-markdown-saved-v1", "output": str(args.output)}
            else:
                print(content)
                return 0
        elif args.command == "dynlib":
            result = dynlib.inspect_path(args.file)
        elif args.command == "analyze":
            result = report.analyze_path(args.file, ghidra_inventory=args.ghidra_inventory,
                                         network_summary=args.network_summary)
            if args.output is not None:
                report.save_report_exclusive(result, args.output)
                result = {"format": "middleManPS4-analysis-saved-v1",
                          "output": str(args.output), "source": result["source"],
                          "type": result["type"], "evidence": result["evidence"]}
        elif args.command == "batch":
            result = report.batch_directory(args.directory, pattern=args.glob, limit=args.limit)
            if args.output is not None:
                report.save_report_exclusive(result, args.output)
                result = {"format": "middleManPS4-batch-saved-v1",
                          "output": str(args.output), "ok": result["ok"],
                          "failed": result["failed"]}
        elif args.command == "psf":
            result = psf.inspect_path(args.file)
        elif args.command == "symbols":
            result = symbols.scan_path(args.file)
        elif args.command == "nids":
            result = nids.inspect_path(args.file)
        elif args.command == "net":
            result = netmap.inspect_path(args.file)
        elif args.command == "net-diff":
            result = netmap.diff_maps(load_summary(args.baseline), load_summary(args.attempt))
        elif args.command == "analyze-diff":
            result = report.compare_reports(report.load_report(args.baseline),
                                            report.load_report(args.attempt))
        elif args.command == "ghidra-summary":
            result = summarize_inventory(load_inventory(args.file))
        elif args.command == "ghidra-diff":
            result = diff_inventory(load_inventory(args.baseline), load_inventory(args.attempt))
        else:
            result = make_plan(ghidra_home=args.ghidra_home, binary=args.file,
                               output=args.output, project_dir=args.project_dir,
                               project_name=args.project_name)
            if args.command == "ghidra-run":
                result = run_plan(result)
    except (OSError, ValueError, DiagnosticError, UnicodeError, GhidraBridgeError, report.ReportError) as exc:
        print(f"RE toolkit error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.command == "ghidra-run" and not result["success"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
