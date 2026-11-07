"""Offline Ghidra headless command builder and bounded inventory comparator.

Requires an independently installed Ghidra distribution for actual decompilation.
Never invokes a shell and does not acquire any binaries from the network.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from .binary import read_bounded

MAX_INVENTORY_BYTES = 8 * 1024 * 1024
MAX_FUNCTIONS = 10000
PROJECT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
SCHEMA = "middleManPS4-ghidra-v1"


class GhidraBridgeError(ValueError):
    """User-visible validation failure, not a Ghidra runtime failure."""


def analyzer_executable(ghidra_home: Path, *, windows: bool | None = None) -> Path:
    if windows is None:
        windows = os.name == "nt"
    executable = ghidra_home.resolve() / "support" / ("analyzeHeadless.bat" if windows else "analyzeHeadless")
    if not executable.is_file():
        raise GhidraBridgeError(f"Ghidra analyzeHeadless was not found in: {ghidra_home}")
    return executable


def make_plan(*, ghidra_home: Path, binary: Path, output: Path,
              project_dir: Path, project_name: str = "middleManPS4_RE",
              script_dir: Path | None = None, windows: bool | None = None) -> dict:
    """Create a safe subprocess argv vector; do not launch anything."""
    if not PROJECT_NAME.fullmatch(project_name):
        raise GhidraBridgeError("Invalid Ghidra project name")
    binary = binary.resolve()
    output = output.resolve()
    project_dir = project_dir.resolve()
    if not binary.is_file():
        raise GhidraBridgeError(f"Input ELF does not exist: {binary}")
    # Fingerprint and format check before Ghidra is launched.
    from .binary import inspect_bytes
    data = read_bounded(binary)
    inspected = inspect_bytes(data)
    if inspected["format"] == "PS4 SELF container":
        raise GhidraBridgeError("Encrypted/packed SELF is not an unpacked ELF")
    if not output.parent.is_dir() or output.exists():
        raise GhidraBridgeError("JSON output directory must exist and output file must not")
    if not project_dir.is_dir():
        raise GhidraBridgeError("Ghidra project directory must already exist")
    if script_dir is None:
        script_dir = Path(__file__).resolve().parents[3] / "scripts" / "ghidra"
    script_dir = script_dir.resolve()
    if not (script_dir / "ExportREInventory.java").is_file():
        raise GhidraBridgeError("ExportREInventory.java was not found")
    launcher = analyzer_executable(ghidra_home, windows=windows)
    if windows is None:
        windows = os.name == "nt"
    if windows:
        # Windows launches .bat files through cmd.exe even with shell=False.
        # Fail closed on cmd metacharacters in user-supplied filesystem paths.
        for value in (str(launcher), str(binary), str(output), str(project_dir), str(script_dir)):
            if any(char in value for char in "&|<>^%!\r\n\""):
                raise GhidraBridgeError("Windows paths may not contain shell metacharacters")
    argv = [str(launcher), str(project_dir), project_name,
            "-import", str(binary), "-scriptPath", str(script_dir),
            "-postScript", "ExportREInventory.java", str(output),
            "-analysisTimeoutPerFile", "300"]
    return {"format": "middleManPS4-ghidra-plan-v1", "input": str(binary),
            "input_sha256": sha256(data).hexdigest(), "input_elf_type": inspected["elf_type"],
            "output": str(output), "argv": argv, "executes": False,
            "note": "Dry-run; Ghidra must be installed separately. No firmware or PSN modification."}


def run_plan(plan: dict, *, timeout: int = 600) -> dict:
    """Explicit execution only; no shell, no rewrite or login, no hidden side effects."""
    if plan.get("format") != "middleManPS4-ghidra-plan-v1":
        raise GhidraBridgeError("Expected a validated Ghidra execution plan")
    try:
        # Stream external tool output into temporary files, rather than holding
        # arbitrarily large logs in memory.
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            result = subprocess.run(plan["argv"], stdout=stdout_file, stderr=stderr_file,
                                    check=False, timeout=timeout)
            stdout_file.seek(max(0, stdout_file.tell() - 1500))
            stderr_file.seek(max(0, stderr_file.tell() - 1500))
            out_tail = stdout_file.read().decode("utf-8", errors="replace")
            err_tail = stderr_file.read().decode("utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GhidraBridgeError(f"Ghidra failed to launch or timed out: {exc}") from exc
    output = Path(plan["output"])
    valid_inventory = False
    report_error = None
    if output.is_file():
        try:
            load_inventory(output)
            valid_inventory = True
        except (OSError, ValueError, UnicodeError) as exc:
            report_error = str(exc)[:300]
    elif result.returncode == 0:
        report_error = "Ghidra returned 0 but produced no inventory JSON"
    return {"return_code": result.returncode, "output_exists": output.is_file(),
            "valid_inventory": valid_inventory, "success": result.returncode == 0 and valid_inventory,
            "inventory_error": report_error,
            "output": str(output), "stdout_tail": out_tail, "stderr_tail": err_tail}


def load_inventory(path: Path) -> dict:
    with path.open("rb") as handle:
        content = handle.read(MAX_INVENTORY_BYTES + 1)
    if len(content) > MAX_INVENTORY_BYTES:
        raise GhidraBridgeError("Ghidra JSON inventory exceeds 8 MiB")
    try:
        inventory = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GhidraBridgeError("Invalid Ghidra inventory JSON") from exc
    if not isinstance(inventory, dict) or inventory.get("format") != SCHEMA:
        raise GhidraBridgeError("Unknown Ghidra inventory schema")
    for category in ("local_functions", "external_functions"):
        funcs = inventory.get(category)
        if not isinstance(funcs, list) or len(funcs) > MAX_FUNCTIONS:
            raise GhidraBridgeError(f"Invalid or oversized {category}")
        for item in funcs:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(key), str) and len(item[key]) <= 512
                for key in ("name", "namespace", "entry")
            ):
                raise GhidraBridgeError("Invalid function record")
    return inventory


def _names(inventory: dict, category: str) -> set[str]:
    return {f"{x['namespace']}::{x['name']}" for x in inventory[category]}


def summarize_inventory(inventory: dict) -> dict:
    return {"format": "middleManPS4-ghidra-summary-v1",
            "program": inventory.get("program", ""), "language": inventory.get("language", ""),
            "local_functions": len(inventory["local_functions"]),
            "external_functions": len(inventory["external_functions"]),
            "local_truncated": inventory.get("local_truncated", False),
            "external_truncated": inventory.get("external_truncated", False),
            "external_names": sorted(_names(inventory, "external_functions"))[:500],
            "external_names_truncated": len(_names(inventory, "external_functions")) > 500}


def diff_inventory(before: dict, after: dict) -> dict:
    result = {"format": "middleManPS4-ghidra-diff-v1"}
    for category in ("local_functions", "external_functions"):
        old, new = _names(before, category), _names(after, category)
        result[category] = {"added": sorted(new - old)[:500],
                            "removed": sorted(old - new)[:500],
                            "added_total": len(new - old), "removed_total": len(old - new),
                            "truncated": len(new - old) > 500 or len(old - new) > 500}
    return result
