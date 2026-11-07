"""One-command offline package checks. Never opens a connection to the PS4."""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def checkout_hash_matches(data: bytes, digest: str) -> bool:
    """Accept exact bytes or CRLF-only normalization of a text checkout.

    Git on Windows may rewrite LF to CRLF. All other changes still fail.
    Binary files are never line-ending normalized.
    """
    if hashlib.sha256(data).hexdigest() == digest:
        return True
    if b"\r\n" in data and b"\x00" not in data:
        normalized = data.replace(b"\r\n", b"\n")
        return hashlib.sha256(normalized).hexdigest() == digest
    return False


def check_manifest() -> bool:
    path = ROOT / 'SHA256SUMS.txt'
    if not path.exists():
        print('FAIL: SHA256SUMS.txt missing')
        return False
    count = 0
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        try:
            digest, filename = line.split('  ', 1)
        except ValueError:
            print(f'FAIL: malformed manifest line: {line!r}')
            return False
        resolved = (ROOT / filename).resolve()
        if not resolved.is_relative_to(ROOT.resolve()) or not resolved.is_file():
            print(f'FAIL: file missing/outside project: {filename}')
            return False
        if not checkout_hash_matches(resolved.read_bytes(), digest):
            print(f'FAIL: local file modified since archive creation: {filename}')
            return False
        count += 1
    print(f'PASS: archive file hashes ({count} files)')
    return count > 0


def main() -> int:
    print('=== fwSpoofer OFFLINE PRE-FLIGHT ===')
    print('This command never probes TCP ports or contacts the PS4.')
    if not check_manifest():
        return 1
    tasks = [
        [sys.executable, '-m', 'compileall', '-q', 'host', 'tests', 'scripts/fetch_official_elfldr.py', 'scripts/preflight_offline.py'],
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-q'],
    ]
    for args in tasks:
        print('RUN:', ' '.join(args), flush=True)
        r = subprocess.run(args, cwd=ROOT, check=False)
        if r.returncode:
            print(f'FAIL: exit code {r.returncode}')
            return r.returncode
    print('PASS: code tests and syntax.')

    bin_path = ROOT / 'dist' / 'elfldr.bin'
    hash_path = ROOT / 'dist' / 'elfldr.bin.sha256'
    if bin_path.exists():
        if not hash_path.exists():
            print('FAIL: dist/elfldr.bin exists but its SHA-256 sidecar is absent.')
            return 1
        expected = hash_path.read_text(encoding='utf-8').split()[0].lower()
        actual = hashlib.sha256(bin_path.read_bytes()).hexdigest()
        if expected != actual:
            print('FAIL: dist/elfldr.bin differs from its staged hash.')
            return 1
        from fetch_official_elfldr import EXPECTED_SHA256
        print('PASS: staged BIN hash matches its sidecar.')
        print('Official elfldr v0.7 asset:' if actual == EXPECTED_SHA256 else
              'Custom/local BIN (not byte-identical to official elfldr v0.7 release).')
    else:
        print('SKIP: no elfldr.bin staged (optional, fetch later).')
    print('NO PS4 EXECUTION VERIFIED. Firmware spoofing NOT implemented.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
