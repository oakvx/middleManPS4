"""Opt-in retrieval of the upstream *official* elfldr v0.7 flat BIN.

No network is used without --download. A pinned SHA-256 and byte length
make accidental release/redirect replacement detectable, not console-safe.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
from urllib.request import Request, urlopen

UPSTREAM = 'https://github.com/ps4-payload-dev/elfldr/releases/download/v0.7/elfldr.bin'
EXPECTED_SHA256 = '9525dc95393ab943758db69a1f49fea6e82f36f2821bf5f41bc00bfc4d6f75df'
EXPECTED_BYTES = 261012
ROOT = Path(__file__).resolve().parents[1]


def fetch_and_verify(destination: Path) -> tuple[str, int]:
    request = Request(UPSTREAM, headers={'User-Agent': 'fwSpoofer-verifier/0.4'})
    # urllib normally follows HTTPS redirects to GitHub's release assets.
    with urlopen(request, timeout=20) as response:
        data = response.read(EXPECTED_BYTES + 1)
    if len(data) != EXPECTED_BYTES:
        raise ValueError(f'Unexpected artifact length: {len(data)} vs {EXPECTED_BYTES}')
    if data.startswith(b'\x7fELF'):
        raise ValueError('Unexpected ELF header in official flat BIN')
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f'OFFICIAL RELEASE HASH MISMATCH: {digest}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Only stage when the entire file is verified. Atomic replace protects
    # against interrupted or partial downloads and does not change the PS4.
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.elfldr.', delete=False) as tmp:
        tmp.write(data)
        tmp_name = Path(tmp.name)
    try:
        os.replace(tmp_name, destination)
    finally:
        tmp_name.unlink(missing_ok=True)
    digest_path = destination.with_name(destination.name + '.sha256')
    digest_path.write_text(f'{digest}  {destination.name}\n', encoding='utf-8')
    return digest, len(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Fetch pinned elfldr.bin v0.7; offline unless --download')
    parser.add_argument('--download', action='store_true', help='Fetch official GitHub release asset')
    parser.add_argument('--destination', type=Path, default=ROOT / 'dist' / 'elfldr.bin')
    args = parser.parse_args(argv)
    print(f'Official release URL: {UPSTREAM}')
    print(f'Expected SHA-256: {EXPECTED_SHA256}')
    print(f'Expected size: {EXPECTED_BYTES} bytes')
    if not args.download:
        print('NO NETWORK: to retrieve the official release run with --download.')
        return 0
    try:
        digest, length = fetch_and_verify(args.destination)
    except (OSError, ValueError) as exc:
        print(f'RETRIEVAL FAILED: {exc}')
        return 1
    print(f'OFFICIAL BIN VERIFIED: {args.destination} ({length} bytes; sha256 {digest})')
    print('This verifies download provenance only, NOT PS4 bootstrapping compatibility.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
