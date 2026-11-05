"""Protocol-aware TCP sender for payloads on an authorized local PS4.

Transmission is deliberately opt-in; successful sendall() does NOT confirm
remote loading or execution.
"""
from __future__ import annotations

import argparse
import ipaddress
import math
import re
import sys
from hashlib import sha256
from pathlib import Path

from .transport import read_payload, send_payload

LOADER_PORTS = {"elfldr": 9021, "goldhen": 9090}
# Hash of upstream elfldr v0.7 *flat* loader: provenance pin for GoldHEN bootstrap.
OFFICIAL_ELFLDR_V07_SHA256 = "9525dc95393ab943758db69a1f49fea6e82f36f2821bf5f41bc00bfc4d6f75df"
# Non-interchangeable services. 9020 may be a one-shot bootstrap receiver.
FORBIDDEN_ELFLDR_PORTS = frozenset((9020, 9026, 9090, 3232))


def valid_target(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() == "localhost"
    if address.is_unspecified or address.is_multicast or address.is_link_local:
        return False
    if any(address in ipaddress.ip_network(net) for net in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"
    )):
        return False
    return address.is_loopback or (address.is_private and not address.is_reserved)


def validate_profile(loader: str, port: int, suffix: str) -> None:
    """Fail closed on accidental cross-protocol traffic, even with --port."""
    if port == 9020:
        raise ValueError("port 9020 is a potentially ONE-SHOT bootstrap; not supported by this sender")
    if loader == "goldhen":
        if port != 9090:
            raise ValueError("GoldHEN profile only supports TCP 9090")
        if suffix != ".bin":
            raise ValueError("GoldHEN 9090 expects a flat .bin, not a .elf")
    elif loader == "elfldr":
        if port in FORBIDDEN_ELFLDR_PORTS:
            raise ValueError(f"port {port} belongs to another service, not elfldr")
        if suffix != ".elf":
            raise ValueError("elfldr profile expects a .elf payload")
    else:
        raise ValueError("unknown loader profile")


def validate_payload_format(data: bytes, suffix: str, *, check_elf: bool) -> None:
    if suffix == ".bin" and data.startswith(b"\x7fELF"):
        raise ValueError("file has an ELF header but .bin extension; do not rename ELF to BIN")
    if suffix == ".elf" and check_elf:
        from .elfcheck import inspect_elf
        inspect_elf(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="fwSpoofer - protocol-aware raw TCP payload sender")
    parser.add_argument("--host", required=True, help="Trusted private LAN IP/loopback only")
    parser.add_argument("--loader", choices=LOADER_PORTS, default="elfldr",
                        help="elfldr=9021 [default]; goldhen=9090 (experimental)")
    parser.add_argument("--port", type=int, default=None,
                        help="Optional custom elfldr port; requires --allow-custom-elfldr-port")
    parser.add_argument("--allow-custom-elfldr-port", action="store_true",
                        help="Explicitly authorize nondefault ELF TCP port (not known loader ports)")
    parser.add_argument("--file", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--send", action="store_true", help="Actually send (default: offline dry-run)")
    parser.add_argument("--accept-bootstrap-risk", action="store_true",
                        help="Required to transmit a flat BIN to GoldHEN's experimental 9090 loader")
    parser.add_argument("--allow-custom-bin", action="store_true",
                        help="Additionally authorize a BIN not matching official elfldr v0.7 SHA-256")
    parser.add_argument("--response-timeout", type=float, default=5.0,
                        help="Collect elfldr stdout/errors for up to N seconds after sending (default: 5)")
    parser.add_argument("--check-elf", action="store_true",
                        help="Validate ELF even on dry-run (always checked on send)")
    parser.add_argument("--expected-sha256", default=None,
                        help="Fail before network if payload SHA-256 differs (64 hex chars)")
    args = parser.parse_args(argv)
    port = args.port if args.port is not None else LOADER_PORTS[args.loader]
    suffix = args.file.suffix.lower()

    try:
        if not valid_target(args.host):
            raise ValueError("target must be a trusted private LAN or loopback IP")
        if not 1 <= port <= 65535 or not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("invalid port or timeout")
        if not math.isfinite(args.response_timeout) or not 0 <= args.response_timeout <= 120:
            raise ValueError("invalid --response-timeout (0..120 seconds)")
        if suffix not in {".elf", ".bin"}:
            raise ValueError("expected .elf or .bin file")
        validate_profile(args.loader, port, suffix)
        if args.loader == "elfldr" and port != LOADER_PORTS["elfldr"] and not args.allow_custom_elfldr_port:
            raise ValueError("nonstandard elfldr port: pass --allow-custom-elfldr-port explicitly")
        data = read_payload(args.file)
        # Dry run must also reject invalid ELF files; it is a real preflight.
        validate_payload_format(data, suffix, check_elf=True)
        digest = sha256(data).hexdigest()
        if args.expected_sha256 is not None:
            if not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_sha256):
                raise ValueError("--expected-sha256 must contain exactly 64 hex characters")
            if digest != args.expected_sha256.lower():
                raise ValueError("SHA-256 MISMATCH: file changed or wrong payload; nothing sent")
        if args.check_elf and suffix == ".elf":
            from .elfcheck import inspect_elf
            report = inspect_elf(data)
            print(f"ELF validated: {report['type']} entry={report['entry']}")
        # This protection must live in the Python sender itself, not only in
        # the PowerShell wrapper: users can invoke the CLI directly.
        if args.send and args.loader == "goldhen":
            if not args.accept_bootstrap_risk:
                raise ValueError("GoldHEN BIN send requires --accept-bootstrap-risk")
            if args.expected_sha256 is None:
                raise ValueError("GoldHEN BIN send requires --expected-sha256 (pin exact bytes)")
            if digest != OFFICIAL_ELFLDR_V07_SHA256 and not args.allow_custom_bin:
                raise ValueError("nonofficial BIN blocked; add --allow-custom-bin only after review")
        if not args.send:
            print(f"DRY RUN: {len(data)} bytes")
            print(f"SHA-256: {digest}")
            print(f"Loader: {args.loader}; target: {args.host}:{port}")
            print("No network connection opened.")
            return 0
        result = send_payload(
            args.host, args.file, port, args.timeout, payload_bytes=data,
            response_timeout=(args.response_timeout if args.loader == "elfldr" else 0.0),
        )
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"TCP transfer completed: {result.bytes_sent} bytes")
    print(f"SHA-256: {result.sha256}")
    if args.loader == "elfldr":
        if result.response:
            print("=== ELFLDR REMOTE OUTPUT / STDOUT / STDERR ===")
            print(result.response.decode("utf-8", errors="replace").replace("\x00", ""))
            print("=== END REMOTE OUTPUT ===")
        else:
            print("No remote output captured (not proof of failure or success).")
        if result.response_error:
            print(f"ERROR: remote response channel failed: {result.response_error}", file=sys.stderr)
        if result.response_truncated:
            print("WARNING: response truncated at 256 KiB", file=sys.stderr)
        elif args.response_timeout > 0 and not result.response_complete:
            print("Response capture reached its time limit; the process may still run.")
        if b"[elfldr.elf] Error" in result.response or b"[elfldr.elf] Unknown payload" in result.response:
            print("ERROR: elfldr reported an explicit load/spawn error.", file=sys.stderr)
            return 2
        if result.response_error:
            print("Remote execution NOT verified: output channel failed.", file=sys.stderr)
            return 3
    print("Remote execution NOT verified. A 'Payload received' toast is not proof of main().")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
