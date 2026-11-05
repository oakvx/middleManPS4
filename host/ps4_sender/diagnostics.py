"""Conservative TCP listener checks for a PS4 on the local network.

Only elfldr 9021 and GoldHEN Klog 3232 are permitted. A connect-only
probe can still disturb a listener, so do NOT probe bootstrap/binloaders.
"""
from __future__ import annotations
import argparse
import math
import socket
import sys
from .cli import valid_target

PORT_LABELS = {9021: "elfldr ELF server", 3232: "GoldHEN Klog"}
SAFE_PROBE_PORTS = frozenset(PORT_LABELS)


def probe(host: str, port: int, timeout: float = 1.5) -> bool:
    if port not in SAFE_PROBE_PORTS:
        raise ValueError("Never probe bootstrap/binloader ports; only 9021 and 3232 are allowed")
    if not valid_target(host):
        raise ValueError("only trusted local/private targets are allowed")
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Check TCP services 9021 / 3232 only (NO binloader probes)")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, action="append", help="Repeatable; default 9021 only. Klog optional: 3232")
    p.add_argument("--timeout", type=float, default=1.5)
    p.add_argument("--require-open", action="store_true")
    a = p.parse_args(argv)
    if not valid_target(a.host) or not math.isfinite(a.timeout) or a.timeout <= 0:
        print("ERROR: trusted private/loopback target and positive timeout required", file=sys.stderr)
        return 2
    ports = a.port or [9021]
    if any(port < 1 or port > 65535 for port in ports):
        print("ERROR: invalid port", file=sys.stderr)
        return 2
    if any(port not in SAFE_PROBE_PORTS for port in ports):
        print("ERROR: only 9021 and 3232 may be probed; 9020/9026/9090 are excluded.", file=sys.stderr)
        return 2
    results = []
    for port in ports:
        opened = probe(a.host, port, a.timeout)
        results.append(opened)
        print(f"{a.host}:{port} {'OPEN' if opened else 'CLOSED'} - {PORT_LABELS.get(port, 'TCP')}")
    print("OPEN proves only TCP accept, NOT execution. Bootstrap/binloader ports were not touched.")
    return 1 if a.require_open and not all(results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
