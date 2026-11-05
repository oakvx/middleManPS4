"""Capture TCP Klog data into a local timestamped binary file (no console modifications)."""
from __future__ import annotations

import argparse
import math
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

from .cli import valid_target


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Capture GoldHEN Klog TCP 3232")
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=3232, help="GoldHEN Klog only; other ports refused")
    p.add_argument("--seconds", type=float, default=60.0)
    p.add_argument("--output", type=Path, default=None)
    args = p.parse_args(argv)
    if not valid_target(args.host) or args.port != 3232 or not math.isfinite(args.seconds) or args.seconds <= 0:
        print("Invalid host/port/duration", file=sys.stderr)
        return 2
    path = args.output or Path("logs") / f"klog-{datetime.now():%Y%m%d-%H%M%S}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + args.seconds
    count = 0
    try:
        with socket.create_connection((args.host, args.port), timeout=5) as conn, path.open("wb") as f:
            conn.settimeout(0.5)
            while time.monotonic() < deadline:
                try:
                    data = conn.recv(16384)
                except socket.timeout:
                    continue
                if not data:
                    break
                f.write(data)
                f.flush()
                count += len(data)
    except KeyboardInterrupt:
        print("Interrotto dall'utente; log parziale conservato.")
    except OSError as exc:
        print(f"KLOG ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Klog salvato in {path} ({count} byte).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
