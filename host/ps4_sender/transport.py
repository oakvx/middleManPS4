"""Raw TCP transport with optional, bounded collection of elfldr stdio.

elfldr uses the same accepted socket to send loader errors and the spawned
payload's stdout/stderr. Closing it immediately after sendall loses evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import math
from pathlib import Path
import socket
import time

DEFAULT_PORT = 9021
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024
MAX_RESPONSE_SIZE = 256 * 1024


@dataclass(frozen=True)
class TransferReport:
    bytes_sent: int
    sha256: str
    response: bytes = b""
    response_complete: bool = False
    response_truncated: bool = False
    response_error: str | None = None


def read_payload(path: Path) -> bytes:
    """Read one immutable snapshot of a local payload (max 64 MiB)."""
    size = path.stat().st_size
    if not 0 < size <= MAX_PAYLOAD_SIZE:
        raise ValueError(f"Invalid payload size: {size} bytes")
    data = path.read_bytes()
    if len(data) != size:
        raise OSError("Payload changed while being read")
    return data


def send_payload(
    host: str,
    path: Path,
    port: int = DEFAULT_PORT,
    timeout: float = 10.0,
    *,
    payload_bytes: bytes | None = None,
    response_timeout: float = 0.0,
) -> TransferReport:
    """Send raw bytes; optionally half-close and collect remote output.

    The bounded capture is intended for elfldr on port 9021, *not* GoldHEN's
    experimental BinLoader. Returning from this method proves no execution.
    """
    if not 1 <= port <= 65535:
        raise ValueError("Port must be in range 1..65535")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Timeout must be finite and positive")
    if not math.isfinite(response_timeout) or response_timeout < 0 or response_timeout > 120:
        raise ValueError("Response timeout must be between 0 and 120 seconds")
    data = read_payload(path) if payload_bytes is None else payload_bytes
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PAYLOAD_SIZE:
        raise ValueError("Invalid payload bytes")

    response = bytearray()
    complete = False
    truncated = False
    recv_error: str | None = None
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.sendall(data)
        if response_timeout:
            # elfldr has read the ELF's known lengths; signal end of stdin,
            # but keep the read half alive for its stdout/stderr and errors.
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError as exc:
                recv_error = f"TCP half-close failed: {exc}"
            deadline = time.monotonic() + response_timeout
            while recv_error is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if len(response) >= MAX_RESPONSE_SIZE:
                    truncated = True
                    break
                conn.settimeout(min(remaining, 1.0))
                try:
                    chunk = conn.recv(min(16384, MAX_RESPONSE_SIZE - len(response)))
                except socket.timeout:
                    continue
                except OSError as exc:
                    recv_error = str(exc)
                    break
                if not chunk:
                    complete = True
                    break
                response.extend(chunk)

    return TransferReport(
        bytes_sent=len(data), sha256=sha256(data).hexdigest(),
        response=bytes(response), response_complete=complete,
        response_truncated=truncated, response_error=recv_error,
    )
