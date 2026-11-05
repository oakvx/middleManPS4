"""Read-only PSN/update diagnostic for an authorized PS4's GoldHEN Klog.

This is NOT a PSN bypass and cannot establish whether a particular version
check was performed locally or by Sony. Never persists or prints raw logs:
those can contain identifiers, credentials or tokens.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, field
import math
import re
import socket
import sys
import time

from .cli import valid_target

KLOG_PORT = 3232
MAX_SECONDS = 120
MAX_PENDING = 8192
ERROR_CODE = re.compile(r"(?<![\w-])(?:NP|WS|CE|SU|NW|WV|E)-\d{3,6}-\d{1,3}\b", re.IGNORECASE)
PSN_TAG = re.compile(r"\b(?:psn|sceNp\w*|npmanager|npauth|np-auth|playstation network)\b", re.IGNORECASE)
UPDATE_TAG = re.compile(r"\b(?:update|updater|sysupdate|system software|firmware|sceSystemUpdate\w*|required version)\b", re.IGNORECASE)
NETWORK_TAG = re.compile(r"\b(?:https?|ssl|tls|dns|network|socket|connect(?:ion)?)\b", re.IGNORECASE)


@dataclass
class Summary:
    bytes_received: int = 0
    lines_seen: int = 0
    psn_lines: int = 0
    update_lines: int = 0
    network_lines: int = 0
    codes: Counter[str] = field(default_factory=Counter)
    truncated_lines: int = 0
    stream_closed: bool = False

    def inspect(self, line: bytes) -> None:
        self.lines_seen += 1
        # Only ephemeral decoding; never persist or echo the original line.
        text = line.decode("utf-8", errors="replace")
        self.psn_lines += bool(PSN_TAG.search(text))
        self.update_lines += bool(UPDATE_TAG.search(text))
        self.network_lines += bool(NETWORK_TAG.search(text))
        for code in ERROR_CODE.findall(text):
            self.codes[code.upper()] += 1


def collect(conn: socket.socket, seconds: float, *, now=time.monotonic) -> Summary:
    """Read from an already connected Klog socket without sending bytes."""
    result = Summary()
    pending = bytearray()
    deadline = now() + seconds
    while now() < deadline:
        conn.settimeout(min(0.5, max(0.001, deadline - now())))
        try:
            data = conn.recv(4096)
        except socket.timeout:
            continue
        if not data:
            result.stream_closed = True
            break
        result.bytes_received += len(data)
        pending.extend(data)
        while b"\n" in pending:
            line, _, tail = pending.partition(b"\n")
            if len(line) <= MAX_PENDING:
                result.inspect(line)
            else:
                result.truncated_lines += 1
            pending = bytearray(tail)
        if len(pending) > MAX_PENDING:
            # Avoid retaining giant untrusted lines (including credentials).
            result.truncated_lines += 1
            pending.clear()
    if pending:
        result.inspect(pending)
    return result


def format_summary(result: Summary) -> str:
    codes = ", ".join(f"{code} ({count})" for code, count in result.codes.most_common(10))
    return "\n".join((
        "=== PSN DIAGNOSTIC: SOLO METADATI ===",
        f"Byte Klog ricevuti: {result.bytes_received}",
        f"Righe elaborate: {result.lines_seen}",
        f"Righe con riferimenti PSN/NP: {result.psn_lines}",
        f"Righe con riferimenti aggiornamento/firmware: {result.update_lines}",
        f"Righe con riferimenti di rete: {result.network_lines}",
        f"Codici di errore osservati (anche non PSN): {codes or 'nessuno'}",
        f"Righe troppo lunghe scartate: {result.truncated_lines}",
        f"Stream chiuso dal server: {'si' if result.stream_closed else 'no'}",
        "Non vengono salvati o mostrati log integrali, credenziali o token.",
        "ATTENZIONE: questi indizi NON identificano da soli un controllo locale o remoto.",
        "L'assenza di messaggi NON significa che il controllo sia locale.",
    ))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="GoldHEN 3232 read-only PSN diagnostics (no firmware patch)")
    p.add_argument("--host", required=True, help="IP privato della tua PS4")
    p.add_argument("--seconds", type=float, default=45.0, help="Durata ascolto (1-120 s, default 45)")
    args = p.parse_args(argv)
    if not valid_target(args.host) or not math.isfinite(args.seconds) or not 1 <= args.seconds <= MAX_SECONDS:
        print("ERRORE: serve IP locale attendibile e durata da 1 a 120 secondi.", file=sys.stderr)
        return 2
    print(f"Connessione a Klog GoldHEN {args.host}:{KLOG_PORT} (solo lettura)...", flush=True)
    try:
        with socket.create_connection((args.host, KLOG_PORT), timeout=4) as conn:
            print("IN ASCOLTO. Ora, sulla PS4, tenta UNA VOLTA 'Accedi a PSN'.", flush=True)
            print("Quando compare la richiesta di aggiornamento, annota il messaggio.", flush=True)
            summary = collect(conn, args.seconds)
    except KeyboardInterrupt:
        print("Interrotto dall'utente. Nessuna modifica effettuata sulla console.", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"ERRORE KLOG: {exc}", file=sys.stderr)
        print("Controlla che GoldHEN Klog Server (TCP 3232) sia attivo.", file=sys.stderr)
        return 1
    print(format_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
