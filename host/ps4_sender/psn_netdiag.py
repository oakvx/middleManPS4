"""Passive PS4 DNS/TLS metadata capture and comparison with TShark.

Never decrypts, modifies or replays packets. Raw PCAP stays in a temporary
folder and is removed automatically; only a bounded JSON metadata summary
is retained if requested. This tool sees PS4 traffic only on a suitable
capture interface (gateway, AP or mirror port).
"""
from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

MAX_PCAP = 64 * 1024 * 1024
MAX_EVENTS = 5000
FIELDS = (
    "frame.time_relative", "ip.src", "ip.dst", "tcp.dstport", "dns.qry.name",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "tcp.flags.syn",
    "tcp.flags.reset", "tls.record.content_type"
)
FILTER = ("dns.qry.name or tls.handshake.type == 1 or tcp.flags.syn == 1 "
          "or tcp.flags.reset == 1 or tls.record.content_type == 21")
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$", re.ASCII)


class DiagnosticError(Exception):
    pass


def tshark_path() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    for home in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if home:
            candidate = Path(home) / "Wireshark" / "tshark.exe"
            if candidate.is_file():
                return str(candidate)
    raise DiagnosticError("TShark non trovato. Installa Wireshark + TShark/Npcap.")


def ip_is_ps4(text: str, ps4_ip: str) -> bool:
    return text == ps4_ip


def normal_host(value: str) -> str | None:
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253 or not HOST_RE.fullmatch(value):
        return None
    return value


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def summarise_tshark(tsv: str, ps4_ip: str) -> dict:
    """Consume only TShark -T fields output; never handles HTTP or TLS payloads."""
    events = []
    counts: Counter[str] = Counter()
    dns: set[str] = set()
    snis: set[str] = set()
    ips: set[str] = set()
    for line in tsv.splitlines():
        cols = line.rstrip("\r").split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        timestamp, src, dst, dstport, dns_name, hs_type, sni, syn, rst, rec_type = cols[:len(FIELDS)]
        if not (ip_is_ps4(src, ps4_ip) or ip_is_ps4(dst, ps4_ip)):
            continue
        try:
            seconds = float(timestamp)
        except ValueError:
            continue
        if not math.isfinite(seconds) or seconds < 0:
            continue
        observed = []
        name = normal_host(dns_name)
        server_name = normal_host(sni)
        if name:
            counts["dns"] += 1
            dns.add(name)
            observed.append(("dns", name))
        if hs_type.split(",")[0] == "1":
            counts["tls_clienthello"] += 1
            if server_name:
                snis.add(server_name)
            observed.append(("tls_clienthello", server_name))
        if syn == "1":
            counts["tcp_syn"] += 1
            observed.append(("tcp_syn", None))
        if rst == "1":
            counts["tcp_rst"] += 1
            observed.append(("tcp_rst", None))
        if rec_type.split(",")[0] == "21":
            counts["tls_alert"] += 1
            observed.append(("tls_alert", None))
        # Only the destination for outbound packets from the actual PS4.
        if src == ps4_ip:
            public = normalize_ip(dst)
            if public and ipaddress.ip_address(public).is_global:
                ips.add(public)
        for kind, host in observed:
            if len(events) < MAX_EVENTS:
                events.append({"t": round(seconds, 3), "kind": kind, "host": host,
                               "dst": normalize_ip(dst) if src == ps4_ip else None,
                               "port": int(dstport) if dstport.isdigit() and int(dstport) <= 65535 else None})
    return {"format": "fwSpoofer-netmeta-v1", "ps4_ip": ps4_ip,
            "counts": dict(counts), "dns_names": sorted(dns)[:250],
            "tls_sni": sorted(snis)[:250], "public_ips": sorted(ips)[:250],
            "events": events, "events_limit_reached": len(events) >= MAX_EVENTS}


def read_capture(path: Path, ps4_ip: str, *, runner=subprocess.run, tshark: str) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_PCAP:
        raise DiagnosticError("PCAP mancante o maggiore di 64 MiB")
    cmd = [tshark, "-r", str(path), "-Y", FILTER, "-T", "fields", "-E", "occurrence=f"]
    for name in FIELDS:
        cmd.extend(("-e", name))
    try:
        proc = runner(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DiagnosticError("TShark non ha completato l'analisi") from exc
    if proc.returncode:
        raise DiagnosticError("Errore TShark nell'analisi: controlla versione e campi supportati")
    return summarise_tshark(proc.stdout, ps4_ip)


def save_summary(path: Path, data: dict) -> None:
    if path.exists() or not path.parent.is_dir():
        raise DiagnosticError("Il file riepilogo deve essere nuovo e in una cartella esistente")
    try:
        with path.open("x", encoding="utf-8") as out:
            json.dump(data, out, ensure_ascii=False, indent=2, sort_keys=True)
    except OSError as exc:
        raise DiagnosticError("Impossibile salvare il riepilogo") from exc


def load_summary(path: Path) -> dict:
    """Accept sanitized TShark JSON or metadata-only CONNECT JSONL."""
    if path.stat().st_size > 4 * 1024 * 1024:
        raise DiagnosticError("Riepilogo troppo grande (max 4 MiB)")
    raw = path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict) and data.get("format") == "fwSpoofer-netmeta-v1":
        return data
    # Tunnel JSONL: no HTTP content, no TLS keys or request headers.
    hosts = set()
    ps4_ip = None
    count = 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise DiagnosticError("Il file non contiene JSON di riepilogo valido") from exc
        if not isinstance(entry, dict) or not isinstance(entry.get("ps4_ip"), str):
            raise DiagnosticError("Riga di log CONNECT priva dell'IP PS4")
        if ps4_ip is not None and ps4_ip != entry["ps4_ip"]:
            raise DiagnosticError("Log CONNECT con piu' IP PS4")
        ps4_ip = entry["ps4_ip"]
        host = normal_host(entry.get("host", ""))
        if host and entry.get("result") == "tunneled":
            hosts.add(host)
        count += 1
    if not count:
        raise DiagnosticError("Riepilogo vuoto")
    return {"format": "fwSpoofer-tunnel-v1", "ps4_ip": ps4_ip,
            "connect_hosts": sorted(hosts), "counts": {"connect_attempts": count}}


def comparison(baseline: dict, attempt: dict) -> dict:
    if baseline.get("format") != attempt.get("format") or baseline.get("format") not in (
            "fwSpoofer-netmeta-v1", "fwSpoofer-tunnel-v1"):
        raise DiagnosticError("Formati incompatibili: confronta PCAP con PCAP oppure tunnel con tunnel")
    if baseline.get("ps4_ip") != attempt.get("ps4_ip"):
        raise DiagnosticError("Gli IP PS4 dei due rilievi non coincidono")
    result = {"ps4_ip": baseline["ps4_ip"]}
    fields = (("connect_hosts",) if baseline["format"] == "fwSpoofer-tunnel-v1"
              else ("dns_names", "tls_sni", "public_ips"))
    for field in fields:
        try:
            first = set(baseline[field])
            second = set(attempt[field])
        except (KeyError, TypeError) as exc:
            raise DiagnosticError("Riepilogo incompleto") from exc
        result[field + "_new"] = sorted(second - first)
    result["baseline_counts"] = baseline.get("counts", {})
    result["attempt_counts"] = attempt.get("counts", {})
    return result


def _valid_ps4_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return parsed.version == 4 and parsed.is_private and not parsed.is_loopback


def _display(summary: dict) -> None:
    print("=== RIEPILOGO METADATI (NON CONTENUTO HTTPS) ===")
    for key in ("dns", "tls_clienthello", "tcp_syn", "tcp_rst", "tls_alert"):
        print(f"{key}: {summary['counts'].get(key, 0)}")
    print(f"Nomi DNS distinti: {len(summary['dns_names'])}; SNI distinti: {len(summary['tls_sni'])}")
    if not summary["events"]:
        print("ATTENZIONE: nessun evento PS4 osservato. Il PC potrebbe non trovarsi nel percorso di rete.")
    print("La sola presenza di DNS/SNI non dimostra autenticazione né origine del blocco PSN.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="PS4 DNS/TLS metadata-only TShark acquisition")
    commands = p.add_subparsers(dest="cmd", required=True)
    commands.add_parser("interfaces", help="Lista interfacce Wireshark")
    for verb in ("capture", "analyze"):
        child = commands.add_parser(verb)
        child.add_argument("--host", required=True, help="IP privato della PS4")
        child.add_argument("--summary", type=Path, required=True, help="JSON riassuntivo senza payload")
        if verb == "capture":
            child.add_argument("--interface", required=True, help="ID della rete da tshark -D")
            child.add_argument("--seconds", type=int, default=30, help="Durata 10-120 s")
            child.add_argument("--capture", action="store_true", help="Avvia la cattura, non solo dry-run")
        else:
            child.add_argument("--pcap", required=True, type=Path)
    comp = commands.add_parser("compare", help="Confronta i riepiloghi baseline/PSN")
    comp.add_argument("--baseline", required=True, type=Path)
    comp.add_argument("--attempt", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        if args.cmd == "compare":
            b = load_summary(args.baseline)
            a = load_summary(args.attempt)
            print(json.dumps(comparison(b, a), indent=2, ensure_ascii=False))
            print("Differenze di rete ≠ prova che Sony abbia rifiutato il login.")
            return 0
        path = tshark_path()
        if args.cmd == "interfaces":
            proc = subprocess.run([path, "-D"], capture_output=True, text=True, timeout=15)
            if proc.returncode:
                raise DiagnosticError("Impossibile elencare le interfacce")
            print(proc.stdout)
            return 0
        if not _valid_ps4_ip(args.host):
            raise DiagnosticError("Serve l'IP IPv4 privato della PS4")
        if args.summary.exists():
            raise DiagnosticError("Il riepilogo esiste: scegli un nuovo nome per evitare sovrascritture")
        if args.cmd == "analyze":
            summary = read_capture(args.pcap, args.host, tshark=path)
        else:
            if not (10 <= args.seconds <= 120 and
                    re.fullmatch(r"[\w.{}\\-]{1,120}", args.interface, re.ASCII)):
                raise DiagnosticError("Interfaccia non valida o durata fuori intervallo 10-120 s")
            print(f"Filtro passivo: solo pacchetti host {args.host} per {args.seconds} s.")
            if not args.capture:
                print("DRY RUN: nessuna cattura. Specifica --capture per iniziare.")
                return 0
            with tempfile.TemporaryDirectory(prefix="fwSpoofer-netmeta-") as temp:
                pcap = Path(temp) / "private-capture.pcapng"
                print("In ascolto: apri UNA volta l'accesso PSN, poi non confermare aggiornamenti.", flush=True)
                proc = subprocess.run([path, "-i", args.interface, "-f", f"host {args.host}",
                                       "-a", f"duration:{args.seconds}", "-a", "filesize:8192",
                                       "-w", str(pcap)], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True, timeout=args.seconds + 20)
                if proc.returncode and not pcap.exists():
                    raise DiagnosticError("Cattura fallita: controlla Npcap, privilegi e interfaccia")
                summary = read_capture(pcap, args.host, tshark=path)
                # tempfile removes the sensitive raw PCAP upon exiting the block.
        save_summary(args.summary, summary)
        _display(summary)
        print(f"Riepilogo scritto in {args.summary}; non contiene credenziali o payload HTTP/TLS.")
        print("Conserva il JSON in privato: DNS/SNI e indirizzi IP restano metadati identificativi.")
        return 0
    except (DiagnosticError, OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"ERRORE DIAGNOSTICA: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
