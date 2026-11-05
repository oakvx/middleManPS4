"""Strict, metadata-only HTTPS CONNECT forwarder for a user's own PS4.

NOT an interception of HTTPS plaintext, PSN authentication bypass, TLS MITM or
firmware spoofer. Only public TCP/443 destinations are allowed. No request
bodies, tokens, TLS records, certificates or raw headers are logged.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import math
from pathlib import Path
import re
import select
import socket
import socketserver
import sys
import threading
import time

DEFAULT_PORT = 8888
MAX_HEADER = 8192
MAX_TUNNEL_SECONDS = 120
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", re.ASCII)


class RequestDenied(Exception):
    """Invalid or non-CONNECT request; never quote attacker-controlled content."""


def public_host_port(headers: bytes) -> str:
    """Parse just a CONNECT authority, never print/store the original headers."""
    try:
        request_line = headers.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise RequestDenied("non-ASCII request") from exc
    for header_line in headers.split(b"\r\n")[1:]:
        # Strict HTTP/1.x field syntax; no forwarding of plaintext requests.
        if not header_line or b":" not in header_line or b"\x00" in header_line:
            raise RequestDenied("invalid CONNECT header")
    parts = request_line.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
        raise RequestDenied("CONNECT required")
    authority = parts[1]
    if ":" not in authority or authority.count(":") != 1:
        raise RequestDenied("expected hostname:443")
    host, port = authority.rsplit(":", 1)
    if port != "443" or not HOST_RE.fullmatch(host) or ".." in host:
        raise RequestDenied("only valid hostnames on TCP 443 are permitted")
    if host.lower() in ("localhost",) or host.lower().endswith((".localhost", ".local", ".internal")):
        raise RequestDenied("local names are forbidden")
    if len(host) > 253 or any(len(part) > 63 or part.startswith("-") or part.endswith("-") for part in host.split(".")):
        raise RequestDenied("invalid hostname labels")
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not parsed.is_global:
            raise RequestDenied("non-public destination")
    return host.lower()


def open_public_tcp443(host: str, timeout: float) -> socket.socket:
    """Resolve once, connect to a vetted public address; no DNS-rebind second lookup."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise RequestDenied("DNS lookup unsuccessful") from exc
    for family, socktype, proto, _, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if not ip.is_global:
            continue
        upstream = socket.socket(family, socktype, proto)
        try:
            upstream.settimeout(timeout)
            upstream.connect(sockaddr)
            return upstream
        except OSError:
            upstream.close()
    raise RequestDenied("no reachable public address")


def read_header(sock: socket.socket) -> tuple[bytes, bytes]:
    pending = bytearray()
    while b"\r\n\r\n" not in pending:
        chunk = sock.recv(1024)
        if not chunk:
            raise RequestDenied("incomplete CONNECT header")
        pending.extend(chunk)
        if len(pending) > MAX_HEADER:
            raise RequestDenied("header too large")
    head, remaining = bytes(pending).split(b"\r\n\r\n", 1)
    return head, remaining


def relay_opaque(client: socket.socket, upstream: socket.socket, prefetched: bytes,
                 max_seconds: float = MAX_TUNNEL_SECONDS) -> tuple[int, int]:
    """Forward opaque encrypted bytes. Return (PS4->server, server->PS4)."""
    sent_out = sent_in = 0
    if prefetched:
        upstream.sendall(prefetched)
        sent_out += len(prefetched)
    deadline = time.monotonic() + max_seconds
    readable_sockets = {client, upstream}
    while readable_sockets and time.monotonic() < deadline:
        try:
            readable, _, _ = select.select(list(readable_sockets), [], [],
                                           min(1.0, max(0.001, deadline - time.monotonic())))
        except (OSError, ValueError):
            break
        for src in readable:
            dst = upstream if src is client else client
            try:
                data = src.recv(16384)
                if not data:
                    readable_sockets.remove(src)
                    # Preserve half-close semantics: the other endpoint may
                    # still have a final TLS record to send.
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                dst.sendall(data)
                if src is client:
                    sent_out += len(data)
                else:
                    sent_in += len(data)
            except OSError:
                return sent_out, sent_in
    return sent_out, sent_in


class TunnelServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 10

    def __init__(self, address: tuple[str, int], allowed_client: str, report: Path | None,
                 max_tunnel_seconds: float):
        self.allowed_client = allowed_client
        self.report = report
        self.max_tunnel_seconds = max_tunnel_seconds
        self.write_lock = threading.Lock()
        self.limiter = threading.BoundedSemaphore(8)
        super().__init__(address, TunnelHandler)

    def record(self, data: dict) -> None:
        # Strictly metadata; never include raw request headers or TCP contents.
        entry = {"utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "ps4_ip": self.allowed_client, **data}
        with self.write_lock:
            print(f"CONNECT {entry['host']}:{entry['port']} {entry['result']} "
                  f"out={entry['bytes_up']} in={entry['bytes_down']}", flush=True)
            if self.report:
                with self.report.open("a", encoding="utf-8") as out:
                    out.write(json.dumps(entry, sort_keys=True) + "\n")


class TunnelHandler(socketserver.BaseRequestHandler):
    server: TunnelServer

    def handle(self) -> None:
        if self.client_address[0] != self.server.allowed_client:
            return
        if not self.server.limiter.acquire(blocking=False):
            self._reply(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
            return
        host = "(rejected)"
        bytes_up = bytes_down = 0
        result = "rejected"
        try:
            self.request.settimeout(8.0)
            header, prefetched = read_header(self.request)
            host = public_host_port(header)
            try:
                remote = open_public_tcp443(host, 7.0)
            except RequestDenied:
                self._reply(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                result = "upstream-unavailable"
                return
            with remote:
                self._reply(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                result = "tunneled"
                bytes_up, bytes_down = relay_opaque(
                    self.request, remote, prefetched, self.server.max_tunnel_seconds
                )
        except (RequestDenied, OSError, TimeoutError):
            if result == "rejected":
                self._reply(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
        finally:
            self.server.record({"host": host, "port": 443 if host != "(rejected)" else 0,
                                "result": result, "bytes_up": bytes_up,
                                "bytes_down": bytes_down})
            self.server.limiter.release()

    def _reply(self, data: bytes) -> None:
        try:
            self.request.sendall(data)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Opaque PS4 HTTPS CONNECT tunnel, metadata only")
    parser.add_argument("--client-ip", required=True, help="PS4 IP, the only permitted client")
    parser.add_argument("--bind", default="127.0.0.1", help="Local PC listen address; default loopback")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--seconds", type=float, default=90.0, help="Listening time 5-300 seconds")
    parser.add_argument("--report", type=Path, help="Optional JSONL metadata report (no payloads)")
    parser.add_argument("--serve", action="store_true", help="Actually open a listening socket")
    parser.add_argument("--allow-lan", action="store_true", help="Allow listening on LAN, only for the PS4 IP")
    args = parser.parse_args(argv)
    try:
        client = ipaddress.ip_address(args.client_ip)
        bind = ipaddress.ip_address(args.bind)
    except ValueError:
        parser.error("client-ip and bind must be literal IPv4 addresses")
    if client.version != 4 or bind.version != 4 or not client.is_private:
        parser.error("client must be a private IPv4 address; bind must be IPv4")
    if not (1 <= args.port <= 65535 and math.isfinite(args.seconds) and 5 <= args.seconds <= 300):
        parser.error("invalid TCP port or duration")
    if not bind.is_loopback and not args.allow_lan:
        parser.error("LAN listening requires --allow-lan; access restricted to --client-ip")
    if args.report and (args.report.exists() or not args.report.parent.is_dir()):
        parser.error("report must be a NEW file in an existing directory; no overwrite")
    print(f"Tunnel TLS cifrato: {args.bind}:{args.port}, PS4 autorizzata {client}.")
    print("Solo CONNECT TCP/443 verso IP pubblici; nessuna decifratura, modifica o cattura credenziali.")
    print(f"Durata massima {args.seconds:g}s; report: {args.report or 'terminale soltanto'}.")
    if not args.serve:
        print("DRY RUN: nessuna porta aperta. Usa --serve per avviare realmente.")
        return 0
    try:
        with TunnelServer((args.bind, args.port), str(client), args.report,
                          max_tunnel_seconds=min(120, args.seconds)) as server:
            timer = threading.Timer(args.seconds, server.shutdown)
            timer.daemon = True
            timer.start()
            try:
                print("IN ASCOLTO: configura il proxy HTTPS della tua PS4 su IP-PC e porta indicata.", flush=True)
                server.serve_forever(poll_interval=0.25)
            finally:
                timer.cancel()
    except KeyboardInterrupt:
        print("Interrotto: disattiva il proxy nella configurazione di rete della PS4.")
        return 130
    except OSError as exc:
        print(f"Errore socket locale: {exc}", file=sys.stderr)
        return 1
    print("Terminato. Disattiva il proxy nella configurazione di rete della PS4.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
