"""LAN-paired, metadata-only, bounded PS4 agent receiver and localhost dashboard.

This is NOT a system syscall tracer. Only self-process events explicitly
emitted by a configured agent are accepted. No account, packet or TLS data.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html import escape

VERSION = 1
MAX_LINE = 512
MAX_EVENTS_PER_SESSION = 128
MAX_EVENTS_MEMORY = 1000
ALLOWED_KINDS = frozenset({"agent_start", "firmware_read", "heartbeat", "agent_complete", "agent_error"})
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_32 = re.compile(r"[0-9a-f]{32}\Z")


class LiveAgentError(ValueError):
    """Configuration or protocol failure."""


def valid_private_ipv4(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Only RFC1918 and loopback; ipaddress.is_private also includes some reserved ranges.
    return parsed.version == 4 and any(parsed in network for network in (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ))


def load_key(path: Path) -> bytes:
    raw = path.read_text(encoding="ascii").strip()
    if not HEX_64.fullmatch(raw):
        raise LiveAgentError("Pairing key must contain exactly 64 lowercase hexadecimal characters")
    return bytes.fromhex(raw)


def proof(key: bytes, nonce: str) -> str:
    if not HEX_32.fullmatch(nonce) or len(key) != 32:
        raise LiveAgentError("Invalid challenge or pairing key")
    return hmac.new(key, b"mmps4-live-v1:" + nonce.encode("ascii"), hashlib.sha256).hexdigest()


def event_signature(key: bytes, nonce: str, event: dict) -> str:
    msg = (f"mmps4-event-v1|{nonce}|{event['seq']}|{event['kind']}|"
           f"{event['pid']}|{event['elapsed_ms']}|{event['status']}")
    return hmac.new(key, msg.encode("ascii"), hashlib.sha256).hexdigest()


def normalize_event(raw: object, key: bytes, nonce: str, seq: int, previous_elapsed: int) -> dict:
    if not isinstance(raw, dict) or set(raw) != {
            "type", "protocol", "seq", "kind", "pid", "elapsed_ms", "status", "mac"}:
        raise LiveAgentError("Unexpected event frame fields")
    if raw["type"] != "event" or type(raw["protocol"]) is not int or raw["protocol"] != VERSION:
        raise LiveAgentError("Unsupported event frame")
    if type(raw["seq"]) is not int or raw["seq"] != seq:
        raise LiveAgentError("Non-monotonic event sequence")
    if not isinstance(raw["kind"], str) or raw["kind"] not in ALLOWED_KINDS:
        raise LiveAgentError("Unexpected event kind")
    pid, elapsed, status = raw["pid"], raw["elapsed_ms"], raw["status"]
    if (type(pid) is not int or not 1 <= pid <= 2**31 - 1 or
            type(elapsed) is not int or not previous_elapsed <= elapsed <= 3_600_000 or
            type(status) is not int or not -32768 <= status <= 32767):
        raise LiveAgentError("Out-of-bounds event values")
    mac = raw["mac"]
    if not isinstance(mac, str) or not HEX_64.fullmatch(mac):
        raise LiveAgentError("Malformed event MAC")
    fields = {k: raw[k] for k in ("seq", "kind", "pid", "elapsed_ms", "status")}
    if not hmac.compare_digest(mac, event_signature(key, nonce, fields)):
        raise LiveAgentError("Invalid event MAC")
    return fields  # Never retain unrecognized, unauthenticated payloads.


def json_line(obj: dict) -> bytes:
    payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    if len(payload) > MAX_LINE:
        raise LiveAgentError("Protocol frame exceeds 512 bytes")
    return payload


def read_json_frame(channel) -> dict:
    line = channel.readline(MAX_LINE + 1)
    if not line or len(line) > MAX_LINE or not line.endswith(b"\n"):
        raise LiveAgentError("Missing or oversized protocol frame")
    try:
        parsed = json.loads(line)
    except (UnicodeError, ValueError) as exc:
        raise LiveAgentError("Invalid JSON frame") from exc
    if not isinstance(parsed, dict):
        raise LiveAgentError("Expected a JSON object")
    return parsed


class LiveState:
    def __init__(self, output: Path | None = None):
        self.lock = threading.Lock()
        self.events: deque[dict] = deque(maxlen=MAX_EVENTS_MEMORY)
        self.total = 0
        self.authenticated_sessions = 0
        self.rejected_sessions = 0
        self.output = None
        if output is not None:
            if not output.parent.is_dir():
                raise LiveAgentError("The output directory must already exist")
            self.output = output.open("x", encoding="utf-8", newline="\n")

    def close(self):
        with self.lock:
            if self.output:
                self.output.close()
                self.output = None

    def append(self, event: dict):
        envelope = {"received_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                    **event}
        with self.lock:
            self.events.append(envelope)
            self.total += 1
            if self.output:
                self.output.write(json.dumps(envelope, separators=(",", ":"), sort_keys=True) + "\n")
                self.output.flush()

    def snapshot(self) -> dict:
        with self.lock:
            items = list(self.events)
            return {"format": "middleManPS4-live-v1", "total_events": self.total,
                    "authenticated_sessions": self.authenticated_sessions,
                    "rejected_sessions": self.rejected_sessions,
                    "buffer_capacity": MAX_EVENTS_MEMORY,
                    "buffered_events": len(items),
                    "events_dropped_from_buffer": max(0, self.total - len(items)),
                    "counts": dict(sorted(Counter(e["kind"] for e in items).items())),
                    "events": items,
                    "capture_scope": "agent_process_only",
                    "system_wide_syscalls": "not_implemented"}


class LiveTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], *, key: bytes, ps4_ip: str,
                 state: LiveState):
        if not valid_private_ipv4(address[0]) or not valid_private_ipv4(ps4_ip):
            raise LiveAgentError("Bind and peer must be explicit private/loopback IPv4 addresses")
        if len(key) != 32:
            raise LiveAgentError("Expected a 256-bit pairing key")
        self.pair_key = key
        self.peer_allowlist = ps4_ip
        self.state = state
        super().__init__(address, LiveHandler)


class LiveHandler(socketserver.BaseRequestHandler):
    def handle(self):
        server: LiveTCPServer = self.server
        if self.client_address[0] != server.peer_allowlist:
            with server.state.lock:
                server.state.rejected_sessions += 1
            return
        self.request.settimeout(4.0)
        nonce = secrets.token_hex(16)
        verified = False
        try:
            self.request.sendall(json_line({"type": "challenge", "protocol": VERSION,
                                            "nonce": nonce}))
            with self.request.makefile("rb", buffering=0) as channel:
                handshake = read_json_frame(channel)
                if (set(handshake) != {"type", "protocol", "proof"} or
                        handshake["type"] != "auth" or
                        type(handshake["protocol"]) is not int or handshake["protocol"] != VERSION or
                        not isinstance(handshake["proof"], str) or
                        not hmac.compare_digest(handshake["proof"], proof(server.pair_key, nonce))):
                    raise LiveAgentError("Pairing failed")
                verified = True
                with server.state.lock:
                    server.state.authenticated_sessions += 1
                self.request.sendall(json_line({"type": "accepted", "protocol": VERSION}))
                seq, last_ms = 0, 0
                end = time.monotonic() + 60.0
                while seq < MAX_EVENTS_PER_SESSION and time.monotonic() < end:
                    try:
                        frame = read_json_frame(channel)
                    except LiveAgentError as exc:
                        if str(exc).startswith("Missing"):
                            break
                        raise
                    event = normalize_event(frame, server.pair_key, nonce, seq, last_ms)
                    server.state.append(event)
                    seq += 1
                    last_ms = event["elapsed_ms"]
                    if event["kind"] in ("agent_complete", "agent_error"):
                        break
        except (OSError, LiveAgentError, ValueError):
            if not verified:
                with server.state.lock:
                    server.state.rejected_sessions += 1
            # No raw request contents, connection tokens or peer addresses logged.


HTML = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>middleManPS4 Live Agent</title><style>body{font:15px system-ui;margin:0;background:#0d1724;color:#eef4fa}main{max-width:1050px;margin:0 auto;padding:30px}h1{font-size:27px}.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.card{padding:18px;background:#162536;border:1px solid #30455c;border-radius:10px}small{color:#b8c9d7}table{border-collapse:collapse;width:100%;margin-top:16px}td,th{text-align:left;padding:10px;border-bottom:1px solid #30455c}thead{color:#b4d5ea}.warn{color:#efc177}</style></head><body><main><h1>middleManPS4 · Live Agent</h1><p class='warn'>Read-only process telemetry · not a system syscall trace · localhost dashboard</p><div class='cols'><div class='card'><small>Events received</small><h2 id='total'>0</h2></div><div class='card'><small>Authenticated sessions</small><h2 id='sessions'>0</h2></div><div class='card'><small>Overwritten ring events</small><h2 id='dropped'>0</h2></div></div><h2>Latest events</h2><table><thead><tr><th>UTC</th><th>PID</th><th>Event</th><th>Elapsed ms</th><th>Status</th></tr></thead><tbody id='events'></tbody></table><script>async function refresh(){try{const r=await fetch('/api/snapshot',{cache:'no-store'});const s=await r.json();document.getElementById('total').textContent=s.total_events;document.getElementById('sessions').textContent=s.authenticated_sessions;document.getElementById('dropped').textContent=s.events_dropped_from_buffer;const list=document.getElementById('events');list.replaceChildren();for(const e of s.events.slice(-40).reverse()){const tr=document.createElement('tr');for(const k of ['received_utc','pid','kind','elapsed_ms','status']){const td=document.createElement('td');td.textContent=String(e[k]);tr.appendChild(td)}list.appendChild(tr)}}catch(e){}}setInterval(refresh,1000);refresh()</script></main></body></html>"""


def make_dashboard(state: LiveState, port: int = 8769) -> ThreadingHTTPServer:
    if type(port) is not int or not 0 <= port <= 65535:
        raise LiveAgentError("Dashboard port must be 0..65535")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                content, mime, status = HTML.encode("utf-8"), "text/html; charset=utf-8", 200
            elif self.path == "/api/snapshot":
                content = json.dumps(state.snapshot(), separators=(",", ":")).encode("utf-8")
                mime, status = "application/json", 200
            else:
                content, mime, status = b"Not found", "text/plain", 404
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            self.wfile.write(content)

        def do_POST(self):
            self.send_error(405, "Read-only")

        def log_message(self, *_args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def simulate(peer: str, port: int, key: bytes, count: int = 5) -> None:
    """Synthetic client to prove the protocol; does not access any PS4 or Sony service."""
    if peer not in ("127.0.0.1", "::1") or not 1 <= count <= 12:
        raise LiveAgentError("Simulator is restricted to localhost and 1..12 samples")
    with socket.create_connection((peer, port), timeout=4.0) as conn:
        conn.settimeout(4.0)
        with conn.makefile("rb", buffering=0) as channel:
            challenge = read_json_frame(channel)
            nonce = challenge.get("nonce")
            if set(challenge) != {"type", "protocol", "nonce"} or challenge["type"] != "challenge" or challenge["protocol"] != VERSION:
                raise LiveAgentError("Unexpected server challenge")
            conn.sendall(json_line({"type": "auth", "protocol": VERSION, "proof": proof(key, nonce)}))
            if read_json_frame(channel) != {"type": "accepted", "protocol": VERSION}:
                raise LiveAgentError("Pairing was not accepted")
            for index in range(count + 2):
                kind = "agent_start" if index == 0 else "agent_complete" if index == count + 1 else "heartbeat"
                event = {"seq": index, "kind": kind, "pid": os.getpid(), "elapsed_ms": index * 1000, "status": 0}
                conn.sendall(json_line({"type": "event", "protocol": VERSION, **event,
                                        "mac": event_signature(key, nonce, event)}))


def create_config(pc_ip: str, port: int, key_path: Path, header_path: Path) -> None:
    if not valid_private_ipv4(pc_ip) or ipaddress.ip_address(pc_ip).is_loopback:
        raise LiveAgentError("PC IP must be a private non-loopback IPv4 address")
    if not 1024 <= port <= 65535:
        raise LiveAgentError("Agent TCP port must be 1024..65535")
    if not key_path.parent.is_dir() or not header_path.parent.is_dir() or key_path.exists() or header_path.exists():
        raise LiveAgentError("Both output paths must be new and parents must exist")
    hex_key = secrets.token_hex(32)
    key_file_descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(key_file_descriptor, "w", encoding="ascii", newline="\n") as handle:
        handle.write(hex_key + "\n")
    header_fd = os.open(header_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(header_fd, "w", encoding="ascii", newline="\n") as header:
        header.write("#ifndef MMPS4_AGENT_LOCAL_CONFIG_H\n#define MMPS4_AGENT_LOCAL_CONFIG_H\n"
                     f'#define MMPS4_PC_IP "{pc_ip}"\n'
                     f"#define MMPS4_PC_PORT {port}\n"
                     f'#define MMPS4_PAIR_KEY_HEX "{hex_key}"\n'
                     "#endif\n")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="middleManPS4 LAN agent — metadata-only")
    sub = p.add_subparsers(dest="cmd", required=True)
    config = sub.add_parser("config", help="Generate secret key and private C header; never commit")
    config.add_argument("--pc-ip", required=True)
    config.add_argument("--port", type=int, default=8768)
    config.add_argument("--key-file", type=Path, required=True)
    config.add_argument("--header", type=Path, required=True)
    listen = sub.add_parser("listen", help="Receive authenticated telemetry from an allowlisted PS4")
    listen.add_argument("--bind", required=True, help="IP of the PC interface used by PS4")
    listen.add_argument("--ps4-ip", required=True)
    listen.add_argument("--key-file", type=Path, required=True)
    listen.add_argument("--port", type=int, default=8768)
    listen.add_argument("--dashboard-port", type=int, default=8769)
    listen.add_argument("--output", type=Path, help="Create one new private JSONL file (never overwrite)")
    demo = sub.add_parser("simulate", help="Send synthetic events to localhost only")
    demo.add_argument("--key-file", type=Path, required=True)
    demo.add_argument("--port", type=int, default=8768)
    demo.add_argument("--count", type=int, default=5)
    args = p.parse_args(argv)
    try:
        if args.cmd == "config":
            create_config(args.pc_ip, args.port, args.key_file, args.header)
            print("Private pairing files created. Never publish the key or compiled ELF.")
        elif args.cmd == "simulate":
            simulate("127.0.0.1", args.port, load_key(args.key_file), args.count)
            print("Synthetic events sent to the local receiver; no PS4 contacted.")
        else:
            if not 1024 <= args.port <= 65535:
                raise LiveAgentError("TCP listener port must be 1024..65535")
            state = LiveState(args.output)
            try:
                with LiveTCPServer((args.bind, args.port), key=load_key(args.key_file),
                                   ps4_ip=args.ps4_ip, state=state) as receiver, make_dashboard(state, args.dashboard_port) as dashboard:
                    t = threading.Thread(target=dashboard.serve_forever, daemon=True)
                    t.start()
                    print(f"Receiver: {args.bind}:{receiver.server_address[1]} ; peer allowlist: {args.ps4_ip}")
                    print(f"Local dashboard: http://127.0.0.1:{dashboard.server_port}/")
                    try:
                        receiver.serve_forever()
                    except KeyboardInterrupt:
                        pass
                    finally:
                        dashboard.shutdown()
                        t.join(timeout=3)
            finally:
                state.close()
        return 0
    except (OSError, LiveAgentError, ValueError) as exc:
        print(f"Live Agent: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
