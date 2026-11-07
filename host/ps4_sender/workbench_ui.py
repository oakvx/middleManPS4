"""Localhost-only, read-only case dashboard. No external assets or telemetry."""
from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

from .workbench import WorkbenchError, verify_case


STYLE = """*{box-sizing:border-box}body{margin:0;background:#0c121c;color:#e9eff9;
font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1120px;
margin:auto;padding:36px 24px 64px}header{display:flex;gap:18px;align-items:center;
justify-content:space-between;border-bottom:1px solid #2b3b50;padding-bottom:23px;
flex-wrap:wrap}h1{font-size:30px;letter-spacing:-1px;margin:0}h2{font-size:17px;margin:0 0 12px}
p{margin:6px 0;color:#a9bed3}.muted{color:#9fb1c8}small{font-size:12px}
mark{background:#23416a;color:#fff;border-radius:6px;padding:4px 9px}.grid{display:grid;
grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:15px;margin:24px 0}
.card{border:1px solid #2c3c51;background:#131d2b;border-radius:14px;padding:20px;
min-width:0;overflow-wrap:anywhere}.number{font-size:32px;font-weight:750}
.good{color:#70dcba}.warn{color:#ecc07f}.dim{color:#aec0d6}.pill{display:inline-block;
border:1px solid #36546f;border-radius:999px;padding:3px 11px;color:#9fbdd5;font-size:12px}
.timeline{display:grid;gap:9px}.barrow{display:grid;grid-template-columns:70px 1fr 44px;
align-items:center;gap:12px}.track{height:12px;background:#26384d;border-radius:8px;
overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,#44a6cb,#82ddbb);
border-radius:8px}ul{padding-left:20px}li{margin:9px 0}code{color:#b4d3f5}
pre{overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;background:#0b131f;
padding:14px;border-radius:8px;font-size:12px}@media(max-width:600px){
main{padding:20px 14px}.barrow{grid-template-columns:56px 1fr 30px}}
"""


def render_html(case: dict) -> str:
    if not verify_case(case):
        raise WorkbenchError("Unverified case cannot be rendered")
    category = case.get("kind")
    cards = []
    if category == "case":
        observer = case.get("observer") or {}
        network = case.get("network") or {}
        visibility = network.get("visibility") or {}
        cards = [
            ("Observer sequence", str(observer.get("status", "not supplied"))),
            ("Capture visibility", str(visibility.get("status", "not supplied"))),
            ("Metadata events", str(network.get("metadata_events", "not supplied"))),
            ("Firmware gate origin", "undetermined"),
        ]
    elif category == "firmware_diff":
        cards = [
            ("Input A format", str(case["before"]["format"])),
            ("Input B format", str(case["after"]["format"])),
            ("Binary fingerprint", "SHA-256"),
            ("Firmware policy", "unverified"),
        ]
    else:
        raise WorkbenchError("Unsupported report kind")
    card_html = "".join(
        '<article class="card"><small class="muted">' + escape(label) +
        '</small><div class="number" style="font-size:21px">' + escape(value) +
        "</div></article>" for label, value in cards
    )
    rows = []
    if category == "case":
        frames = ((case.get("replay") or {}).get("frames") or [])
        max_count = max((sum(row["counts"].values()) for row in frames), default=1) or 1
        for frame in frames[:100]:
            count = sum(frame["counts"].values())
            width = round(100 * count / max_count)
            rows.append('<div class="barrow"><small>' +
                        escape(str(frame["start_second"])) + '–' +
                        escape(str(frame["end_second"])) + 's</small>' +
                        '<div class="track"><div class="fill" style="width:' +
                        str(width) + '%"></div></div><small>' +
                        str(count) + '</small></div>')
    timeline = "".join(rows) if rows else '<p>No replay frames available.</p>'
    ideas = case.get("recommendations") or []
    bullet_html = "".join('<li><span class="pill">' +
                          escape(str(item["level"])) + '</span> ' +
                          escape(str(item["finding"])) + '<p>Next: ' +
                          escape(str(item["next"])) + '</p></li>' for item in ideas[:15])
    if not bullet_html:
        bullet_html = "<li>Offline binary metadata comparison, not a PSN runtime verdict.</li>"
    limitations = "".join("<li>" + escape(str(item)) + "</li>"
                          for item in case.get("limitations", [])[:12])
    if category == "firmware_diff":
        details = json.dumps(case.get("changes", {}), ensure_ascii=False, indent=2)[:14000]
        timeline = "<pre>" + escape(details) + "</pre>"
    header = "Network timeline" if category == "case" else "Static binary differences"
    return ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>middleManPS4 | Research Console</title><style>' + STYLE +
            '</style></head><body><main><header><div><small class="muted">'
            'PS4 RESEARCH WORKSPACE · OFFLINE</small><h1>middleManPS4</h1>'
            '<p>Evidence-based analysis · local read-only dashboard</p></div>'
            '<span class="pill good">INTEGRITY VERIFIED</span></header>'
            '<section class="grid">' + card_html + '</section>'
            '<section class="card"><h2>' + header + '</h2><div class="timeline">' +
            timeline + '</div></section><section class="grid">'
            '<article class="card"><h2>Analysis assistant (rules)</h2><ul>' +
            bullet_html + '</ul></article><article class="card">'
            '<h2>Evidence limitations</h2><ul>' + limitations +
            '</ul></article></section><footer class="muted"><small>'
            'All analysis is local. No automatic PSN login, firmware spoof, '
            'system process hook or remote telemetry.</small></footer></main></body></html>')


def make_server(case: dict, port: int = 8765) -> ThreadingHTTPServer:
    if type(port) is not int or not 0 <= port <= 65535:
        raise WorkbenchError("Invalid local dashboard port")
    html = render_html(case).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                payload, content_type, status = html, "text/html; charset=utf-8", 200
            elif self.path == "/health":
                payload = json.dumps({"ok": True, "scope": "localhost_only"}).encode("ascii")
                content_type, status = "application/json", 200
            else:
                payload, content_type, status = b"Not found", "text/plain", 404
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            self.send_error(405, "Read-only dashboard")

        def log_message(self, format, *args):
            return

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(case: dict, *, port: int = 8765) -> None:
    with make_server(case, port) as server:
        print(f"middleManPS4 dashboard: http://127.0.0.1:{server.server_port}/",
              flush=True)
        print("Read-only; press Ctrl+C to stop.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
