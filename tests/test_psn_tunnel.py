"""No external traffic: PSN CONNECT tunnel contract tests."""
from __future__ import annotations

import contextlib
import io
import socket
import threading
import time
import unittest
from unittest.mock import patch

from host.ps4_sender import psn_tunnel as p


class TunnelTests(unittest.TestCase):
    def test_accepts_only_connect_to_public_port_443(self):
        self.assertEqual(p.public_host_port(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com"), "example.com")
        for text in (
            b"GET http://example.com/ HTTP/1.1", b"CONNECT example.com:80 HTTP/1.1",
            b"CONNECT localhost:443 HTTP/1.1", b"CONNECT router.local:443 HTTP/1.1",
            b"CONNECT 127.0.0.1:443 HTTP/1.1", b"CONNECT 192.168.1.1:443 HTTP/1.1",
            b"CONNECT [::1]:443 HTTP/1.1", b"CONNECT user@example.com:443 HTTP/1.1",
            b"CONNECT example..com:443 HTTP/1.1", b"CONNECT / HTTP/1.1",
            b"CONNECT google.com:443 HTTP/2", b"CONNECT example.com:443 HTTP/1.1\r\nHTTP/1.1",
        ):
            with self.subTest(value=text), self.assertRaises(p.RequestDenied):
                p.public_host_port(text)

    def test_header_parser_preserves_first_tls_bytes(self):
        a, b = socket.socketpair()
        try:
            b.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\nTLS-OPAQUE")
            a.settimeout(1.0)
            headers, tail = p.read_header(a)
            self.assertIn(b"CONNECT", headers)
            self.assertEqual(tail, b"TLS-OPAQUE")
        finally:
            a.close()
            b.close()

    def test_relay_opaque_bytes_without_modification(self):
        client, client_peer = socket.socketpair()
        upstream, upstream_peer = socket.socketpair()
        client.settimeout(2)
        upstream.settimeout(2)
        client_peer.settimeout(2)
        upstream_peer.settimeout(2)
        results = []
        worker = threading.Thread(target=lambda: results.append(p.relay_opaque(client, upstream, b"first", 2)))
        try:
            worker.start()
            self.assertEqual(upstream_peer.recv(5), b"first")
            client_peer.sendall(b"encrypted-request")
            self.assertEqual(upstream_peer.recv(17), b"encrypted-request")
            upstream_peer.sendall(b"encrypted-response")
            self.assertEqual(client_peer.recv(18), b"encrypted-response")
            client_peer.shutdown(socket.SHUT_WR)
            upstream_peer.shutdown(socket.SHUT_WR)
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(results[0], (22, 18))
        finally:
            client.close()
            client_peer.close()
            upstream.close()
            upstream_peer.close()

    def test_private_dns_answers_cannot_be_reached(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch.object(p.socket, "getaddrinfo", return_value=answer), patch.object(p.socket, "socket") as dial:
            with self.assertRaises(p.RequestDenied):
                p.open_public_tcp443("example.com", 2)
            dial.assert_not_called()

    def test_dry_run_does_not_listen(self):
        with patch.object(p, "TunnelServer") as srv, contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(p.main(["--client-ip", "192.168.31.11"]), 0)
            self.assertIn("DRY RUN", out.getvalue())
            srv.assert_not_called()

    def test_lan_bind_requires_explicit_opt_in(self):
        with self.assertRaises(SystemExit) as err, contextlib.redirect_stderr(io.StringIO()):
            p.main(["--client-ip", "192.168.31.11", "--bind", "0.0.0.0", "--serve"])
        self.assertEqual(err.exception.code, 2)

    def test_public_client_is_rejected(self):
        with self.assertRaises(SystemExit) as err, contextlib.redirect_stderr(io.StringIO()):
            p.main(["--client-ip", "8.8.8.8"])
        self.assertEqual(err.exception.code, 2)

    def test_nonnumeric_duration_cannot_start_server(self):
        with self.assertRaises(SystemExit) as err, contextlib.redirect_stderr(io.StringIO()):
            p.main(["--client-ip", "192.168.31.11", "--seconds", "nan", "--serve"])
        self.assertEqual(err.exception.code, 2)

    def test_log_only_contains_metadata(self):
        with patch.object(p.TunnelServer, "__init__", return_value=None):
            srv = object.__new__(p.TunnelServer)
        srv.allowed_client = "192.168.31.11"
        srv.report = None
        srv.write_lock = threading.Lock()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            srv.record({"host": "example.com", "port": 443,
                        "result": "tunneled", "bytes_up": 100, "bytes_down": 200})
            output = out.getvalue()
        self.assertIn("example.com", output)
        self.assertNotIn("token", output.lower())


if __name__ == "__main__":
    unittest.main()

class LocalProxyIntegrationTests(unittest.TestCase):
    def test_real_loopback_connect_without_external_network(self):
        """Simulate one CONNECT using local socketpairs; no Sony/Internet access."""
        srv_sock, peer_sock = socket.socketpair()
        peer_sock.settimeout(2)
        with p.TunnelServer(("127.0.0.1", 0), "127.0.0.1", None, 2) as server:
            worker = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": 0.05}, daemon=True)
            worker.start()
            try:
                with patch.object(p, "open_public_tcp443", return_value=srv_sock), \
                        contextlib.redirect_stdout(io.StringIO()):
                    with socket.create_connection(server.server_address, timeout=2) as client:
                        client.settimeout(2)
                        client.sendall(b"CONNECT test.example:443 HTTP/1.1\r\nHost: test.example\r\n\r\n")
                        self.assertIn(b"200 Connection Established", client.recv(256))
                        client.sendall(b"opaque-hello")
                        self.assertEqual(peer_sock.recv(12), b"opaque-hello")
                        peer_sock.sendall(b"opaque-reply")
                        self.assertEqual(client.recv(12), b"opaque-reply")
            finally:
                server.shutdown()
                worker.join(timeout=2)
                peer_sock.close()
