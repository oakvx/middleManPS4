"""End-to-end local TCP doubles for upstream elfldr v0.7's response channel.

The upstream elfldr reuses the accepted socket for spawned stdout/stderr and
for its error strings. Tests do not contact the PS4.
"""
from __future__ import annotations

import io
import socket
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from host.ps4_sender.cli import main
from host.ps4_sender.transport import send_payload, MAX_RESPONSE_SIZE
from tests.test_elfcheck import fake_elf


def run_server(testcase: unittest.TestCase, payload: bytes, reply: bytes, fn):
    """Run one localhost server; read until SHUT_WR and then return reply."""
    received = bytearray()
    errors = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(5)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def worker():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(5)
                    while chunk := conn.recv(4096):
                        received.extend(chunk)
                    if reply:
                        conn.sendall(reply)
            except OSError as e:
                errors.append(str(e))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        result = fn(port)
        thread.join(timeout=6)
        testcase.assertFalse(thread.is_alive(), 'server waiting on socket EOF')
        testcase.assertFalse(errors, errors)
        testcase.assertEqual(bytes(received), payload)
        return result


class ElfldrFeedbackTests(unittest.TestCase):
    def test_half_close_then_capture_stdout_and_stderr(self):
        payload = fake_elf()
        reply = b'[payload] hello_world started\n[payload] notification result: 0\n'
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'payload.elf'
            path.write_bytes(payload)
            report = run_server(self, payload, reply, lambda port: send_payload(
                '127.0.0.1', path, port, response_timeout=2.0
            ))
        self.assertEqual(report.bytes_sent, len(payload))
        self.assertEqual(report.response, reply)
        self.assertTrue(report.response_complete)
        self.assertFalse(report.response_truncated)
        self.assertIsNone(report.response_error)

    def test_empty_reply_still_finishes(self):
        payload = fake_elf()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'payload.elf'
            path.write_bytes(payload)
            report = run_server(self, payload, b'', lambda port: send_payload(
                '127.0.0.1', path, port, response_timeout=2.0
            ))
        self.assertEqual(report.response, b'')
        self.assertTrue(report.response_complete)

    def test_cli_detects_explicit_elfldr_failure(self):
        payload = fake_elf()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'payload.elf'
            path.write_bytes(payload)
            output = io.StringIO()
            error = io.StringIO()
            def run(port):
                with redirect_stdout(output), redirect_stderr(error):
                    return main(['--host', '127.0.0.1', '--loader', 'elfldr',
                                 '--port', str(port), '--allow-custom-elfldr-port', '--file', str(path), '--send'])
            status = run_server(self, payload, b'[elfldr.elf] Error spawning payload\n\x00', run)
        self.assertEqual(status, 2)
        self.assertIn('Error spawning payload', output.getvalue())
        self.assertIn('explicit load/spawn error', error.getvalue())

    def test_cli_dry_run_rejects_truncated_elf(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'bad.elf'
            path.write_bytes(b'\x7fELF')
            with redirect_stderr(io.StringIO()):
                status = main(['--host', '127.0.0.1', '--file', str(path)])
        self.assertEqual(status, 1)

    def test_nonfinite_capture_timeout_rejected_without_network(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'payload.elf'
            path.write_bytes(fake_elf())
            with redirect_stderr(io.StringIO()):
                status = main(['--host', '127.0.0.1', '--file', str(path),
                               '--response-timeout', 'nan', '--send'])
        self.assertEqual(status, 1)

    def test_large_remote_output_bounded(self):
        payload = fake_elf()
        reply = b'e' * (MAX_RESPONSE_SIZE + 8192)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'payload.elf'
            path.write_bytes(payload)
            report = run_server(self, payload, reply, lambda port: send_payload(
                '127.0.0.1', path, port, response_timeout=2.0
            ))
        self.assertLessEqual(len(report.response), MAX_RESPONSE_SIZE)
        self.assertTrue(report.response_truncated)


if __name__ == '__main__':
    unittest.main()
