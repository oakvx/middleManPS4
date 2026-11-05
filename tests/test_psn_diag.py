"""Contract tests for the read-only Klog PSN diagnostics."""
from __future__ import annotations

import io
import socket
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from host.ps4_sender import psn_diag


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        return self.chunks.pop(0) if self.chunks else b""

    def send(self, *_):
        raise AssertionError("A read-only diagnostic must not send data")

    def sendall(self, *_):
        raise AssertionError("A read-only diagnostic must not send data")


class TestPsnDiag(unittest.TestCase):
    def test_filters_raw_identifiers_and_tokens(self):
        sensitive = b"sceNp auth token=MY_SECRET_TOKEN user=jane@example.org NP-31730-4\n"
        s = psn_diag.collect(FakeSocket([sensitive]), 1, now=lambda: 0)
        formatted = psn_diag.format_summary(s)
        self.assertIn("NP-31730-4 (1)", formatted)
        self.assertIn("Righe con riferimenti PSN/NP: 1", formatted)
        self.assertNotIn("jane", formatted)
        self.assertNotIn("MY_SECRET", formatted)

    def test_fragmented_lines_and_aggregate_counts(self):
        s = psn_diag.collect(FakeSocket([b"sceNp: " , b"connection refused\nsystem software update", b" needed\n"]), 1, now=lambda: 0)
        self.assertEqual((s.lines_seen, s.psn_lines, s.update_lines, s.network_lines), (2, 1, 1, 1))
        self.assertTrue(s.stream_closed)

    def test_empty_stream_is_inconclusive(self):
        s = psn_diag.collect(FakeSocket([]), 1, now=lambda: 0)
        self.assertEqual(s.bytes_received, 0)
        self.assertIn("NON significa", psn_diag.format_summary(s))

    def test_stream_without_newline(self):
        s = psn_diag.collect(FakeSocket([b"firmware check"]), 1, now=lambda: 0)
        self.assertEqual((s.lines_seen, s.update_lines), (1, 1))

    def test_discards_excessively_long_lines(self):
        s = psn_diag.collect(FakeSocket([b"private=" + b"x" * 9000]), 1, now=lambda: 0)
        self.assertGreater(s.truncated_lines, 0)
        self.assertEqual(s.lines_seen, 0)

    def test_no_actual_network_with_invalid_args(self):
        for args in (["--host", "8.8.8.8"], ["--host", "192.168.31.11", "--seconds", "nan"], ["--host", "192.168.31.11", "--seconds", "121"]):
            with self.subTest(args=args), patch.object(psn_diag.socket, "create_connection") as dial, redirect_stderr(io.StringIO()):
                self.assertEqual(psn_diag.main(args), 2)
                dial.assert_not_called()

    def test_fixed_only_klog_port_and_no_payload(self):
        class Conn(FakeSocket):
            def __enter__(self): return self
            def __exit__(self, *_): return None
        conn = Conn([b"sceNp sign in\n"])
        with patch.object(psn_diag.socket, "create_connection", return_value=conn) as dial, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(psn_diag.main(["--host", "192.168.31.11", "--seconds", "1"]), 0)
            self.assertIn("IN ASCOLTO", out.getvalue())
            dial.assert_called_once_with(("192.168.31.11", 3232), timeout=4)

    def test_closed_klog_reports_error(self):
        with patch.object(psn_diag.socket, "create_connection", side_effect=ConnectionRefusedError("refused")), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(psn_diag.main(["--host", "192.168.31.11"]), 1)
            self.assertIn("GoldHEN Klog Server", err.getvalue())


if __name__ == "__main__":
    unittest.main()
