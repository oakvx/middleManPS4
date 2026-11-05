"""Passive-only TShark metadata analyzer tests (no capture or external network)."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from host.ps4_sender import psn_netdiag as n


PS4 = "192.168.31.11"


def row(*values):
    data = list(values)
    return "\t".join(str(x) for x in data + [""] * (len(n.FIELDS) - len(data)))


SAMPLE = "\n".join((
    row("0.112", PS4, "192.168.31.1", "53", "example.com", "", "", "", "", ""),
    row("0.220", PS4, "93.184.215.14", "443", "", "", "", "1", "", ""),
    row("0.320", PS4, "93.184.215.14", "443", "", "1", "example.com", "", "", ""),
    row("0.520", "93.184.215.14", PS4, "", "", "", "", "", "1", ""),
    row("0.620", PS4, "93.184.215.14", "443", "", "", "", "", "", "21"),
    row("0.700", "192.168.31.99", "93.184.215.14", "443", "private@example.org", "", "", "", "", ""),
))


class NetDiagTests(unittest.TestCase):
    def test_extracts_only_ps4_dns_tls_tcp_metadata(self):
        s = n.summarise_tshark(SAMPLE, PS4)
        self.assertEqual(s["counts"], {"dns": 1, "tcp_syn": 1, "tls_clienthello": 1,
                                        "tcp_rst": 1, "tls_alert": 1})
        self.assertEqual(s["dns_names"], ["example.com"])
        self.assertEqual(s["tls_sni"], ["example.com"])
        self.assertNotIn("private@example.org", json.dumps(s))
        self.assertEqual(len(s["events"]), 5)

    def test_invalid_dns_not_persisted(self):
        s = n.summarise_tshark(row("0.1", PS4, "1.1.1.1", "53", "token=SECRET@domain.org"), PS4)
        self.assertEqual(s["dns_names"], [])
        self.assertNotIn("SECRET", json.dumps(s))

    def test_bad_times_rejected(self):
        s = n.summarise_tshark(row("nan", PS4, "1.1.1.1", "53", "example.com") + "\n" +
                                row("-1", PS4, "1.1.1.1", "53", "example.com"), PS4)
        self.assertEqual(s["events"], [])

    def test_comparison_rejects_mismatch_and_detects_new_hosts(self):
        a = n.summarise_tshark(row("0.1", PS4, "1.1.1.1", "53", "first.example"), PS4)
        b = n.summarise_tshark(row("0.1", PS4, "1.1.1.1", "53", "auth.example"), PS4)
        self.assertEqual(n.comparison(a, b)["dns_names_new"], ["auth.example"])
        b["ps4_ip"] = "192.168.31.12"
        with self.assertRaises(n.DiagnosticError):
            n.comparison(a, b)

    def test_read_capture_invokes_offline_tshark(self):
        with tempfile.TemporaryDirectory() as t:
            cap = Path(t) / "capture.pcapng"
            cap.write_bytes(b"fake")
            proc = subprocess.CompletedProcess([], 0, stdout=SAMPLE, stderr="")
            calls = []

            def runner(args, **kwargs):
                calls.append(args)
                return proc

            summary = n.read_capture(cap, PS4, runner=runner, tshark="tshark-test")
            self.assertEqual(summary["counts"]["dns"], 1)
            self.assertIn("-r", calls[0])
            self.assertIn("-T", calls[0])
            self.assertNotIn("-w", calls[0])

    def test_rejects_big_pcap_and_overwrites(self):
        with tempfile.TemporaryDirectory() as t:
            path = Path(t) / "already.json"
            path.write_text("already", encoding="utf-8")
            with self.assertRaises(n.DiagnosticError):
                n.save_summary(path, {})
            cap = Path(t) / "raw.pcapng"
            with cap.open("wb") as f:
                f.truncate(n.MAX_PCAP + 1)
            with self.assertRaises(n.DiagnosticError):
                n.read_capture(cap, PS4, tshark="tshark-test")

    def test_compare_command_does_not_call_tshark(self):
        with tempfile.TemporaryDirectory() as t:
            a = Path(t) / "a.json"
            b = Path(t) / "b.json"
            data = n.summarise_tshark(SAMPLE, PS4)
            a.write_text(json.dumps(data), encoding="utf-8")
            b.write_text(json.dumps(data), encoding="utf-8")
            with patch.object(n, "tshark_path") as tshark, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(n.main(["compare", "--baseline", str(a), "--attempt", str(b)]), 0)
                tshark.assert_not_called()
                self.assertIn("dns_names_new", out.getvalue())

    def test_capture_default_does_not_record_packets(self):
        with tempfile.TemporaryDirectory() as t:
            with patch.object(n, "tshark_path", return_value="tshark"), \
                    patch.object(n.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(n.main(["capture", "--host", PS4, "--interface", "2",
                                         "--seconds", "30", "--summary", str(Path(t) / "test.json")]), 0)
                run.assert_not_called()
                self.assertIn("DRY RUN", out.getvalue())


if __name__ == "__main__":
    unittest.main()

class TunnelCompareTests(unittest.TestCase):
    def test_compare_connect_logs_without_plaintext(self):
        with tempfile.TemporaryDirectory() as t:
            a, b = Path(t) / "baseline.jsonl", Path(t) / "attempt.jsonl"
            a.write_text(json.dumps({"ps4_ip": PS4, "host": "cdn.example.com",
                                     "result": "tunneled", "bytes_up": 15, "bytes_down": 9}) + "\n", encoding="utf-8")
            b.write_text(json.dumps({"ps4_ip": PS4, "host": "auth.example.com",
                                     "result": "tunneled", "bytes_up": 25, "bytes_down": 60}) + "\n", encoding="utf-8")
            compared = n.comparison(n.load_summary(a), n.load_summary(b))
            self.assertEqual(compared["connect_hosts_new"], ["auth.example.com"])
            self.assertNotIn("bytes_up", json.dumps(compared))

    def test_rejects_malformed_proxy_logs(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "bad.jsonl"
            p.write_text('{"host": "example.com"}\n', encoding="utf-8")
            with self.assertRaises(n.DiagnosticError):
                n.load_summary(p)
