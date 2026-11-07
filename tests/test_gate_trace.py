"""Pure offline regression tests for Observer / PSN prompt event comparison."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from host.ps4_sender.gate_trace import (
    GateTraceError, build_report, main, parse_observer,
)


START = "[middleManPS4/observer] event=start pid=123 firmware=12.520.001 (raw 0x12520001)"
COMPLETE = "[middleManPS4/observer] event=complete samples=12"
GOOD = "\n".join([START] + [f"[middleManPS4/observer] event=heartbeat sample={i}" for i in range(1, 13)] + [COMPLETE])
NETWORK = {"format": "fwSpoofer-netmeta-v1", "ps4_ip": "192.168.31.11",
           "counts": {"ipv4_packets": 14, "ps4_outbound_public_ipv4": 5},
           "dns_names": [], "tls_sni": [], "public_ips": [], "events": [
               {"t": 1.0, "kind": "dns", "host": "dont-export.example"},
               {"t": 4.99, "kind": "tcp_syn", "dst": "1.2.3.4"},
               {"t": 5.0, "kind": "tls_clienthello", "host": "dont-export.example"},
               {"t": 6, "kind": "tcp_rst", "secret": "dont-export-token"},
               {"t": 999, "kind": "dns"},
           ]}


class ObserverTraceTests(unittest.TestCase):
    def test_complete_trace(self):
        result = parse_observer("sender output\n" + GOOD + "\nend output")
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["sequence_verified"])
        self.assertEqual(result["start"]["pid"], 123)
        self.assertEqual(len(result["heartbeats"]), 12)

    def test_absent_trace_rejected(self):
        with self.assertRaises(GateTraceError):
            parse_observer("just terminal text")

    def test_bounded_input(self):
        with self.assertRaises(GateTraceError):
            parse_observer("x" * (256 * 1024 + 1))

    def test_partial_trace_not_declared_complete(self):
        r = parse_observer(START + "\n" + COMPLETE)
        self.assertEqual(r["status"], "incomplete")

    def test_duplicate_or_out_of_order_not_complete(self):
        r = parse_observer(START + "\n" + "\n".join(reversed(GOOD.splitlines()[1:-1])) + "\n" + COMPLETE)
        self.assertFalse(r["sequence_verified"])
        self.assertEqual(r["status"], "incomplete")
        r2 = parse_observer(GOOD + "\n" + START)
        self.assertGreater(r2["unrecognized_observer_lines"], 0)

    def test_completion_first_not_accepted(self):
        r = parse_observer(COMPLETE + "\n" + GOOD)
        self.assertEqual(r["status"], "incomplete")

    def test_malformed_network_event_kind_ignored(self):
        r = build_report(parse_observer(GOOD),
                         dict(NETWORK, events=[{"t": 1.0, "kind": ["dns"]}]),
                         prompt_second=2)
        self.assertEqual(r["network"]["before_prompt"], {})

    def test_firmware_error_without_start(self):
        r = parse_observer("[middleManPS4/observer] event=error stage=firmware code=-1")
        self.assertEqual(r["status"], "error")
        self.assertIsNone(r["start"])

    def test_sanitizes_untrusted_elfldr_output(self):
        r = parse_observer("password=unsafe\n" + START + "\n" +
                           "[middleManPS4/observer] event=hacked token=veryprivate")
        self.assertNotIn("unsafe", str(r))
        self.assertNotIn("veryprivate", str(r))
        self.assertEqual(r["unrecognized_observer_lines"], 1)


class GateReportTests(unittest.TestCase):
    def setUp(self):
        self.observer = parse_observer(GOOD)

    def test_manual_marker_windows_and_metadata_sanitized(self):
        r = build_report(self.observer, NETWORK, prompt_second=5, window_seconds=5)
        net = r["network"]
        self.assertEqual(net["capture_visibility"]["status"], "public_destination_observed")
        self.assertEqual(net["before_prompt"], {"dns": 1, "tcp_syn": 1})
        self.assertEqual(net["after_prompt"], {"tcp_rst": 1, "tls_clienthello": 1})
        self.assertNotIn("dont-export", json.dumps(r))
        self.assertNotIn("1.2.3.4", json.dumps(r))

    def test_no_network_does_not_claim_visibility(self):
        r = build_report(self.observer)
        self.assertIsNone(r["network"])

    def test_zero_events_and_legacy_capture(self):
        r = build_report(self.observer, dict(NETWORK, counts={}, events=[]), prompt_second=5)
        self.assertEqual(r["network"]["capture_visibility"]["status"], "not_measured")
        self.assertEqual(r["network"]["before_prompt"], {})

    def test_no_public_packets_not_called_psn_block(self):
        r = build_report(self.observer, dict(NETWORK, counts={"ipv4_packets": 7,
                                                              "ps4_outbound_public_ipv4": 0}))
        self.assertEqual(r["network"]["capture_visibility"]["status"],
                         "only_nonpublic_or_inbound_observed")

    def test_invalid_offsets_and_formats(self):
        for v in (float("nan"), float("inf"), -1, 4000):
            with self.subTest(v=v), self.assertRaises(GateTraceError):
                build_report(self.observer, NETWORK, prompt_second=v)
        with self.assertRaises(GateTraceError):
            build_report(self.observer, prompt_second=2)
        with self.assertRaises(GateTraceError):
            build_report(self.observer, dict(NETWORK, format="fwSpoofer-tunnel-v1"))
        with self.assertRaises(GateTraceError):
            build_report(self.observer, NETWORK, window_seconds=0)
        with self.assertRaises(GateTraceError):
            build_report(self.observer, NETWORK, window_seconds=float("nan"))

    def test_invalid_counter_and_event_list(self):
        with self.assertRaises(GateTraceError):
            build_report(self.observer, dict(NETWORK, counts={"ipv4_packets": 3,
                                                              "ps4_outbound_public_ipv4": True}))
        with self.assertRaises(GateTraceError):
            build_report(self.observer, dict(NETWORK, events="invalid"))

    def test_cli_report_exclusive_creation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            observer = p / "private-log.txt"
            observer.write_text(GOOD, encoding="utf-8")
            network = p / "sanitized.json"
            network.write_text(json.dumps(NETWORK), encoding="utf-8")
            output = p / "report.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["--observer", str(observer), "--network", str(network),
                             "--prompt-second", "5", "--output", str(output)])
            self.assertEqual(code, 0)
            r = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(r["network"]["before_prompt"]["dns"], 1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--observer", str(observer), "--output", str(output)]), 2)


if __name__ == "__main__":
    unittest.main()
