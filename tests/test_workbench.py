"""End-to-end offline tests for the integrated research workbench."""
from __future__ import annotations

import contextlib
from hashlib import sha256
import io
import json
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib import error, request

from host.ps4_sender import workbench
from host.ps4_sender.workbench_ui import make_server, render_html
from tests.test_rekit_v14 import make_sce_elf

ROOT = Path(__file__).resolve().parents[1]
OBS = ROOT / "examples/observer_v016_sample.txt"
NET = ROOT / "examples/netmeta_v016_sample.json"


class WorkbenchCaseTests(unittest.TestCase):
    def test_case_from_synthetic_inputs(self):
        result = workbench.build_case(OBS, NET, prompt_second=5)
        self.assertTrue(workbench.verify_case(result))
        self.assertEqual(result["observer"]["status"], "complete")
        self.assertEqual(result["network"]["visibility"]["status"],
                         "public_destination_observed")
        self.assertEqual(result["network"]["before_prompt"], {"dns": 1, "tcp_syn": 1})
        self.assertEqual(result["network"]["after_prompt"], {"tcp_rst": 1,
                                                               "tls_clienthello": 1})
        self.assertEqual(result["capabilities"]["psn_bypass"], "not_implemented")
        self.assertEqual(result["replay"]["events_count"], 4)
        self.assertEqual(len(result["sources"]), 2)

    def test_replay_is_deterministic_and_metadata_only(self):
        events = [{"t": 5.1, "kind": "dns", "token": "SECRET"},
                  {"t": 2.0, "kind": "tcp_syn", "host": "private.host"},
                  {"t": 5.3, "kind": "dns"}]
        output = workbench.replay_metadata(events)
        self.assertEqual([x["start_second"] for x in output["frames"]], [0, 5])
        self.assertEqual(output["frames"][1]["counts"], {"dns": 2})
        self.assertNotIn("SECRET", str(output))
        self.assertNotIn("private.host", str(output))

    def test_unhashable_event_kind_ignored_on_import(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "meta.json"
            data = json.loads(NET.read_text())
            data["events"].append({"t": 1, "kind": ["not-hashable"]})
            file.write_text(json.dumps(data))
            output = workbench.build_case(OBS, file)
            self.assertEqual(output["replay"]["events_count"], 4)

    def test_no_untrusted_network_fields_in_report(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "meta.json"
            data = json.loads(NET.read_text())
            data["events"].append({"kind": "dns", "t": 7.2,
                                   "token": "DO_NOT_EXPORT", "host": "SECRET.HOST",
                                   "dst": "1.2.3.4"})
            file.write_text(json.dumps(data))
            output = workbench.build_case(OBS, file, prompt_second=5)
            rendered = json.dumps(output)
            for secret in ("DO_NOT_EXPORT", "SECRET.HOST", "1.2.3.4"):
                self.assertNotIn(secret, rendered)

    def test_missing_observer_and_network_states(self):
        output = workbench.build_case(None, NET)
        self.assertIsNone(output["observer"])
        self.assertIsNone(output["network"]["before_prompt"])
        self.assertTrue(any(row["level"] == "unknown"
                            for row in output["recommendations"]))
        no_network = workbench.build_case(OBS, None)
        self.assertIsNone(no_network["network"])
        with self.assertRaises(workbench.WorkbenchError):
            workbench.build_case(None, None)
        with self.assertRaises(workbench.WorkbenchError):
            workbench.build_case(OBS, None, prompt_second=2)

    def test_invalid_marker(self):
        for bad in (float("nan"), float("inf"), -1, 5000):
            with self.subTest(marker=bad), self.assertRaises(workbench.WorkbenchError):
                workbench.build_case(OBS, NET, prompt_second=bad)

    def test_replay_bad_shapes(self):
        for event in ({"t": -1, "kind": "dns"}, {"t": float("nan"), "kind": "dns"},
                      {"t": 0, "kind": "forbidden"}, {"t": 0, "kind": ["dns"]}):
            with self.subTest(event=str(event)), self.assertRaises(
                    (workbench.WorkbenchError, TypeError)):
                workbench.replay_metadata([event])
        with self.assertRaises(workbench.WorkbenchError):
            workbench.replay_metadata([], interval=0)
        bad = {"t": 2, "kind": ["not-hashable"]}
        with self.assertRaises(workbench.WorkbenchError):
            workbench.replay_metadata([bad])

    def test_input_size_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            oversize = Path(directory) / "observer.log"
            oversize.write_bytes(b"X" * (workbench.MAX_OBSERVER + 1))
            with self.assertRaises(workbench.WorkbenchError):
                workbench.build_case(oversize, NET)

    def test_report_integrity_and_exclusive_writes(self):
        payload = workbench.build_case(OBS, NET, prompt_second=5)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "case.json"
            workbench.save_new(out, payload)
            self.assertTrue(workbench.verify_case(workbench.load_case(out)))
            with self.assertRaises(FileExistsError):
                workbench.save_new(out, payload)
            tampered = dict(payload)
            tampered["prompt_second_manual"] = 22
            self.assertFalse(workbench.verify_case(tampered))
            out.write_text(json.dumps(tampered))
            with self.assertRaises(workbench.WorkbenchError):
                workbench.load_case(out)

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.json"
            args = ["case", "--observer", str(OBS), "--network", str(NET),
                    "--prompt-second", "5", "--output", str(path)]
            self.assertEqual(workbench.main(args), 0)
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(workbench.main(["verify", "--report", str(path)]), 0)
            self.assertIn('"verified": true', stdout.getvalue())
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(workbench.main(["explain", "--report", str(path)]), 0)
            self.assertIn("deterministic_rules", stdout.getvalue())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(workbench.main(args), 2)


class FirmwareDiffTests(unittest.TestCase):
    def test_compare_two_bounded_elf_metadata_fixtures(self):
        a = bytearray(make_sce_elf())
        b = bytearray(make_sce_elf())
        # An ELF program-header-neutral change; fingerprints must differ.
        b[0x380] = 65
        with tempfile.TemporaryDirectory() as directory:
            before = Path(directory) / "before.elf"
            after = Path(directory) / "after.elf"
            before.write_bytes(a)
            after.write_bytes(b)
            result = workbench.compare_firmware(before, after)
            self.assertTrue(workbench.verify_case(result))
            self.assertNotEqual(result["before"]["sha256"], result["after"]["sha256"])
            self.assertEqual(result["kind"], "firmware_diff")
            self.assertIn("changes", result)
            self.assertIn("No SELF decryption", " ".join(result["limitations"]))

    def test_diff_rejects_invalid_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.bin"
            path.write_bytes(b"NOT AN ELF")
            with self.assertRaises(ValueError):
                workbench.compare_firmware(path, path)


class AssistantTests(unittest.TestCase):
    def test_rule_assistant_no_model_and_no_network(self):
        result = workbench.rule_explain(workbench.build_case(OBS, NET))
        self.assertEqual(result["mode"], "deterministic_rules")
        self.assertNotIn("text", result)
        self.assertNotIn("token", json.dumps(result))

    def test_optional_ollama_is_explicit_and_only_sanitized(self):
        case = workbench.build_case(OBS, NET)
        class MockReply:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self, count):
                return b'{"response":"Check the gateway first."}'
        seen = []
        def fake_open(req, timeout):
            seen.append((req.full_url, req.data.decode()))
            return MockReply()
        class MockOpener:
            def open(self, req, timeout):
                return fake_open(req, timeout)
        with patch("host.ps4_sender.workbench.request.build_opener", return_value=MockOpener()):
            result = workbench.local_model_explain(case, "qwen2.5:3b")
        self.assertEqual(result["mode"], "optional_local_ollama")
        self.assertEqual(seen[0][0], "http://127.0.0.1:11434/api/generate")
        self.assertNotIn("192.168.", seen[0][1])
        self.assertNotIn("123 firmware", seen[0][1])
        with self.assertRaises(workbench.WorkbenchError):
            workbench.local_model_explain(case, "http://other-host/model")


class DashboardTests(unittest.TestCase):
    def test_html_escapes_untrusted_commentary(self):
        case = workbench.build_case(OBS, NET)
        body = {k: v for k, v in case.items() if k != "integrity"}
        body["recommendations"][0]["finding"] = '<script>alert("unsafe")</script>'
        altered = workbench._seal(body)
        html = render_html(altered)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("middleManPS4", html)

    def test_local_bind_and_read_only_routes(self):
        case = workbench.build_case(OBS, NET)
        server = make_server(case, 0)
        self.assertEqual(server.server_address[0], "127.0.0.1")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = "http://127.0.0.1:" + str(server.server_port)
            with request.urlopen(url + "/", timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(b"middleManPS4", response.read())
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
            with request.urlopen(url + "/health", timeout=5) as response:
                self.assertEqual(json.load(response)["ok"], True)
            with self.assertRaises(error.HTTPError) as error_ctx:
                request.urlopen(request.Request(url, data=b"secret", method="POST"), timeout=5)
            self.assertEqual(error_ctx.exception.code, 405)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_unsealed_report_denied(self):
        with self.assertRaises(workbench.WorkbenchError):
            render_html({"kind": "case"})


if __name__ == "__main__":
    unittest.main()
