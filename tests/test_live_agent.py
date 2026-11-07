"""Host-only validation: authenticated bounded LAN telemetry and C self-agent mocks."""
from __future__ import annotations

import contextlib
from hashlib import sha256
import hmac
from http import client
from pathlib import Path
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib import request, error

from host.ps4_sender.live_agent import (
    LiveAgentError, LiveState, LiveTCPServer, create_config,
    event_signature, json_line, load_key, make_dashboard,
    normalize_event, proof, simulate, valid_private_ipv4,
)

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
KEY = bytes.fromhex("00" * 31 + "01")


class ProtocolTests(unittest.TestCase):
    def test_hmac_proof_matches_reference(self):
        nonce = "0123456789abcdef" * 2
        expected = hmac.new(KEY, b"mmps4-live-v1:" + nonce.encode(), sha256).hexdigest()
        self.assertEqual(proof(KEY, nonce), expected)
        with self.assertRaises(LiveAgentError):
            proof(KEY, "not-hex")

    def test_reject_malformed_key(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / "bad-key"
            file.write_text("not a key")
            with self.assertRaises(LiveAgentError):
                load_key(file)

    def test_private_ipv4_only(self):
        for ip in ("127.0.0.1", "192.168.1.5", "10.23.0.1"):
            self.assertTrue(valid_private_ipv4(ip))
        for ip in ("0.0.0.0", "8.8.8.8", "::1", "192.0.2.1.1", "192.0.2.1", "169.254.1.1"):
            self.assertFalse(valid_private_ipv4(ip))

    def test_authenticated_event_and_non_monotonic_rejected(self):
        nonce = "f" * 32
        raw = {"type": "event", "protocol": 1, "seq": 0, "kind": "heartbeat",
               "pid": 139, "elapsed_ms": 2000, "status": 0}
        raw["mac"] = event_signature(KEY, nonce, raw)
        self.assertEqual(normalize_event(raw, KEY, nonce, 0, 0),
                         {"seq": 0, "kind": "heartbeat", "pid": 139,
                          "elapsed_ms": 2000, "status": 0})
        with self.assertRaises(LiveAgentError):
            normalize_event(raw, KEY, nonce, 1, 0)
        with self.assertRaises(LiveAgentError):
            normalize_event(raw, KEY, nonce, 0, 2500)
        raw["status"] = -200
        with self.assertRaises(LiveAgentError):
            normalize_event(raw, KEY, nonce, 0, 0)

    def test_reject_unknown_and_unhashable_fields(self):
        nonce = "f" * 32
        good = {"type": "event", "protocol": 1, "seq": 0, "kind": "agent_start",
                "pid": 139, "elapsed_ms": 0, "status": 0}
        for key, value in (("kind", ["heartbeat"]), ("pid", True),
                           ("elapsed_ms", -1), ("protocol", True),
                           ("kind", "execve")):
            with self.subTest(field=key):
                frame = dict(good, **{key: value, "mac": "0" * 64})
                with self.assertRaises(LiveAgentError):
                    normalize_event(frame, KEY, nonce, 0, 0)
        extra = {**good, "mac": "0" * 64, "credential": "DO_NOT_STORE"}
        with self.assertRaises(LiveAgentError):
            normalize_event(extra, KEY, nonce, 0, 0)

    def test_frame_limit(self):
        with self.assertRaises(LiveAgentError):
            json_line({"data": "x" * 600})


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.state = LiveState()
        self.receiver = LiveTCPServer(("127.0.0.1", 0), key=KEY,
                                      ps4_ip="127.0.0.1", state=self.state)
        self.thread = threading.Thread(target=self.receiver.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.receiver.shutdown()
        self.receiver.server_close()
        self.thread.join(timeout=5)
        self.state.close()

    def test_simulated_agent_auth_and_bounded_events(self):
        simulate("127.0.0.1", self.receiver.server_address[1], KEY, 5)
        # Handler receives bytes asynchronously; take a short bounded snapshot wait.
        import time
        deadline = time.monotonic() + 2
        while self.state.snapshot()["total_events"] < 7 and time.monotonic() < deadline:
            time.sleep(0.01)
        s = self.state.snapshot()
        self.assertEqual(s["total_events"], 7)
        self.assertEqual(s["events"][0]["kind"], "agent_start")
        self.assertEqual(s["events"][-1]["kind"], "agent_complete")
        self.assertEqual(s["authenticated_sessions"], 1)
        self.assertEqual(s["system_wide_syscalls"], "not_implemented")
        self.assertNotIn("mac", json.dumps(s))
        self.assertNotIn(KEY.hex(), json.dumps(s))

    def test_invalid_pairing_rejected(self):
        with self.assertRaises(LiveAgentError):
            simulate("127.0.0.1", self.receiver.server_address[1], b"X" * 32, 2)
        import time
        deadline = time.monotonic() + 2
        while self.state.snapshot()["rejected_sessions"] == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreaterEqual(self.state.snapshot()["rejected_sessions"], 1)
        self.assertEqual(self.state.snapshot()["total_events"], 0)

    def test_dashboard_local_and_read_only(self):
        with make_dashboard(self.state, 0) as viewer:
            self.assertEqual(viewer.server_address[0], "127.0.0.1")
            thread = threading.Thread(target=viewer.serve_forever, daemon=True)
            thread.start()
            url = "http://127.0.0.1:" + str(viewer.server_port)
            try:
                with request.urlopen(url, timeout=3) as response:
                    self.assertIn(b"Live Agent", response.read())
                    self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                with request.urlopen(url + "/api/snapshot", timeout=3) as response:
                    self.assertEqual(json.load(response)["total_events"], 0)
                with self.assertRaises(error.HTTPError) as ctx:
                    request.urlopen(request.Request(url, data=b"secret", method="POST"), timeout=3)
                self.assertEqual(ctx.exception.code, 405)
            finally:
                viewer.shutdown()
                thread.join(timeout=5)


class ConfigTests(unittest.TestCase):
    def test_generated_local_config_does_not_override(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            k = base / "key.txt"
            h = base / "live_agent_config.h"
            create_config("192.168.1.30", 8768, k, h)
            self.assertEqual(len(load_key(k)), 32)
            self.assertIn("MMPS4_PC_IP", h.read_text())
            self.assertIn(load_key(k).hex(), h.read_text())
            with self.assertRaises(LiveAgentError):
                create_config("192.168.1.30", 8768, k, h)

    def test_invalid_config(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            with self.assertRaises(LiveAgentError):
                create_config("127.0.0.1", 8768, base / "k", base / "h")
            with self.assertRaises(LiveAgentError):
                create_config("192.168.1.33", 10, base / "k", base / "h")


@unittest.skipUnless(CC and sys.platform.startswith("linux"), "Linux C compiler needed")
class HostCTests(unittest.TestCase):
    def test_hmac_known_vectors(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "hmac"
            subprocess.run([CC, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                            "-I", str(ROOT / "payloads/live_agent/include"),
                            str(ROOT / "payloads/live_agent/src/live_crypto.c"),
                            str(ROOT / "tests/c/live_crypto_harness.c"),
                            "-o", str(output)], check=True, capture_output=True, text=True)
            proc = subprocess.run([str(output)], check=True, capture_output=True, text=True)
            self.assertIn("live HMAC tests: OK", proc.stdout)

    def test_compiled_c_agent_to_python_receiver(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            config = base / "live_agent_config.h"
            config.write_text('#define MMPS4_PC_IP "127.0.0.1"\n'
                              f'#define MMPS4_PC_PORT {self._port()}\n'
                              f'#define MMPS4_PAIR_KEY_HEX "{KEY.hex()}"\n')
            # Use the existing project fw_info.c with a host API mock.
            output = base / "agent"
            cmd = [CC, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                   "-I", str(base), "-I", str(ROOT / "payloads/live_agent/include"),
                   "-I", str(ROOT / "payloads/common/include"),
                   str(ROOT / "payloads/live_agent/src/main.c"),
                   str(ROOT / "payloads/live_agent/src/live_crypto.c"),
                   str(ROOT / "payloads/common/src/fw_info.c"),
                   str(ROOT / "tests/c/live_agent_api_mock.c"), "-o", str(output)]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            env = dict(os.environ)
            env.pop("MMPS4_TEST_FAIL_SLEEP", None)
            proc = subprocess.run([str(output)], timeout=15, env=env, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertIn("session ended status=0", proc.stdout)
            import time
            deadline = time.monotonic() + 2
            while self._state().snapshot()["total_events"] < 11 and time.monotonic() < deadline:
                time.sleep(0.01)
            s = self._state().snapshot()
            self.assertEqual(s["total_events"], 11)
            self.assertEqual(s["events"][-1]["kind"], "agent_complete")

    def _port(self):
        # Created below by setUp; test class uses the same receiver context.
        return self.receiver.server_address[1]

    def _state(self):
        return self.state

    def setUp(self):
        self.state = LiveState()
        self.receiver = LiveTCPServer(("127.0.0.1", 0), key=KEY,
                                      ps4_ip="127.0.0.1", state=self.state)
        self.thread = threading.Thread(target=self.receiver.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.receiver.shutdown()
        self.receiver.server_close()
        self.thread.join(timeout=5)
        self.state.close()


if __name__ == "__main__":
    unittest.main()
