"""Host-C regression for Observer; never touches a console or a network."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1"]


@unittest.skipUnless(CC, "host C compiler unavailable")
class ObserverTests(unittest.TestCase):
    def test_success_and_expected_failures(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            include = str(ROOT / "payloads/common/include")
            inputs = [
                ("payloads/common/src/fw_info.c", "info.o", []),
                ("payloads/observer/src/main.c", "observer.o", ["-Dmain=observer_payload_main"]),
                ("tests/c/observer_harness.c", "mock.o", []),
            ]
            for source, output, extra in inputs:
                subprocess.run(
                    [CC, *FLAGS, "-I", include, *extra, "-c", str(ROOT / source),
                     "-o", str(root / output)],
                    check=True, capture_output=True, text=True,
                )
            executable = root / "observer_test"
            subprocess.run(
                [CC, *(str(root / obj) for _, obj, _ in inputs), "-o", str(executable)],
                check=True, capture_output=True, text=True,
            )
            result = subprocess.run(
                [str(executable)], check=True, capture_output=True, text=True,
                timeout=10,
            )
            self.assertIn("observer mock tests: OK", result.stdout)
            self.assertEqual(result.stdout.count("event=heartbeat"), 14)
            self.assertIn("event=complete samples=12", result.stdout)
            self.assertIn("event=error stage=firmware", result.stdout)
            self.assertIn("event=error stage=sleep sample=3", result.stdout)
