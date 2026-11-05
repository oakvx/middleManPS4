"""Compile and run actual project C source with host-only PS4 API mocks.

These tests prove source-level behavior, not on-console ABI compatibility.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O1"]


@unittest.skipUnless(CC, "C compiler unavailable on this test runner")
class CPayloadTests(unittest.TestCase):
    def compile_obj(self, source: Path, object_path: Path, *extra: str) -> None:
        subprocess.run([CC, *FLAGS, *extra, "-c", str(source), "-o", str(object_path)],
                       check=True, capture_output=True, text=True)

    def run_exe(self, out: Path, *objs: Path):
        subprocess.run([CC, *[str(o) for o in objs], "-o", str(out)],
                       check=True, capture_output=True, text=True)
        result = subprocess.run([str(out)], check=True, capture_output=True, text=True,
                                timeout=10)
        self.assertIn("mock tests: OK", result.stdout)

    def test_hello_world_api_call(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            src = ROOT / "payloads/hello_world/src/main.c"
            harness = ROOT / "tests/c/hello_world_harness.c"
            self.compile_obj(src, t / "hello.o", "-Dmain=payload_main")
            self.compile_obj(harness, t / "mock.o")
            self.run_exe(t / "hello_test", t / "hello.o", t / "mock.o")

    def test_fw_info_api_and_control_flow(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d)
            inc = str(ROOT / "payloads/common/include")
            self.compile_obj(ROOT / "payloads/common/src/fw_info.c", t / "info.o",
                             "-I", inc)
            self.compile_obj(ROOT / "payloads/firmware_info/src/main.c", t / "main.o",
                             "-I", inc, "-Dmain=firmware_payload_main")
            self.compile_obj(ROOT / "tests/c/firmware_info_harness.c", t / "mock.o",
                             "-I", inc)
            self.run_exe(t / "info_test", t / "info.o", t / "main.o", t / "mock.o")
