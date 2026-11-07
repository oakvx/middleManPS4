"""v0.14 end-to-end integration, malformed input and CLI regressions."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from host.ps4_sender.rekit import binary, dynlib, report
from host.ps4_sender.rekit.__main__ import main
from host.ps4_sender.rekit.ghidra_bridge import run_plan
from tests.test_rekit_v13 import make_dynamic_elf


def make_sce_elf():
    data = bytearray(1024)
    data[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     0xFE10, 62, 1, 0x40, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 16)
    table = b"libSceNet.sprx\0ABCDEFG1234#A#B\0libkernel\0"
    tags = [(0x61000035, 0x20), (0x61000037, len(table)),
            (0x61000015, (0x10001 << 32) | 0),
            (0x6100000f, (0x20001 << 32) | (len(table) - len(b"libkernel\0"))),
            (0, 0)]
    for i, (tag, val) in enumerate(tags):
        struct.pack_into("<QQ", data, 0x140 + i*16, tag, val)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 0x140, 0x140, 0,
                     len(tags)*16, len(tags)*16, 8)
    struct.pack_into("<IIQQQQQQ", data, 176, 0x61000000, 4, 0x200, 0x200, 0,
                     0x100, 0x100, 16)
    data[0x220:0x220 + len(table)] = table
    return bytes(data)


class DynlibIntegrationTests(unittest.TestCase):
    def test_strict_scoped_nids_and_library_mapping(self):
        data = make_sce_elf()
        found = dynlib.inspect_bytes(data)
        self.assertTrue(found["table_validated"])
        self.assertEqual(found["scoped_nids_found"], 1)
        self.assertEqual(found["scoped_nids"][0]["file_offset"], hex(0x220 + 15))
        self.assertEqual(found["named_records"][0]["name"], "libSceNet.sprx")
        self.assertEqual(found["named_records"][1]["name"], "libkernel")
        self.assertEqual(found["named_records"][0]["packed_high_32"], hex(0x10001))

    def test_nid_outside_table_not_scoped(self):
        data = bytearray(make_sce_elf())
        data[0x380:0x380+16] = b"ABCDEFGHIJK#B#C\0"
        found = dynlib.inspect_bytes(bytes(data))
        self.assertEqual(found["scoped_nids_found"], 1)
        self.assertEqual(report.analyze_bytes(bytes(data))["nid_scan"]["records_found"], 2)

    def test_reject_dangling_relative_pointer(self):
        data = bytearray(make_sce_elf())
        struct.pack_into("<Q", data, 0x140 + 8, 0xFC)
        with self.assertRaises(binary.BinaryFormatError):
            dynlib.inspect_bytes(bytes(data))

    def test_reject_ambiguous_sce_tags(self):
        data = bytearray(make_sce_elf())
        struct.pack_into("<Q", data, 0x140 + 2*16, 0x61000035)
        with self.assertRaises(binary.BinaryFormatError):
            dynlib.inspect_bytes(bytes(data))

    def test_standard_elf_fallback(self):
        self.assertFalse(dynlib.inspect_bytes(make_dynamic_elf())["table_validated"])

    def test_self_container_not_decrypted(self):
        result = report.analyze_bytes(binary.PS4_SELF_MAGIC + b"\0" * 36)
        self.assertEqual(result["type"], "PS4 SELF container")
        self.assertIsNone(result["dynlib"])


class ReportIntegrationTests(unittest.TestCase):
    @staticmethod
    def inventory():
        return {"format": "middleManPS4-ghidra-v1", "program": "sample.elf",
                "language": "x86:LE:64:default", "local_functions": [],
                "external_functions": [
                    {"name": "sceKernelGetSystemSwVersion", "namespace": "libkernel", "entry": "EXTERNAL:123"},
                    {"name": "sceMissing", "namespace": "libkernel", "entry": "EXTERNAL:124"}]}

    def test_end_to_end_raw_elf_ghidra_and_network(self):
        data = bytearray(make_sce_elf())
        data[0x350:0x350+len(b"sceKernelGetSystemSwVersion\0")] = b"sceKernelGetSystemSwVersion\0"
        network = {"format": "fwSpoofer-netmeta-v1", "ps4_ip": "192.168.1.25",
                   "counts": {"ipv4_packets": 2, "ps4_outbound_public_ipv4": 1},
                   "events": [{"kind": "tcp_syn", "dst": "1.1.1.1", "t": 0.1}],
                   "dns_names": [], "tls_sni": []}
        result = report.analyze_bytes(bytes(data), ghidra=self.inventory(), network=network,
                                      path_name="sample.elf")
        self.assertEqual(result["dynlib"]["scoped_nids_found"], 1)
        self.assertTrue(result["related"]["ghidra"]["source_program_matches_filename"])
        self.assertEqual(result["related"]["ghidra"]["external_name_matches_total"], 1)
        self.assertEqual(result["related"]["network"]["event_count"], 1)
        self.assertTrue(any(x["level"] == "unverified-provenance" for x in result["evidence"]))
        self.assertTrue(any(x["level"] == "not-attributed" for x in result["evidence"]))

    def test_ghidra_disallowed_on_self(self):
        with self.assertRaises(report.ReportError):
            report.analyze_bytes(binary.PS4_SELF_MAGIC + b"\0" * 36,
                                 ghidra=self.inventory())

    def test_psf_dispatch(self):
        from tests.test_rekit import make_psf
        r = report.analyze_bytes(make_psf())
        self.assertEqual(r["type"], "PSF")
        self.assertIsNone(r["orbis"])

    def test_exclusive_report_round_trip_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "out.json"
            data = make_sce_elf()
            case1 = report.analyze_bytes(data)
            report.save_report_exclusive(case1, path)
            loaded = report.load_report(path)
            self.assertEqual(loaded["source"]["sha256"], case1["source"]["sha256"])
            with self.assertRaises(FileExistsError):
                report.save_report_exclusive(case1, path)
            case2 = report.analyze_bytes(make_dynamic_elf())
            diff = report.compare_reports(case1, case2)
            self.assertIn("libkernel", diff["changes"]["libraries"]["removed"])
            self.assertEqual(diff["changes"]["nid_candidates"]["removed_total"], 1)

    def test_markdown_digest_cli_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_file = root / "case.json"
            markdown_file = root / "case.md"
            report.save_report_exclusive(report.analyze_bytes(make_sce_elf()), case_file)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["markdown", str(case_file), "--output", str(markdown_file)]), 0)
            self.assertIn("Offline RE Case", markdown_file.read_text())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["markdown", str(case_file), "--output", str(markdown_file)]), 2)

    def test_batch_rejects_symlink_and_unsafe_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.elf").write_bytes(make_sce_elf())
            (root / "bad.elf").write_bytes(b"\0" * 128)
            batch = report.batch_directory(root)
            self.assertEqual((batch["ok"], batch["failed"]), (1,1))
            with self.assertRaises(report.ReportError):
                report.batch_directory(root, pattern="../*.elf")
            with self.assertRaises(report.ReportError):
                report.batch_directory(root, limit=0)

    def test_cli_analyze_batch_and_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "sample.elf"
            source.write_bytes(make_sce_elf())
            saved = root / "sample-report.json"
            for args in (["dynlib", str(source)],
                         ["analyze", str(source), "--output", str(saved)],
                         ["analyze-diff", str(saved), str(saved)],
                         ["batch", str(root)]):
                with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()) as buffer:
                    self.assertEqual(main(args), 0)
                    self.assertIsInstance(json.loads(buffer.getvalue()), dict)
            self.assertTrue(saved.is_file())
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["analyze", str(source), "--output", str(saved)]), 2)

    def test_run_plan_requires_valid_ghidra_json(self):
        class FakeProcess:
            returncode = 0
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'missing.json'
            plan = {"format": "middleManPS4-ghidra-plan-v1", "argv": ["fake"], "output": str(output)}
            with patch('host.ps4_sender.rekit.ghidra_bridge.subprocess.run', return_value=FakeProcess()):
                result = run_plan(plan)
            self.assertFalse(result["success"])
            self.assertFalse(result["valid_inventory"])
            output.write_text(json.dumps(self.inventory()), encoding="utf-8")
            with patch('host.ps4_sender.rekit.ghidra_bridge.subprocess.run', return_value=FakeProcess()):
                result = run_plan(plan)
            self.assertTrue(result["success"])


if __name__ == '__main__':
    unittest.main()
