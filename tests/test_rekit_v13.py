"""Additional v0.13 regression tests; synthetic ELF and no network/console."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from host.ps4_sender.rekit import binary, nids, orbis
from host.ps4_sender.rekit.__main__ import main
from host.ps4_sender.rekit.ghidra_bridge import (
    GhidraBridgeError, diff_inventory, load_inventory, make_plan, summarize_inventory,
)


def make_dynamic_elf() -> bytes:
    data = bytearray(640)
    data[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     0xFE10, 62, 1, 0x40, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, len(data), len(data), 16)
    tags = [(1, 1), (5, 0x1d0), (10, 19), (0, 0)]
    off = 0x140
    for tag, value in tags:
        struct.pack_into("<QQ", data, off, tag, value)
        off += 16
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 0x140, 0x140, 0,
                     len(tags) * 16, len(tags) * 16, 8)
    data[0x1d0:0x1d0 + 19] = b"\0libSceNet.sprx\0xyz"
    return bytes(data)


class OrbisTests(unittest.TestCase):
    def test_resolve_standard_needed(self):
        report = orbis.inspect_bytes(make_dynamic_elf())
        self.assertTrue(report["is_orbis_elf_type"])
        self.assertEqual(report["elf_type"], "ET_SCE_EXEC_ASLR")
        self.assertEqual(report["standard_dt_needed"], ["libSceNet.sprx"])
        self.assertTrue(report["dynamic_terminated"])
        self.assertEqual(report["dynamic_tag_counts"]["DT_NEEDED"], 1)

    def test_unknown_orbis_tag_preserved(self):
        data = bytearray(make_dynamic_elf())
        struct.pack_into("<QQ", data, 0x140, 0x6100000f, 0x123456)
        report = orbis.inspect_bytes(bytes(data))
        self.assertIn("DT_SCE_NEEDED_MODULE", report["dynamic_tag_counts"])
        self.assertEqual(report["standard_dt_needed"], [])

    def test_partial_dynamic_rejected(self):
        data = bytearray(make_dynamic_elf())
        struct.pack_into("<Q", data, 120 + 32, 63)
        with self.assertRaises(binary.BinaryFormatError):
            orbis.inspect_bytes(bytes(data))

    def test_no_dynamic_is_valid(self):
        data = bytearray(make_dynamic_elf())
        struct.pack_into("<I", data, 120, 4)
        report = orbis.inspect_bytes(bytes(data))
        self.assertEqual(report["dynamic_entries"], [])
        self.assertTrue(report["dynamic_terminated"])

    def test_no_bss_reads(self):
        data = bytearray(make_dynamic_elf())
        struct.pack_into("<Q", data, 0x140 + 16 + 8, 0x270)
        self.assertEqual(orbis.inspect_bytes(bytes(data))["standard_dt_needed"], [])

    def test_unterminated_dynamic_marked(self):
        data = bytearray(make_dynamic_elf())
        struct.pack_into("<QQ", data, 0x140 + 48, 0x61000015, 7)
        self.assertFalse(orbis.inspect_bytes(bytes(data))["dynamic_terminated"])

    def test_self_not_decrypted(self):
        with self.assertRaises(binary.BinaryFormatError):
            orbis.inspect_bytes(binary.PS4_SELF_MAGIC + b"\x00" * 64)


class NIDTests(unittest.TestCase):
    def test_layout_indices_offsets(self):
        blob = b"\x00ABCDEFG1234#A#B\0something\0ABCDEFGHIJK#B#C\0"
        r = nids.inventory_bytes(blob)
        self.assertEqual(r["records_found"], 2)
        self.assertEqual(r["records"][0]["library_index"], 0)
        self.assertEqual(r["records"][0]["module_index"], 1)
        self.assertEqual(r["records"][1]["module_index"], 2)

    def test_requires_terminator(self):
        self.assertEqual(nids.inventory_bytes(b"ABCDEFG1234#A#B!")["records_found"], 0)

    def test_no_plaintext_dump(self):
        out = nids.inventory_bytes(b"secret_password=qwerty\0")
        self.assertNotIn("secret", json.dumps(out))


class GhidraBridgeTests(unittest.TestCase):
    def test_safe_command_vector(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "Ghidra"
            (home / "support").mkdir(parents=True)
            (home / "support" / "analyzeHeadless").touch()
            project_dir = root / "project"
            project_dir.mkdir()
            binary_path = root / "test.elf"
            binary_path.write_bytes(make_dynamic_elf())
            report = make_plan(ghidra_home=home, binary=binary_path,
                               output=root / "new.json", project_dir=project_dir,
                               windows=False)
            self.assertFalse(report["executes"])
            self.assertEqual(report["input_elf_type"], "ET_SCE_EXEC_ASLR")
            self.assertEqual(report["argv"].count("-postScript"), 1)
            self.assertIn("ExportREInventory.java", report["argv"])
            self.assertNotIn("shell", report)

    def test_reject_unsafe_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "Ghidra"
            (home / "support").mkdir(parents=True)
            (home / "support" / "analyzeHeadless").touch()
            binary_path = root / "sample.elf"
            binary_path.write_bytes(make_dynamic_elf())
            kwargs = {"ghidra_home": home, "binary": binary_path,
                      "output": root / "new.json", "project_dir": root, "windows": False}
            with self.assertRaises(GhidraBridgeError):
                make_plan(**kwargs, project_name="bad name;cmd")
            (root / "new.json").touch()
            with self.assertRaises(GhidraBridgeError):
                make_plan(**kwargs)
            (root / "new.json").unlink()
            binary_path.write_bytes(binary.PS4_SELF_MAGIC + b"\x00" * 50)
            with self.assertRaises(GhidraBridgeError):
                make_plan(**kwargs)

    @staticmethod
    def sample():
        return {"format": "middleManPS4-ghidra-v1", "program": "test.elf",
                "language": "x86:LE:64:default",
                "local_functions": [{"name": "entry", "namespace": "Global", "entry": "00000040"}],
                "external_functions": [{"name": "sceFoo", "namespace": "libSceExample",
                                        "entry": "EXTERNAL:0001"}]}

    def test_summary_and_diff(self):
        sample = self.sample()
        self.assertEqual(summarize_inventory(sample)["external_functions"], 1)
        changed = json.loads(json.dumps(sample))
        changed["external_functions"][0]["name"] = "sceBar"
        delta = diff_inventory(sample, changed)
        self.assertEqual(delta["external_functions"]["added"], ["libSceExample::sceBar"])
        self.assertEqual(delta["external_functions"]["removed_total"], 1)

    def test_load_and_reject_invalid_records(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventory.json"
            path.write_text(json.dumps(self.sample()))
            self.assertEqual(len(load_inventory(path)["local_functions"]), 1)
            data = self.sample()
            data["local_functions"] = [{"name": None, "namespace": "", "entry": "0x0"}]
            path.write_text(json.dumps(data))
            with self.assertRaises(GhidraBridgeError):
                load_inventory(path)

    def test_cli_orbis_nids_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            (path / "test.elf").write_bytes(make_dynamic_elf())
            (path / "nids.bin").write_bytes(b"ABCDEFG1234#A#B\0")
            (path / "ghidra.json").write_text(json.dumps(self.sample()))
            for cmd, fn in (("orbis", "test.elf"), ("nids", "nids.bin"),
                            ("ghidra-summary", "ghidra.json")):
                with self.subTest(cmd=cmd), contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(main([cmd, str(path / fn)]), 0)
                    self.assertIsInstance(json.loads(out.getvalue()), dict)


if __name__ == "__main__":
    unittest.main()
