"""Regression tests for offline PS4 RE toolkit: synthetic inputs, no network."""
from __future__ import annotations

import contextlib
from hashlib import sha256
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

from host.ps4_sender.rekit import binary, netmap, nids, orbis, psf, symbols
from host.ps4_sender.rekit.__main__ import main
from host.ps4_sender.psn_netdiag import DiagnosticError


def make_elf(*, elf_type: int = 3) -> bytes:
    data = bytearray(160)
    data[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     elf_type, 62, 1, 0x40, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 100, 100, 16)
    return bytes(data)


def make_psf() -> bytes:
    # The key and data sections are deliberately constructed, never dumped
    # from a retail console or third-party title.
    keys = b"SYSTEM_VER\x00TITLE_ID\x00PATCH_COUNT\x00BLOB\x00"
    values = [b"12.52\x00", b"CUSA00000\x00", struct.pack("<i", 7), b"\x01\x02"]
    entries = []
    keyofs = [0, 11, 20, 32]
    offset = 0
    for keyoff, fmt, value in zip(keyofs, (0x0204, 0x0204, 0x0404, 0x0004), values):
        entries.append(struct.pack("<HHIII", keyoff, fmt, len(value), len(value), offset))
        offset += len(value)
    index = b"".join(entries)
    key_offset = 20 + len(index)
    data_offset = key_offset + len(keys)
    return b"\x00PSF" + struct.pack("<IIII", 0x0101, key_offset, data_offset, 4) + index + keys + b"".join(values)


class BinaryTests(unittest.TestCase):
    def test_generic_elf(self):
        report = binary.inspect_bytes(make_elf())
        self.assertEqual(report["elf_type"], "0x3")
        self.assertEqual(report["program_header_types"], {"PT_LOAD": 1})
        self.assertEqual(report["entry_point"], "0x40")

    def test_orbis_elf(self):
        report = binary.inspect_bytes(make_elf(elf_type=0xFE18))
        self.assertEqual(report["format"], "Orbis ELF64")
        self.assertEqual(report["elf_type"], "ET_SCE_DYNAMIC")

    def test_orbis_aslr_name_from_specification(self):
        report = binary.inspect_bytes(make_elf(elf_type=0xFE10))
        self.assertEqual(report["elf_type"], "ET_SCE_EXEC_ASLR")

    def test_self_container_not_decrypted(self):
        report = binary.inspect_bytes(binary.PS4_SELF_MAGIC + b"\0" * 32)
        self.assertEqual(report["format"], "PS4 SELF container")
        self.assertEqual(report["encrypted_content"], "unknown; not inspected")
        self.assertNotIn("segments", report)

    def test_reject_truncated_or_invalid_file(self):
        for value in (b"", b"\x7fELF", binary.PS4_SELF_MAGIC + b"0" * 12):
            with self.subTest(value=value), self.assertRaises(binary.BinaryFormatError):
                binary.inspect_bytes(value)

    def test_reject_outside_program_table(self):
        data = bytearray(make_elf())
        struct.pack_into("<Q", data, 32, 999999)
        with self.assertRaises(binary.BinaryFormatError):
            binary.inspect_bytes(data)

    def test_reject_outside_segment_content(self):
        data = bytearray(make_elf())
        struct.pack_into("<Q", data, 64 + 32, 500000)
        with self.assertRaises(binary.BinaryFormatError):
            binary.inspect_bytes(data)

    def test_bounded_read(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "too-big.elf"
            path.write_bytes(b"x" * 12)
            with self.assertRaises(binary.BinaryFormatError):
                binary.read_bounded(path, limit=8)


class PSFTests(unittest.TestCase):
    def test_parse_all_types(self):
        data = make_psf()
        result = psf.parse_psf(data)
        self.assertEqual(result["version"], "1.1")
        self.assertEqual(result["values"]["SYSTEM_VER"], "12.52")
        self.assertEqual(result["values"]["TITLE_ID"], "CUSA00000")
        self.assertEqual(result["values"]["PATCH_COUNT"], 7)
        self.assertEqual(result["values"]["BLOB"]["preview_hex"], "0102")
        self.assertEqual(result["sha256"], sha256(data).hexdigest())

    def test_bad_magic_and_version(self):
        for offset, value in ((0, b"NOT!"), (4, b"\x01\x02\x03\x04")):
            data = bytearray(make_psf())
            data[offset:offset + 4] = value
            with self.assertRaises(psf.PSFFormatError):
                psf.parse_psf(data)

    def test_reject_invalid_entry_size(self):
        data = bytearray(make_psf())
        struct.pack_into("<I", data, 20 + 4, 65536)
        with self.assertRaises(psf.PSFFormatError):
            psf.parse_psf(data)

    def test_reject_bad_table_offset(self):
        data = bytearray(make_psf())
        struct.pack_into("<I", data, 8, 300000)
        with self.assertRaises(psf.PSFFormatError):
            psf.parse_psf(data)

    def test_reject_invalid_format(self):
        data = bytearray(make_psf())
        struct.pack_into("<H", data, 20 + 2, 0xFFFE)
        with self.assertRaises(psf.PSFFormatError):
            psf.parse_psf(data)

    def test_reject_psar_not_raw_psf(self):
        with self.assertRaises(psf.PSFFormatError):
            psf.parse_psf(b"PSAR" + b"\x00" * 100)

    def test_reject_entry_outside_data_table(self):
        data = bytearray(make_psf())
        struct.pack_into("<I", data, 20 + 12, 999999)
        with self.assertRaises(psf.PSFFormatError):
            psf.parse_psf(data)


class SymbolTests(unittest.TestCase):
    def test_only_recognizable_symbols_and_nids(self):
        blob = b"jwt_token=should-not-be-output\x00libSceSystemService.sprx\0sceKernelGetSystemSwVersion\0ABCDEFG1234#A#B\0"
        result = symbols.scan_bytes(blob)
        values = [item["name"] for item in result["symbols"]]
        self.assertIn("sceKernelGetSystemSwVersion", values)
        self.assertIn("libSceSystemService.sprx", values)
        self.assertEqual(result["nid_candidates"][0]["name"], "ABCDEFG1234#A#B")
        self.assertNotIn("jwt_token", json.dumps(result))

    def test_dedupe(self):
        report = symbols.scan_bytes(b"sceKernelFoo\0sceKernelFoo\0")
        self.assertEqual(report["total_matches"]["symbol"], 2)
        self.assertEqual(len(report["symbols"]), 1)

    def test_no_raw_string_dump(self):
        self.assertEqual(symbols.scan_bytes(b"some_secret_passphrase\0")["symbols"], [])


class NetworkTests(unittest.TestCase):
    def sample(self):
        return {"format": "fwSpoofer-netmeta-v1", "ps4_ip": "192.168.1.10",
                "counts": {"ipv4_packets": 3, "ps4_outbound_public_ipv4": 2},
                "dns_names": ["example.invalid"], "tls_sni": [], "public_ips": [],
                "events": [{"t": 1.0, "kind": "dns", "dst": "192.168.1.1"},
                           {"t": 1.2, "kind": "tcp_syn", "dst": "203.0.113.2"},
                           {"t": 6.9, "kind": "tls_clienthello", "dst": "203.0.113.2"}]}

    def test_event_timeline(self):
        report = netmap.build_map(self.sample())
        self.assertEqual([bucket["start_s"] for bucket in report["timeline"]], [0, 5])
        self.assertEqual(report["timeline"][0]["events"], {"dns": 1, "tcp_syn": 1})
        self.assertEqual(report["capture_visibility"]["status"], "public_destination_observed")

    def test_reject_tunnel(self):
        with self.assertRaises(DiagnosticError):
            netmap.build_map({"format": "fwSpoofer-tunnel-v1", "events": []})

    def test_bad_events(self):
        with self.assertRaises(DiagnosticError):
            netmap.build_map({**self.sample(), "events": {}})

    def test_diff_is_offline(self):
        a = self.sample()
        b = {**a, "tls_sni": ["example.invalid"]}
        result = netmap.diff_maps(a, b)
        self.assertEqual(result["difference"]["tls_sni_new"], ["example.invalid"])


class CLITests(unittest.TestCase):
    def test_cli_binary_and_psf(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "app.elf").write_bytes(make_elf())
            (directory / "param.sfo").write_bytes(make_psf())
            for cmd, filename in (("binary", "app.elf"), ("psf", "param.sfo"), ("symbols", "app.elf")):
                with self.subTest(cmd=cmd), contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(main([cmd, str(directory / filename)]), 0)
                    self.assertIsInstance(json.loads(out.getvalue()), dict)

    def test_cli_error_does_not_traceback(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["binary", "/path/not/a/file"]), 2)
        self.assertIn("error", err.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
