import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from host.ps4_sender.cli import main
from host.ps4_sender.transport import TransferReport
from tests.test_elfcheck import fake_elf


class LoaderCliTests(unittest.TestCase):
    def test_default_elfldr_port(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.elf"
            f.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload",
                       return_value=TransferReport(f.stat().st_size, "a" * 64)) as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--file", str(f), "--send"]), 0)
                send.assert_called_once_with("192.168.1.5", f, 9021, 10.0, payload_bytes=f.read_bytes(), response_timeout=5.0)

    def test_goldhen_bin_port(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.bin"
            f.write_bytes(b"\x55\x48\x89\xe5" + b"\x00" * 64)
            with patch("host.ps4_sender.cli.send_payload",
                       return_value=TransferReport(f.stat().st_size, "a" * 64)) as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--loader", "goldhen",
                                       "--file", str(f), "--expected-sha256", __import__("hashlib").sha256(f.read_bytes()).hexdigest(),
                                       "--accept-bootstrap-risk", "--allow-custom-bin", "--send"]), 0)
                send.assert_called_once_with("192.168.1.5", f, 9090, 10.0, payload_bytes=f.read_bytes(), response_timeout=0.0)

    def test_port_override_cannot_bypass_loader_safety(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.elf"
            f.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload") as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--loader", "elfldr",
                                       "--port", "9090", "--file", str(f), "--send"]), 1)
                send.assert_not_called()

    def test_goldhen_cannot_override_port_9021(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.bin"
            f.write_bytes(b"\x90" * 256)
            with patch("host.ps4_sender.cli.send_payload") as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--loader", "goldhen",
                                       "--port", "9021", "--file", str(f), "--send"]), 1)
                send.assert_not_called()

    def test_one_shot_port_never_used(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.elf"
            f.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload") as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--port", "9020",
                                       "--file", str(f), "--send"]), 1)
                send.assert_not_called()

    def test_renamed_elf_bin_never_sent(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "notflat.bin"
            f.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload") as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--loader", "goldhen",
                                       "--file", str(f), "--send"]), 1)
                send.assert_not_called()

    def test_malformed_elf_never_sent(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "corrupt.elf"
            f.write_bytes(b"\x7fELFbad")
            with patch("host.ps4_sender.cli.send_payload") as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--file", str(f), "--send"]), 1)
                send.assert_not_called()

    def test_custom_elfldr_port_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.elf"
            f.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload") as sender:
                self.assertEqual(main(["--host", "192.168.1.5", "--port", "12345",
                                       "--file", str(f), "--send"]), 1)
                sender.assert_not_called()

    def test_custom_elfldr_port_is_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.elf"
            f.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload",
                       return_value=TransferReport(f.stat().st_size, "a" * 64)) as send:
                self.assertEqual(main(["--host", "192.168.1.5", "--port", "12345", "--allow-custom-elfldr-port",
                                       "--file", str(f), "--send"]), 0)
                send.assert_called_once_with("192.168.1.5", f, 12345, 10.0, payload_bytes=f.read_bytes(), response_timeout=5.0)


if __name__ == "__main__":
    unittest.main()

class HashPinTests(unittest.TestCase):
    def test_expected_hash_match_dry_run(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.bin"
            data = b"\x90" * 256
            f.write_bytes(data)
            expected = hashlib.sha256(data).hexdigest()
            self.assertEqual(main(["--host", "127.0.0.1", "--loader", "goldhen",
                                   "--file", str(f), "--expected-sha256", expected]), 0)

    def test_expected_hash_wrong_never_sends(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.bin"
            f.write_bytes(b"\x90" * 256)
            with patch("host.ps4_sender.cli.send_payload") as sender:
                self.assertEqual(main(["--host", "127.0.0.1", "--loader", "goldhen",
                                       "--file", str(f), "--expected-sha256", "a" * 64,
                                       "--send"]), 1)
                sender.assert_not_called()

    def test_expected_hash_invalid_never_sends(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "x.bin"
            f.write_bytes(b"\x90" * 256)
            with patch("host.ps4_sender.cli.send_payload") as sender:
                self.assertEqual(main(["--host", "127.0.0.1", "--loader", "goldhen",
                                       "--file", str(f), "--expected-sha256", "INVALID",
                                       "--send"]), 1)
                sender.assert_not_called()
