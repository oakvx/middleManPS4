"""CLI regression tests (no network access required)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from host.ps4_sender.cli import main
from host.ps4_sender.transport import TransferReport
from tests.test_elfcheck import fake_elf


class SenderCliTests(unittest.TestCase):
    def test_defaults_to_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test.elf"
            path.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload") as mock_send:
                result = main(["--host", "127.0.0.1", "--file", str(path)])
        self.assertEqual(result, 0)
        mock_send.assert_not_called()

    def test_send_flag_transfers_to_loopback_simulator(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test.elf"
            path.write_bytes(fake_elf())
            report = TransferReport(bytes_sent=path.stat().st_size, sha256="a" * 64)
            with patch("host.ps4_sender.cli.send_payload", return_value=report) as mock_send:
                result = main(["--host", "127.0.0.1", "--port", "9911", "--allow-custom-elfldr-port", "--file", str(path), "--send"])
        self.assertEqual(result, 0)
        mock_send.assert_called_once_with("127.0.0.1", path, 9911, 10.0, payload_bytes=fake_elf(), response_timeout=5.0)

    def test_accepts_elf_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test.elf"
            path.write_bytes(fake_elf())
            result = main(["--host", "127.0.0.1", "--file", str(path)])
        self.assertEqual(result, 0)

    def test_rejects_non_payload_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test.txt"
            path.write_bytes(b"text")
            result = main(["--host", "127.0.0.1", "--file", str(path)])
        self.assertEqual(result, 1)

    def test_rejects_remote_address_even_in_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test.elf"
            path.write_bytes(fake_elf())
            result = main(["--host", "192.0.2.10", "--file", str(path)])
        self.assertEqual(result, 1)

    def test_accepts_private_lan_address(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "test.elf"
            path.write_bytes(fake_elf())
            with patch("host.ps4_sender.cli.send_payload") as mock_send:
                result = main(["--host", "192.168.1.50", "--file", str(path)])
            self.assertEqual(result, 0)
            mock_send.assert_not_called()

    def test_missing_file_returns_error_code(self) -> None:
        result = main(["--host", "127.0.0.1", "--file", "missing-test-payload.bin"])
        self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
