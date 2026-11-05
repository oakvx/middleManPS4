"""No-network tests for pinned official GitHub artifact retrieval."""
from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from scripts import fetch_official_elfldr as loader


class OfficialReleaseTests(unittest.TestCase):
    def test_default_mode_is_no_network(self):
        with patch.object(loader, 'urlopen') as http:
            with redirect_stdout(io.StringIO()):
                status = loader.main([])
            self.assertEqual(status, 0)
            http.assert_not_called()

    def test_verified_release_writes_atomic_output_and_hash(self):
        data = b'\x55' + b'\x90' * 511
        with tempfile.TemporaryDirectory() as d:
            destination = Path(d) / 'nested' / 'elfldr.bin'
            with patch.object(loader, 'EXPECTED_BYTES', len(data)), \
                 patch.object(loader, 'EXPECTED_SHA256', hashlib.sha256(data).hexdigest()), \
                 patch.object(loader, 'urlopen') as http:
                http.return_value.__enter__.return_value.read.return_value = data
                digest, size = loader.fetch_and_verify(destination)
            self.assertEqual(size, len(data))
            self.assertEqual(destination.read_bytes(), data)
            self.assertEqual(digest, hashlib.sha256(data).hexdigest())
            self.assertIn(digest, destination.with_name('elfldr.bin.sha256').read_text())

    def test_wrong_digest_does_not_overwrite_existing(self):
        data = b'X' * 512
        with tempfile.TemporaryDirectory() as d:
            destination = Path(d) / 'elfldr.bin'
            destination.write_bytes(b'old-good-file')
            with patch.object(loader, 'EXPECTED_BYTES', len(data)), \
                 patch.object(loader, 'urlopen') as http:
                http.return_value.__enter__.return_value.read.return_value = data
                with self.assertRaisesRegex(ValueError, 'HASH MISMATCH'):
                    loader.fetch_and_verify(destination)
            self.assertEqual(destination.read_bytes(), b'old-good-file')
            self.assertFalse((Path(d) / 'elfldr.bin.sha256').exists())

    def test_wrong_length_does_not_write(self):
        with tempfile.TemporaryDirectory() as d:
            destination = Path(d) / 'elfldr.bin'
            with patch.object(loader, 'urlopen') as http:
                http.return_value.__enter__.return_value.read.return_value = b'\x90' * 120
                with self.assertRaisesRegex(ValueError, 'length'):
                    loader.fetch_and_verify(destination)
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
