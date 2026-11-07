"""Ensure the checked-in archive manifest matches source bytes on every CI OS."""
from __future__ import annotations

import unittest
import hashlib

from scripts.preflight_offline import check_manifest, checkout_hash_matches


class ManifestIntegrityTests(unittest.TestCase):
    def test_windows_crlf_checkout_equivalence(self):
        original = b"a\nb\n"
        expected = hashlib.sha256(original).hexdigest()
        self.assertTrue(checkout_hash_matches(original, expected))
        self.assertTrue(checkout_hash_matches(original.replace(b"\n", b"\r\n"), expected))
        self.assertFalse(checkout_hash_matches(b"a\nchanged\n", expected))
        self.assertFalse(checkout_hash_matches(b"a\x00\r\nb", expected))

    def test_checked_in_source_hashes(self):
        self.assertTrue(check_manifest(), "SHA256SUMS.txt needs regeneration")


if __name__ == "__main__":
    unittest.main()
