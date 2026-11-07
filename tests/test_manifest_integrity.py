"""Ensure the checked-in archive manifest matches source bytes on every CI OS."""
from __future__ import annotations

import unittest

from scripts.preflight_offline import check_manifest


class ManifestIntegrityTests(unittest.TestCase):
    def test_checked_in_source_hashes(self):
        self.assertTrue(check_manifest(), "SHA256SUMS.txt needs regeneration")


if __name__ == "__main__":
    unittest.main()
