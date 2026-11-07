"""Check PKG staging does not pretend to produce an installable package."""
from __future__ import annotations
from pathlib import Path
import tempfile
import unittest
from scripts.build_live_pkg_stage import stage


class PackageStagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.eboot = root / "eboot.bin"
        self.sfo = root / "param.sfo"
        self.icon = root / "icon0.png"
        self.stage_path = root / "pkg-stage"
        self.eboot.write_bytes(b"\x4f\x15\x3d\x1d" + b"\x00" * 64)
        self.sfo.write_bytes(b"\x00PSF" + b"\x00" * 64)
        self.icon.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" +
                              (512).to_bytes(4, "big") * 2 + bytes([8, 2]) + b"\x00" * 32)

    def test_stages_expected_structure_only(self):
        stage(self.eboot, self.sfo, self.icon, self.stage_path)
        self.assertTrue((self.stage_path / "eboot.bin").is_file())
        self.assertTrue((self.stage_path / "sce_sys/param.sfo").is_file())
        self.assertTrue((self.stage_path / "sce_sys/icon0.png").is_file())
        self.assertFalse(list(self.stage_path.rglob("*.pkg")))
        with self.assertRaises(ValueError):
            stage(self.eboot, self.sfo, self.icon, self.stage_path)

    def test_rejects_plain_elf(self):
        self.eboot.write_bytes(b"\x7fELF" + b"\x00" * 64)
        with self.assertRaisesRegex(ValueError, "SELF"):
            stage(self.eboot, self.sfo, self.icon, self.stage_path)

    def test_rejects_wrong_icon(self):
        self.icon.write_bytes(b"not a png")
        with self.assertRaisesRegex(ValueError, "512x512"):
            stage(self.eboot, self.sfo, self.icon, self.stage_path)


if __name__ == "__main__":
    unittest.main()
