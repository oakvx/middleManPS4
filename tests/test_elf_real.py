"""Validate an actual toolchain-produced PIE (not only synthetic headers)."""
from __future__ import annotations
import shutil
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from host.ps4_sender.elfcheck import inspect_path

CC = shutil.which('gcc') or shutil.which('clang')

@unittest.skipUnless(sys.platform.startswith('linux') and CC,
                     'Linux ELF-producing compiler required')
class RealPIEELFTests(unittest.TestCase):
    def test_linux_pie_structure_as_generic_elf_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'fixture.c'
            binfile = Path(d) / 'fixture'
            src.write_text('int main(void) { return 0; }\n')
            subprocess.run([CC, '-fPIE', '-pie', str(src), '-o', str(binfile)],
                           check=True, capture_output=True, timeout=20)
            report = inspect_path(binfile)
            self.assertEqual(report['type'], 'ET_DYN')
            self.assertGreaterEqual(report['section_headers'], 1)
            self.assertGreaterEqual(report['load_segments'], 1)
