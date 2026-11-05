"""Offline tests for BD-JB / GoldHEN-specific safeguards."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from host.ps4_sender.cli import main

class BDJBWorkflowTests(unittest.TestCase):
    def test_powershell_script_requires_provenance_acknowledgement(self):
        script = (Path(__file__).resolve().parents[1] / 'scripts/bdjb_send_elfldr.ps1').read_text()
        self.assertIn('9525dc95393ab943758db69a1f49fea6e82f36f2821bf5f41bc00bfc4d6f75df', script)
        self.assertIn('$Send -and -not $AllowCustomLoader', script)
        self.assertIn('if ($ActualHash -ne $ExpectedHash)', script)
        self.assertIn('--accept-bootstrap-risk', script)
        self.assertIn('--allow-custom-bin', script)

    def test_goldhen_rejects_elf_even_in_dry_run(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Path(temp)/'hello_world.elf'
            f.write_bytes(b'\x7fELF'+b'\0'*128)
            with patch('host.ps4_sender.cli.send_payload') as sender:
                rc=main(['--host','127.0.0.1','--loader','goldhen','--file',str(f),'--send'])
            self.assertEqual(rc,1)
            sender.assert_not_called()

    def test_goldhen_bin_dryrun_does_not_send(self):
        with tempfile.TemporaryDirectory() as temp:
            f=Path(temp)/'elfldr.bin'
            f.write_bytes(b'\x55\x48\x89\xe5'+b'\0'*128)
            with patch('host.ps4_sender.cli.send_payload') as sender:
                rc=main(['--host','127.0.0.1','--loader','goldhen','--file',str(f)])
            self.assertEqual(rc,0)
            sender.assert_not_called()

if __name__=='__main__':
    unittest.main()
