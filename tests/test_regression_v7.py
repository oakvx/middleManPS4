"""Proof-oriented regressions for failures confirmed in v6; no PS4 is contacted."""
from __future__ import annotations

import hashlib
import io
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from host.ps4_sender.cli import main
from host.ps4_sender.transport import TransferReport
from tests.test_elfcheck import fake_elf


class BootstrapSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'bootstrap.bin'
        self.data = b'\x55\x48\x89\xe5' + b'\x90' * 512
        self.path.write_bytes(self.data)
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.base = ['--host','192.168.1.5','--loader','goldhen','--file',str(self.path)]

    def run_mocked(self, extra):
        with patch('host.ps4_sender.cli.send_payload', return_value=TransferReport(len(self.data),self.digest)) as send, \
                redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            result = main(self.base + extra)
        return result, send

    def test_default_dry_run_does_not_require_risk_consent(self):
        rc, send = self.run_mocked([])
        self.assertEqual(rc, 0)
        send.assert_not_called()

    def test_no_risk_acknowledgement_blocks_real_send(self):
        rc, send = self.run_mocked(['--send','--expected-sha256',self.digest, '--allow-custom-bin'])
        self.assertEqual(rc, 1)
        send.assert_not_called()

    def test_no_checksum_pin_blocks_real_send(self):
        rc, send = self.run_mocked(['--send','--accept-bootstrap-risk','--allow-custom-bin'])
        self.assertEqual(rc, 1)
        send.assert_not_called()

    def test_nonofficial_bin_requires_independent_acknowledgement(self):
        rc, send = self.run_mocked(['--send','--accept-bootstrap-risk','--expected-sha256',self.digest])
        self.assertEqual(rc, 1)
        send.assert_not_called()

    def test_custom_bin_with_all_guards_may_send(self):
        rc, send = self.run_mocked(['--send','--accept-bootstrap-risk','--expected-sha256',self.digest,'--allow-custom-bin'])
        self.assertEqual(rc, 0)
        send.assert_called_once()

    def test_known_official_hash_needs_no_custom_override(self):
        with patch('host.ps4_sender.cli.OFFICIAL_ELFLDR_V07_SHA256',self.digest):
            rc, send = self.run_mocked(['--send','--accept-bootstrap-risk','--expected-sha256',self.digest])
        self.assertEqual(rc, 0)
        send.assert_called_once()

    def test_wrong_pin_blocks_even_with_all_confirmations(self):
        rc, send = self.run_mocked(['--send','--accept-bootstrap-risk','--expected-sha256','0'*64,'--allow-custom-bin'])
        self.assertEqual(rc, 1)
        send.assert_not_called()

    def test_powershell_wrapper_forwards_cli_safety_flags(self):
        ps = (Path(__file__).resolve().parents[1] / 'scripts' / 'bdjb_send_elfldr.ps1').read_text()
        self.assertIn("@('--send','--accept-bootstrap-risk')", ps)
        self.assertIn("$ArgsList += '--allow-custom-bin'", ps)


class ResponseChannelStatus(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'payload.elf'
        self.path.write_bytes(fake_elf())
        self.args = ['--host','192.168.1.5','--loader','elfldr','--file',str(self.path),'--send']

    def run_report(self, report):
        with patch('host.ps4_sender.cli.send_payload',return_value=report), \
                redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()) as out:
            rc = main(self.args)
        return rc,err.getvalue(),out.getvalue()

    def test_receive_error_returns_nonzero_even_if_tcp_send_succeeded(self):
        status,stderr,stdout = self.run_report(TransferReport(len(fake_elf()),'a'*64,response_error='connection reset by peer'))
        self.assertEqual(status,3)
        self.assertIn('output channel failed',stderr)
        self.assertIn('TCP transfer completed',stdout)

    def test_explicit_native_loader_failure_remains_distinct(self):
        status,stderr,_ = self.run_report(TransferReport(len(fake_elf()),'a'*64,response=b'[elfldr.elf] Error spawning payload\n'))
        self.assertEqual(status,2)
        self.assertIn('explicit load/spawn error',stderr)

    def test_no_output_and_no_transport_error_is_unknown_not_failure(self):
        status,_,stdout = self.run_report(TransferReport(len(fake_elf()),'a'*64))
        self.assertEqual(status,0)
        self.assertIn('NOT verified',stdout)


if __name__=='__main__':
    unittest.main()
