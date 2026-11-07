import json
from pathlib import Path
import tempfile
import unittest
from host.ps4_sender.psn_triage import triage, main
from host.ps4_sender.psn_netdiag import DiagnosticError


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.base = {'format': 'fwSpoofer-netmeta-v1', 'ps4_ip': '192.168.31.11',
                     'counts': {}, 'dns_names': [], 'tls_sni': [], 'public_ips': []}

    def test_no_capture_does_not_claim_local_gate(self):
        result = triage(self.base, dict(self.base))
        self.assertEqual(result['attempt_events'], 0)
        self.assertIn('NON prova un controllo locale', result['interpretation'])

    def test_new_hosts_are_only_metadata(self):
        attempt = dict(self.base, counts={'tcp_syn': 2}, tls_sni=['auth.example.net'])
        result = triage(self.base, attempt)
        self.assertEqual(result['new_destinations']['tls_sni_new'], ['auth.example.net'])
        self.assertIn('non determinano', result['interpretation'])
        self.assertNotIn('token=', json.dumps(result))

    def test_icmp_only_is_not_internet_visibility(self):
        attempt = dict(self.base,
                       counts={'ipv4_packets': 10, 'ps4_icmp_packets': 10,
                               'ps4_outbound_public_ipv4': 0})
        result = triage(self.base, attempt)
        self.assertEqual(result['capture_visibility']['status'],
                         'only_nonpublic_or_inbound_observed')
        self.assertIn('NON traffico in uscita', result['interpretation'])

    def test_public_packet_observation_is_not_psn_success(self):
        attempt = dict(self.base, counts={'ipv4_packets': 8,
                                         'ps4_outbound_public_ipv4': 3})
        result = triage(self.base, attempt)
        self.assertEqual(result['capture_visibility']['status'], 'public_destination_observed')
        self.assertIn('NON prova accesso PSN', result['interpretation'])

    def test_wrong_format_fails(self):
        with self.assertRaises(DiagnosticError):
            triage(self.base, dict(self.base, format='unknown'))

    def test_wrong_console_fails(self):
        with self.assertRaises(DiagnosticError):
            triage(self.base, dict(self.base, ps4_ip='192.168.31.12'))

    def test_corrupted_input_returns_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp)/'a.json'; b = Path(tmp)/'b.json'
            a.write_text(json.dumps(self.base)); b.write_text('bad file')
            self.assertEqual(main(['--baseline', str(a), '--attempt', str(b)]), 2)

    def test_valid_files_process_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp)/'a.json'; b = Path(tmp)/'b.json'
            a.write_text(json.dumps(self.base)); b.write_text(json.dumps(self.base))
            self.assertEqual(main(['--baseline', str(a), '--attempt', str(b)]), 0)


if __name__ == '__main__':
    unittest.main()
