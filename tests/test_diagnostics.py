import unittest
from unittest.mock import patch
from host.ps4_sender.diagnostics import main, probe


class DiagnosticsTests(unittest.TestCase):
    def test_connect_only_and_no_requirement(self):
        with patch("host.ps4_sender.diagnostics.probe", return_value=False) as fn:
            self.assertEqual(main(["--host", "192.168.1.5", "--port", "9021"]), 0)
        fn.assert_called_once_with("192.168.1.5", 9021, 1.5)

    def test_required_port_fails_if_closed(self):
        with patch("host.ps4_sender.diagnostics.probe", return_value=False):
            self.assertEqual(main(["--host", "192.168.1.5", "--port", "9021", "--require-open"]), 1)

    def test_public_host_rejected(self):
        self.assertEqual(main(["--host", "8.8.8.8", "--port", "9021"]), 2)

    def test_one_shot_port_rejected_without_connect(self):
        with patch("host.ps4_sender.diagnostics.probe") as fn:
            self.assertEqual(main(["--host", "192.168.1.5", "--port", "9020"]), 2)
            fn.assert_not_called()
        with self.assertRaises(ValueError):
            probe("192.168.1.5", 9020)

class InvalidProbeArgsTests(unittest.TestCase):
    def test_nan_timeout_does_not_probe(self):
        with patch("host.ps4_sender.diagnostics.probe") as probe_mock:
            self.assertEqual(main(["--host", "192.168.1.5", "--port", "9021",
                                   "--timeout", "nan"]), 2)
            probe_mock.assert_not_called()

    def test_infinite_timeout_does_not_probe(self):
        with patch("host.ps4_sender.diagnostics.probe") as probe_mock:
            self.assertEqual(main(["--host", "192.168.1.5", "--port", "9021",
                                   "--timeout", "inf"]), 2)
            probe_mock.assert_not_called()

    def test_refuses_binloader_ports_without_connect(self):
        for port in (9020, 9026, 9090):
            with self.subTest(port=port):
                with patch("host.ps4_sender.diagnostics.probe") as probe_mock:
                    self.assertEqual(main(["--host", "192.168.1.5", "--port", str(port)]), 2)
                    probe_mock.assert_not_called()

    def test_default_only_probes_9021(self):
        with patch("host.ps4_sender.diagnostics.probe", return_value=True) as probe_mock:
            self.assertEqual(main(["--host", "192.168.1.5"]), 0)
            probe_mock.assert_called_once_with("192.168.1.5", 9021, 1.5)

    def test_direct_probe_does_not_bypass_restrictions(self):
        for port in (9020, 9026, 9090):
            with self.subTest(port=port):
                with patch("host.ps4_sender.diagnostics.socket.create_connection") as connection:
                    with self.assertRaises(ValueError):
                        probe("192.168.1.5", port)
                    connection.assert_not_called()
