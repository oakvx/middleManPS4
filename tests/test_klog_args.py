import unittest
from unittest.mock import patch
from host.ps4_sender.klog import main


class KlogArgsTests(unittest.TestCase):
    def test_nan_duration_rejected_without_connect(self):
        with patch("host.ps4_sender.klog.socket.create_connection") as connect:
            self.assertEqual(main(["--host", "192.168.1.5", "--seconds", "nan"]), 2)
            connect.assert_not_called()

    def test_public_target_rejected_without_connect(self):
        with patch("host.ps4_sender.klog.socket.create_connection") as connect:
            self.assertEqual(main(["--host", "8.8.8.8"]), 2)
            connect.assert_not_called()

    def test_one_shot_port_refused(self):
        with patch("host.ps4_sender.klog.socket.create_connection") as connect:
            self.assertEqual(main(["--host", "192.168.1.5", "--port", "9020"]), 2)
            connect.assert_not_called()

    def test_loader_9090_refused(self):
        with patch("host.ps4_sender.klog.socket.create_connection") as connect:
            self.assertEqual(main(["--host", "192.168.1.5", "--port", "9090"]), 2)
            connect.assert_not_called()
