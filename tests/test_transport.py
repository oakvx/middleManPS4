
import hashlib
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from host.ps4_sender.transport import (
    read_payload,
    send_payload
)


class TransportTests(unittest.TestCase):

    def test_send_exact_bytes(self):
        payload = b"\x7fELF" + bytes(range(256))
        received = bytearray()

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.elf"
            path.write_bytes(payload)

            with socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            ) as listener:

                listener.bind(("127.0.0.1", 0))
                listener.listen(1)

                port = listener.getsockname()[1]

                def receive():
                    conn, _ = listener.accept()

                    with conn:
                        while chunk := conn.recv(4096):
                            received.extend(chunk)

                worker = threading.Thread(
                    target=receive,
                    daemon=True
                )

                worker.start()

                report = send_payload(
                    "127.0.0.1",
                    path,
                    port=port
                )

                worker.join(timeout=3)

        self.assertFalse(worker.is_alive())
        self.assertEqual(bytes(received), payload)

        self.assertEqual(
            report.bytes_sent,
            len(payload)
        )

        self.assertEqual(
            report.sha256,
            hashlib.sha256(payload).hexdigest()
        )

    def test_empty_payload_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.elf"
            path.write_bytes(b"")

            with self.assertRaises(ValueError):
                read_payload(path)

    def test_missing_payload_rejected(self):
        with self.assertRaises(FileNotFoundError):
            read_payload(
                Path("file-does-not-exist.elf")
            )

    def test_invalid_port_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.bin"
            path.write_bytes(b"abc")

            with self.assertRaises(ValueError):
                send_payload(
                    "127.0.0.1",
                    path,
                    port=0
                )


if __name__ == "__main__":
    unittest.main()

class TransferSnapshotTests(unittest.TestCase):
    def test_snapshot_sent_even_when_file_changes_after_validation(self):
        """Use prevalidated bytes, not a second read of a changed file."""
        source = b"\x90" * 250
        later = b"\xcc" * 250
        captured = bytearray()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "elfldr.bin"
            path.write_bytes(source)
            validated = read_payload(path)
            path.write_bytes(later)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]

                def receive():
                    connection, _ = listener.accept()
                    with connection:
                        while chunk := connection.recv(4096):
                            captured.extend(chunk)

                worker = threading.Thread(target=receive, daemon=True)
                worker.start()
                result = send_payload("127.0.0.1", path, port=port,
                                      payload_bytes=validated)
                worker.join(timeout=3)
                self.assertFalse(worker.is_alive())
        self.assertEqual(bytes(captured), source)
        self.assertEqual(result.sha256, hashlib.sha256(source).hexdigest())
