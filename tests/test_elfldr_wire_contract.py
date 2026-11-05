"""Regression tests against elfldr v0.7's published ELF TCP reader behavior.

Based on https://github.com/ps4-payload-dev/elfldr/blob/v0.7/elfldr.c
These are host-side simulation checks, not execution on a PlayStation.
"""
from __future__ import annotations

import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from host.ps4_sender.elfcheck import ELFError, inspect_elf
from host.ps4_sender.transport import send_payload
from tests.test_elfcheck import fake_elf


def add_relocations(data: bytes, targets: list[int]):
    payload = bytearray(data)
    new_shoff = len(payload)
    payload.extend(b'\x00' * (64 * 2))
    reloff = len(payload)
    for target in targets:
        payload.extend(struct.pack('<QQq', target, 8, 0))
    struct.pack_into('<Q', payload, 40, new_shoff)
    struct.pack_into('<HH', payload, 58, 64, 2)
    struct.pack_into('<IIQQQQIIQQ', payload, new_shoff + 64,
                     0, 4, 0, 0, reloff, 24 * len(targets), 0, 0, 8, 24)
    return bytes(payload)


class NativeLoaderContractTests(unittest.TestCase):
    def test_rejects_zero_section_headers_not_handled_by_native_reader(self):
        data = bytearray(fake_elf())
        struct.pack_into('<Q', data, 40, 0)
        struct.pack_into('<H', data, 60, 0)
        with self.assertRaisesRegex(ELFError, 'section header table'):
            inspect_elf(bytes(data))

    def test_rejects_bad_section_entry_size(self):
        data = bytearray(fake_elf())
        struct.pack_into('<H', data, 58, 40)
        with self.assertRaisesRegex(ELFError, 'section header table'):
            inspect_elf(bytes(data))

    def test_rejects_min_vaddr_other_than_zero(self):
        with self.assertRaisesRegex(ELFError, 'minimum virtual address'):
            inspect_elf(fake_elf(vaddr=0x1000, entry=0x1090))

    def test_rejects_file_segment_unread_by_upstream(self):
        # Native reader stops at section data end (240 bytes), leaving
        # a PT_LOAD whose referenced file content ends at byte 264 unread.
        data = bytearray(fake_elf(filesz=300, memsz=400))
        data.extend(b'\x00' * 100)
        with self.assertRaisesRegex(ELFError, 'not fully received'):
            inspect_elf(bytes(data))

    def test_rejects_relocation_write_past_image(self):
        with self.assertRaisesRegex(ELFError, 'relocation target outside'):
            inspect_elf(add_relocations(fake_elf(), [0x1ff]))

    def test_rejects_relocation_write_in_gap(self):
        with self.assertRaisesRegex(ELFError, 'relocation target outside'):
            inspect_elf(add_relocations(fake_elf(memsz=0x200), [0x200]))

    def test_accepts_valid_relative_relocation(self):
        report = inspect_elf(add_relocations(fake_elf(), [0x1f0]))
        self.assertEqual(report['section_headers'], 2)

    def test_accepts_relative_relocation_negative_addend(self):
        # The addend is a signed computation operand, not a memory write
        # location. Only r_offset must be checked against PT_LOAD.
        data = bytearray(add_relocations(fake_elf(), [0x1f0]))
        struct.pack_into('<q', data, len(data) - 8, -8)
        report = inspect_elf(bytes(data))
        self.assertEqual(report['relative_addends_outside_load'], 1)

    def test_accepts_relative_relocation_large_addend(self):
        data = bytearray(add_relocations(fake_elf(), [0x1f0]))
        struct.pack_into('<q', data, len(data) - 8, 0x700000)
        report = inspect_elf(bytes(data))
        self.assertEqual(report['relative_addends_outside_load'], 1)

    def test_rejects_huge_image(self):
        with self.assertRaisesRegex(ELFError, 'image exceeds'):
            inspect_elf(fake_elf(memsz=65 * 1024 * 1024))

    def test_rejects_huge_address_on_non_load_header(self):
        buf = bytearray(fake_elf())
        # PT_DYNAMIC, though not a load segment, contributes to the
        # original elfldr.c mapping size; reject the oversized span.
        struct.pack_into('<Q', buf, 64 + 56 + 16, 0x90000000)
        with self.assertRaisesRegex(ELFError, 'image exceeds'):
            inspect_elf(bytes(buf))

    def test_rejects_elf_tail_that_would_be_inherited_as_stdin(self):
        p = fake_elf() + b"TRAILING_BYTES_STDIN"
        with self.assertRaisesRegex(ELFError, "unread ELF trailing bytes"):
            inspect_elf(p)

    def test_reports_exact_reader_consumption(self):
        data = fake_elf()
        report = inspect_elf(data)
        self.assertEqual(report['elfldr_read_bytes'], len(data))

    def test_realistic_reader_simulator_and_sender(self):
        data = add_relocations(fake_elf(), [0x1f0])
        self.assertEqual(inspect_elf(data)['elfldr_read_bytes'], len(data))
        reply = b'[payload] main called\n'
        ready = threading.Event()
        received = bytearray()
        port_holder: list[int] = []
        errors: list[BaseException] = []

        def read_exact(conn, amount):
            result = bytearray()
            while len(result) < amount:
                chunk = conn.recv(amount - len(result))
                if not chunk:
                    raise AssertionError('Incomplete ELF upload')
                result.extend(chunk)
            return bytes(result)

        def worker():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(1)
                    port_holder.append(listener.getsockname()[1])
                    ready.set()
                    conn, _addr = listener.accept()
                    with conn:
                        conn.settimeout(4)
                        header = read_exact(conn, 64)
                        shoff = struct.unpack_from('<Q', header, 40)[0]
                        shnum = struct.unpack_from('<H', header, 60)[0]
                        initial = shoff + shnum * 64
                        body = read_exact(conn, initial - 64)
                        received.extend(header + body)
                        total = initial
                        for i in range(shnum):
                            base = shoff + i * 64
                            _name, kind, _flags, _addr, offset, size, *_ = struct.unpack_from(
                                '<IIQQQQIIQQ', received, base)
                            if kind != 8:
                                total = max(total, offset + size)
                        received.extend(read_exact(conn, total - initial))
                        conn.sendall(reply)
            except BaseException as exc:
                errors.append(exc)
                ready.set()

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'payload.elf'
            path.write_bytes(data)
            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            self.assertTrue(ready.wait(timeout=3))
            self.assertTrue(port_holder, errors)
            report = send_payload('127.0.0.1', path, port_holder[0], response_timeout=3)
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), 'Simulator remained blocked')
            self.assertFalse(errors, errors)
            self.assertEqual(bytes(received), data)
            self.assertEqual(report.response, reply)
            self.assertTrue(report.response_complete)
