"""Deterministic mutation regression: malformed network ELF must fail cleanly."""
from __future__ import annotations
import random
import unittest
from host.ps4_sender.elfcheck import inspect_elf, ELFError
from tests.test_elfcheck import fake_elf


class FuzzELFTests(unittest.TestCase):
    def test_1500_random_header_mutations_never_crash_parser(self):
        r = random.Random(0x1252)
        original = fake_elf()
        for i in range(1500):
            buf = bytearray(original)
            for _ in range(r.randint(1, 6)):
                index = r.randrange(min(len(buf), 128))
                buf[index] = r.randrange(256)
            if i % 19 == 0:
                buf = buf[:r.randrange(len(buf))]
            try:
                inspect_elf(bytes(buf))
            except ELFError:
                pass
            except Exception as exc:
                self.fail(f'Uncontrolled failure on mutation #{i}: {exc!r}')
