"""Regression for v7's incorrect R_X86_64_RELATIVE addend constraint."""
from __future__ import annotations

import struct
import unittest
from pathlib import Path

from host.ps4_sender.elfcheck import ELFError, inspect_elf
from tests.test_elfcheck import fake_elf
from tests.test_elfldr_wire_contract import add_relocations


class V8ELFRelativeRegression(unittest.TestCase):
    @staticmethod
    def patched_elf(addend: int, target: int = 0x1f0) -> bytes:
        data = bytearray(add_relocations(fake_elf(), [target]))
        struct.pack_into('<q', data, len(data) - 8, addend)
        return bytes(data)

    def test_addend_zero_is_a_legal_relocation_value(self):
        rep = inspect_elf(self.patched_elf(0))
        self.assertEqual(rep['relative_addends_outside_load'], 0)

    def test_negative_addend_not_confused_with_target(self):
        rep = inspect_elf(self.patched_elf(-1))
        self.assertEqual(rep['relative_addends_outside_load'], 1)

    def test_addend_beyond_image_not_confused_with_target(self):
        rep = inspect_elf(self.patched_elf(0x100000000))
        self.assertEqual(rep['relative_addends_outside_load'], 1)

    def test_invalid_write_target_is_still_rejected(self):
        with self.assertRaisesRegex(ELFError, 'relocation target outside'):
            inspect_elf(self.patched_elf(-1, target=0x1ff))

    def test_unread_trailing_bytes_still_blocked(self):
        with self.assertRaisesRegex(ELFError, 'unread ELF trailing bytes'):
            inspect_elf(self.patched_elf(-1) + b'junk')

    def test_powershell_message_uses_selected_ip(self):
        script = (Path(__file__).resolve().parents[1] / 'scripts' / 'bdjb_send_elfldr.ps1').read_text()
        self.assertIn('--host $Ps4Ip --port 9021', script)
        self.assertNotIn('--host 192.168.1.5 --port 9021', script)
