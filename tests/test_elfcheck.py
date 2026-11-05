"""ELF structure edge cases and regression tests."""
import struct
import unittest
from host.ps4_sender.elfcheck import ELFError, inspect_elf


def fake_elf(*, etype=3, machine=62, segments=(1, 2),
             entry=0x90, execute=True, filesz=160, memsz=512,
             fileoff=0, vaddr=0):
    buf = bytearray(64 + 56 * len(segments))
    buf[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", buf, 16, etype, machine, 1)
    struct.pack_into("<QQ", buf, 24, entry, 64)
    struct.pack_into("<HHH", buf, 52, 64, 56, len(segments))
    for i, segment in enumerate(segments):
        off = 64 + i * 56
        if segment == 1:
            struct.pack_into("<IIQQQQQQ", buf, off,
                             1, 5 if execute else 4, fileoff, vaddr,
                             0, filesz, memsz, 0x1000)
        elif segment == 2:
            struct.pack_into("<IIQQQQQQ", buf, off,
                             2, 4, 0, 0, 0, 0, 0, 8)
        else:
            struct.pack_into("<I", buf, off, segment)
    # A section table is mandatory for elfldr v0.7, unlike generic ELF.
    # Put one NULL section immediately after the program header table.
    shoff = len(buf)
    buf.extend(b"\x00" * 64)
    struct.pack_into("<Q", buf, 40, shoff)
    struct.pack_into("<HH", buf, 58, 64, 1)
    return bytes(buf)


class ELFCheckTests(unittest.TestCase):
    def test_valid_et_dyn_elf(self):
        report = inspect_elf(fake_elf())
        self.assertEqual(report["entry"], "0x90")
        self.assertEqual(report["load_segments"], 1)
        self.assertEqual(report["dynamic_segments"], 1)

    def test_rejects_wrong_architecture(self):
        with self.assertRaises(ELFError):
            inspect_elf(fake_elf(machine=40))

    def test_rejects_executable_type(self):
        with self.assertRaises(ELFError):
            inspect_elf(fake_elf(etype=2))

    def test_rejects_missing_load(self):
        with self.assertRaises(ELFError):
            inspect_elf(fake_elf(segments=(2,)))

    def test_rejects_truncated_payload(self):
        with self.assertRaises(ELFError):
            inspect_elf(fake_elf()[:70])

    def test_rejects_bad_magic(self):
        with self.assertRaises(ELFError):
            inspect_elf(b"not an elf")

    def test_rejects_non_executable_entry(self):
        with self.assertRaisesRegex(ELFError, "entry point"):
            inspect_elf(fake_elf(execute=False))

    def test_rejects_entry_in_executable_bss_not_in_file(self):
        with self.assertRaisesRegex(ELFError, "entry point"):
            inspect_elf(fake_elf(entry=0x90, filesz=64, memsz=512))

    def test_rejects_entry_outside_segment(self):
        with self.assertRaisesRegex(ELFError, "entry point"):
            inspect_elf(fake_elf(entry=0x1000))

    def test_rejects_segment_outside_file(self):
        with self.assertRaisesRegex(ELFError, "outside file"):
            inspect_elf(fake_elf(fileoff=0x4000))

    def test_rejects_filesz_larger_than_memsz(self):
        with self.assertRaisesRegex(ELFError, "exceeds memory"):
            inspect_elf(fake_elf(filesz=64, memsz=1))

    def test_rejects_virtual_address_overflow(self):
        with self.assertRaisesRegex(ELFError, "overflow"):
            inspect_elf(fake_elf(vaddr=(1 << 64) - 10, filesz=160, memsz=200))


    def test_rejects_section_table_outside_file(self):
        buf = bytearray(fake_elf())
        struct.pack_into("<Q", buf, 40, 0x4000)
        struct.pack_into("<HHH", buf, 58, 64, 2, 0)
        with self.assertRaisesRegex(ELFError, "section header table"):
            inspect_elf(bytes(buf))

    def test_rejects_rela_data_outside_file(self):
        buf = bytearray(fake_elf())
        shoff = len(buf)
        buf.extend(b"\x00" * 64)
        struct.pack_into("<Q", buf, 40, shoff)
        struct.pack_into("<HHH", buf, 58, 64, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", buf, shoff, 0, 4, 0, 0, 4096, 24, 0, 0, 8, 24)
        with self.assertRaisesRegex(ELFError, "outside file"):
            inspect_elf(bytes(buf))

    def test_rejects_rela_misaligned_size(self):
        buf = bytearray(fake_elf())
        shoff = len(buf)
        buf.extend(b"\x00" * (64 + 24))
        struct.pack_into("<Q", buf, 40, shoff)
        struct.pack_into("<HHH", buf, 58, 64, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", buf, shoff, 0, 4, 0, 0, shoff + 64, 23, 0, 0, 8, 24)
        with self.assertRaisesRegex(ELFError, "SHT_RELA"):
            inspect_elf(bytes(buf))

    def test_accepts_rela_section_with_valid_bounds(self):
        buf = bytearray(fake_elf())
        shoff = len(buf)
        buf.extend(b"\x00" * (64 + 24))
        struct.pack_into("<Q", buf, 40, shoff)
        struct.pack_into("<HHH", buf, 58, 64, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", buf, shoff, 0, 4, 0, 0, shoff + 64, 24, 0, 0, 8, 24)
        self.assertEqual(inspect_elf(bytes(buf))["section_headers"], 1)

    def test_rejects_invalid_header_size(self):
        buf = bytearray(fake_elf())
        struct.pack_into("<H", buf, 52, 20)
        with self.assertRaisesRegex(ELFError, "dimensions"):
            inspect_elf(bytes(buf))
