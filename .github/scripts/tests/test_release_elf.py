import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify_release_elf.py"
SPEC = importlib.util.spec_from_file_location("verify_release_elf", SCRIPT)
ELF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ELF)


class ReleaseElfTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.asset = Path(self.temporary.name) / "renamed-release-asset"

    def write_header(self, elf_class, machine, elf_type=3):
        header = bytearray(64 if elf_class == 2 else 52)
        header[:7] = b"\x7fELF" + bytes((elf_class, 1, 1))
        struct.pack_into("<HH", header, 16, elf_type, machine)
        self.asset.write_bytes(header)

    def test_all_six_targets_accept_their_matching_elf_header(self):
        for architecture, elf_class, machine in (("amd64", 2, 62), ("arm64", 2, 183), ("armv7", 1, 40)):
            for libc in ("gnu", "musl"):
                with self.subTest(architecture=architecture, libc=libc):
                    self.write_header(elf_class, machine)
                    ELF.verify(self.asset, f"linux-{architecture}-{libc}")

    def test_renamed_arm64_binary_is_rejected_for_armv7(self):
        # Both descriptions contain "ARM", which the old gate accepted.
        self.write_header(2, 183)
        for libc in ("gnu", "musl"):
            with self.subTest(libc=libc), self.assertRaisesRegex(ValueError, "architecture mismatch"):
                ELF.verify(self.asset, f"linux-armv7-{libc}")

    def test_wrong_class_or_non_executable_elf_is_rejected(self):
        self.write_header(2, 40)
        with self.assertRaisesRegex(ValueError, "architecture mismatch"):
            ELF.verify(self.asset, "linux-armv7-gnu")
        self.write_header(2, 62, elf_type=1)
        with self.assertRaisesRegex(ValueError, "architecture mismatch"):
            ELF.verify(self.asset, "linux-amd64-gnu")

    def test_truncated_or_non_elf_input_is_rejected(self):
        for data in (b"\x7fELF", b"x" * 64):
            self.asset.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "invalid or truncated"):
                ELF.verify(self.asset, "linux-amd64-musl")


if __name__ == "__main__":
    unittest.main()
