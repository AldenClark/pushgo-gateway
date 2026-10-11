#!/usr/bin/env python3
"""Check the ELF class and machine of a named Linux release asset."""

import argparse
import struct
from pathlib import Path


def verify(path: Path, target: str) -> None:
    expected = {
        "amd64": (2, 62),
        "arm64": (2, 183),
        "armv7": (1, 40),
    }
    parts = target.split("-")
    if len(parts) != 3 or parts[0] != "linux" or parts[1] not in expected or parts[2] not in ("gnu", "musl"):
        raise ValueError(f"unsupported release target: {target}")
    with path.open("rb") as source:
        header = source.read(64)
    elf_class, machine = expected[parts[1]]
    minimum_header = 64 if elf_class == 2 else 52
    if len(header) < minimum_header or header[:4] != b"\x7fELF" or header[5:7] != b"\x01\x01":
        raise ValueError(f"invalid or truncated little-endian ELF header: {target}")
    actual_type, actual_machine = struct.unpack_from("<HH", header, 16)
    if header[4] != elf_class or actual_machine != machine or actual_type not in (2, 3):
        raise ValueError(f"release asset architecture mismatch: {target}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("target")
    args = parser.parse_args()
    try:
        verify(args.path, args.target)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
