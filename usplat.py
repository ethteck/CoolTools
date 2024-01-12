#!/usr/bin/env python3

from dataclasses import dataclass
from pathlib import Path
import struct
from typing import List

ROOT_DIR = Path(__file__).parent

ROMS = {
    "cool104": {
        "grp": "GRP0301-010",
        "wwp": "WWP2080-7213",
    },
    "wwp2047": {
        "grp": "GRP8001-010",
        "wwp": "WWP2047-1712",
    },
}

VERBOSE = True


def debug(msg: str):
    if VERBOSE:
        print(msg)


@dataclass
class SOS:
    rom_offset: int
    length: int
    name: str
    flag1: int
    data: bytes


def handle_sos(data: bytes, offset: int) -> SOS:
    assert data[0x0:0x6] == b"<SOS>\0"
    length = int.from_bytes(data[0x6:0xA], "big")
    name_offset = int.from_bytes(data[0xA:0xE], "big")
    assert data[0xE:0x10] == b"\xCA\xFE"
    flag1 = int.from_bytes(data[0x10:0x14], "big")  # code start?
    flag2 = int.from_bytes(data[0x14:0x18], "big")
    flag3 = int.from_bytes(data[0x18:0x1C], "big")
    assert data[0x1C:0x20] == b"\0\0\0\0"

    name_zero = data[name_offset:].find(b"\x00")
    assert name_zero != -1

    name = data[name_offset : name_offset + name_zero].decode("ascii")

    bytes_after_name_start = name_offset + name_zero + 1
    bytes_after_name = data[bytes_after_name_start : bytes_after_name_start + 0x4]
    bytes_after_name_str = ""
    for char in bytes_after_name:
        bytes_after_name_str += chr(char) if char >= 0x20 and char <= 0x7E else " "

    debug(
        f"<SOS> {(str(hex(offset))).ljust(8)} {name.ljust(16)} flag1:{flag1:X} flag2:{flag2:X} flag3:{flag3:X}"
    )
    return SOS(offset, length, name, flag1, data[:length])


def bytes_type_str(data: bytes) -> str:
    if all(b == 255 for b in data):
        return "0xFF"
    else:
        return "misc"


def main() -> None:
    rom = "wwp2047"
    print(f"Dumping {rom}...")

    for r in ROMS[rom].values():
        debug(f"{r}:")

        with open(ROOT_DIR / "roms" / rom / (r + ".BIN"), "rb") as f:
            data: bytes = f.read()

        cur_pos = 0
        soss: List[SOS] = []

        while True:
            if data[cur_pos : cur_pos + 5] == b"<SOS>":
                sos = handle_sos(data[cur_pos:], cur_pos)
                soss.append(sos)
                cur_pos += sos.length
            else:
                next_sos = data.find(b"<SOS>", cur_pos)
                if next_sos == -1:
                    debug(
                        f"Reached EOF (skipped 0x{len(data) - cur_pos:X} {bytes_type_str(data[cur_pos:])} bytes)"
                    )
                    break
                else:
                    bytes_skipped_type = (
                        "0xFF"
                        if all(b == 255 for b in data[cur_pos:next_sos])
                        else "misc"
                    )
                    debug(
                        f"Skipped 0x{next_sos - cur_pos:X} {bytes_skipped_type} bytes"
                    )
                    cur_pos = next_sos

        dump_dir = Path("out") / rom / r
        dump_dir.mkdir(exist_ok=True, parents=True)

        for sos in soss:
            a, width, height, is_compressed = struct.unpack(
                ">HHHH", sos.data[sos.flag1 : sos.flag1 + 0x8]
            )
            if is_compressed != 1:
                continue

            debug(f"{sos.name} seems compressed, decompressing")

            cur_pos = sos.flag1 + 0x10
            buf = b""
            y = 0

            while y < height:
                length = int.from_bytes(sos.data[cur_pos : cur_pos + 0x2], "big")
                cur_pos += 2
                end_pos = cur_pos + length

                while cur_pos < end_pos:
                    b: int = struct.unpack(">b", sos.data[cur_pos : cur_pos + 1])[0]
                    cur_pos += 1
                    if b < 0:
                        buf += (sos.data[cur_pos : cur_pos + 1]) * (-b + 1)
                        cur_pos += 1
                    else:
                        buf += sos.data[cur_pos : cur_pos + b + 1]
                        cur_pos += b + 1
                y += 1

            with open(dump_dir / f"{sos.name.replace('/', '-')}.dec.bin", "wb") as f:
                f.write(buf)

        for sos in soss:
            with open(dump_dir / f"{sos.name.replace('/', '-')}.bin", "wb") as f:
                f.write(sos.data)


if __name__ == "__main__":
    main()
