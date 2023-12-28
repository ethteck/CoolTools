#!/usr/bin/env python3

from dataclasses import dataclass
from pathlib import Path
from typing import List

ROOT_DIR = Path(__file__).parent
GRP_ROM = ROOT_DIR / "roms" / "GRP0301-010.BIN"
WWP_ROM = ROOT_DIR / "roms" / "WWP2080-7213.BIN"

VERBOSE = False


def debug(msg: str):
    if VERBOSE:
        print(msg)


@dataclass
class SOS:
    rom_offset: int
    length: int
    name: str
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
    return SOS(offset, length, name, data[:length])


def bytes_type_str(data: bytes) -> str:
    if all(b == 255 for b in data):
        return "0xFF"
    else:
        return "misc"


def main() -> None:
    for r in [GRP_ROM, WWP_ROM]:
        debug(f"{r}:")

        with open(r, "rb") as f:
            data = f.read()

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

        dump_dir = Path("out") / Path(r.with_suffix("").name)
        dump_dir.mkdir(exist_ok=True)

        for sos in soss:
            with open(dump_dir / f"{sos.name.replace('/', '-')}.bin", "wb") as f:
                f.write(sos.data)


if __name__ == "__main__":
    main()
