#!/usr/bin/env python3
"""Decode this daemon's single outgoing AAC-ELD RTP stream in a btmon capture."""
import argparse
import ctypes as c
from ctypes.util import find_library
from pathlib import Path
import subprocess


def decoder_library():
    name = find_library("fdk-aac")
    if not name:
        raise SystemExit("libfdk-aac is required")
    lib = c.CDLL(name)
    buffer = c.POINTER(c.c_ubyte)
    lib.aacDecoder_Open.argtypes = [c.c_int, c.c_uint]
    lib.aacDecoder_Open.restype = c.c_void_p
    lib.aacDecoder_ConfigRaw.argtypes = [c.c_void_p, c.POINTER(buffer), c.POINTER(c.c_uint)]
    lib.aacDecoder_Fill.argtypes = [c.c_void_p, c.POINTER(buffer), c.POINTER(c.c_uint), c.POINTER(c.c_uint)]
    lib.aacDecoder_DecodeFrame.argtypes = [c.c_void_p, c.POINTER(c.c_short), c.c_int, c.c_uint]
    lib.aacDecoder_Close.argtypes = [c.c_void_p]
    lib.aacDecoder_Close.restype = None
    return lib


def buffer_pointer(data):
    return c.cast((c.c_ubyte * len(data)).from_buffer_copy(data), c.POINTER(c.c_ubyte))


def measure(capture, tshark, lib):
    rows = subprocess.check_output([
        tshark, "-n", "-r", str(capture), "-Y", "rtp.ssrc == 1 && rtp.p_type == 96 && hci_mon.opcode == 4",
        "-T", "fields", "-e", "frame.number", "-e", "@rtp",
    ], text=True).splitlines()
    if not rows:
        raise ValueError("no matching outgoing RTP stream")
    handle = lib.aacDecoder_Open(0, 1)
    if not handle:
        raise RuntimeError("could not open AAC decoder")
    try:
        config = buffer_pointer(bytes.fromhex("f8e65000"))
        if lib.aacDecoder_ConfigRaw(handle, c.byref(config), c.byref(c.c_uint(4))):
            raise RuntimeError("invalid stereo AAC-ELD configuration")
        peak = units = 0
        pcm = (c.c_short * 960)()
        for index, row in enumerate(rows):
            frame, raw = row.split("\t")
            packet = bytes.fromhex(raw.replace(":", ""))
            if (packet[:2] != b"\x80\x60" or int.from_bytes(packet[2:4], "big") != index % 65536
                    or int.from_bytes(packet[4:8], "big") != (index * 1440) % 2**32):
                raise ValueError(f"frame {frame}: expected a complete stream from sequence zero")
            offset = 12
            for _ in range(3):
                header = packet[offset:offset + 4]
                if len(header) != 4 or int.from_bytes(header[:2], "big") != (0xB000 | (units & 0xFFF)) or header[2] >> 4 != 1:
                    raise ValueError(f"frame {frame}: invalid codec unit header")
                size = int.from_bytes(header[2:], "big") & 0xFFF
                offset += 4
                data = packet[offset:offset + size]
                if not size or len(data) != size:
                    raise ValueError(f"frame {frame}: truncated codec unit")
                ptr, size_arg, valid = buffer_pointer(data), c.c_uint(size), c.c_uint(size)
                if lib.aacDecoder_Fill(handle, c.byref(ptr), c.byref(size_arg), c.byref(valid)) or valid.value:
                    raise ValueError(f"frame {frame}: could not consume codec unit")
                if lib.aacDecoder_DecodeFrame(handle, pcm, len(pcm), 0):
                    raise ValueError(f"frame {frame}: decoder rejected codec unit")
                peak = max(peak, max(map(abs, pcm)))
                units += 1
                offset += size
            if offset != len(packet):
                raise ValueError(f"frame {frame}: trailing bytes")
        print(f"{capture}: {len(rows)} RTP packets, {units} AAC-ELD units, {units / 100:.2f} s, peak PCM {peak}")
    finally:
        lib.aacDecoder_Close(handle)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args()
    library = decoder_library()
    for path in args.captures:
        measure(path, args.tshark, library)
