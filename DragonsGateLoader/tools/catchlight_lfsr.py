#!/usr/bin/env python3
"""Offline, nonexecuting Catchlight sub_10045A07 bitstream transformation.

The transform is symmetric XOR. The state resets at each function invocation.
A transformed file is not necessarily a decoded PE: the original RUN pipeline
constructs a buffer and invokes this function on multiple separate regions.
"""
import argparse
import pathlib
import struct
import sys

SEED = 0x95000000


def transform(data: bytes, seed: int = SEED) -> bytes:
    """Match the observed MSB-first per-byte bitstream XOR."""
    state = seed
    out = bytearray(data)
    for index in range(len(out)):
        mask = 0
        for bit in range(7, -1, -1):
            feedback = ((state >> 17) ^ (state >> 18)) & 1
            state = (state >> 1) | (feedback << 31)
            mask |= feedback << bit
        out[index] ^= mask
    return bytes(out)


def numeric(s: str) -> int:
    try:
        return int(s, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid integer: {s}") from exc


def check_trailer(data: bytes) -> None:
    if len(data) < 8:
        print("Trailer: too short to validate (minimum 8 bytes)")
        return
    trailer = struct.unpack_from('<I', data, len(data) - 4)[0]
    print(f"Trailer: 0x{trailer:08x}; file length minus four: 0x{len(data)-4:08x}; match: {trailer == len(data)-4}")


def selftest() -> None:
    result = transform(bytes(68))
    observed = bytes.fromhex('f9 d0 14 e0')
    assert result[64:68] == observed, (result[64:68].hex(), observed.hex())
    assert transform(result) == bytes(68), "XOR reversibility failed"
    print("Self-test PASS: zero-byte vector at +0x40 is f9 d0 14 e0 (DWORD 0xe014d0f9)")
    print("Self-test PASS: double application restores original bytes")


def main() -> None:
    p = argparse.ArgumentParser(description='Catchlight sub_10045A07 offline LFSR XOR transform (never executes input).')
    p.add_argument('input', nargs='?', type=pathlib.Path, help='Input file to transform')
    p.add_argument('-o', '--output', type=pathlib.Path, help='Output filename (default: INPUT.decoded.bin)')
    p.add_argument('--offset', type=numeric, default=0, help='Starting byte offset within input (0x notation supported)')
    p.add_argument('--length', type=numeric, help='Number of bytes to transform (default: remaining bytes)')
    p.add_argument('--seed', type=numeric, default=SEED, help='Initial 32-bit LFSR state (default 0x95000000)')
    p.add_argument('--preserve-layout', action='store_true', help='Write a copy of original file with only selected region transformed')
    p.add_argument('--check-trailer', action='store_true', help='Check trailing little-endian DWORD against file length minus four')
    p.add_argument('--self-test', action='store_true', help='Run known-vector and reversibility tests; if no input, exit')
    args = p.parse_args()
    if args.self_test:
        selftest()
    if args.input is None:
        if args.self_test:
            return
        p.error('Input filename is required unless --self-test is specified')
    if args.seed < 0 or args.seed > 0xffffffff:
        p.error('--seed must be an unsigned 32-bit integer')
    data = args.input.read_bytes()
    if args.check_trailer:
        check_trailer(data)
    if not 0 <= args.offset <= len(data):
        p.error('--offset is outside file')
    length = len(data) - args.offset if args.length is None else args.length
    if length < 0 or args.offset + length > len(data):
        p.error('--length is outside input bounds')
    decoded = transform(data[args.offset:args.offset+length], args.seed)
    output = args.output or args.input.with_name(args.input.name + '.decoded.bin')
    if output.resolve() == args.input.resolve():
        p.error('Refusing to overwrite input file')
    if args.preserve_layout:
        result = bytearray(data)
        result[args.offset:args.offset+length] = decoded
        result = bytes(result)
    else:
        result = decoded
    output.write_bytes(result)
    print(f"Input: {args.input} ({len(data):,} bytes)")
    print(f"Decoded region: 0x{args.offset:x}..0x{args.offset+length:x} ({length:,} bytes); seed=0x{args.seed:08x}")
    print(f"First 32 decoded bytes: {decoded[:32].hex(' ')}")
    if len(decoded) >= 68:
        print(f"Decoded DWORD at region +0x40: 0x{int.from_bytes(decoded[64:68], 'little'):08x}")
    if len(decoded) >= 2:
        print(f"Region starts with MZ: {decoded[:2] == b'MZ'}")
    print(f"Saved: {output} ({len(result):,} bytes)")
    print('Note: raw file transformation is NOT equivalent to the full RUN reconstruction pipeline.')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        sys.exit(1)
