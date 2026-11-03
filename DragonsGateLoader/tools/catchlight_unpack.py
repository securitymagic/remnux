#!/usr/bin/env python3
"""Static reconstruction of Catchlight nsis7z.dll!sub_10045F1A. Does not execute bytes."""
import argparse
import hashlib
import pathlib
import struct
import sys
from catchlight_lfsr import transform

STATIC_VA = 0x10060D08
IMAGE_BASE = 0x10000000
STATIC_RVA = STATIC_VA - IMAGE_BASE


def read_pe_rva(filename: pathlib.Path, rva: int, length: int) -> bytes:
    data = filename.read_bytes()
    if data[:2] != b'MZ':
        raise ValueError('DLL is not an MZ file')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe:pe+4] != b'PE\0\0':
        raise ValueError('DLL PE signature missing')
    num_sections, optional_length = struct.unpack_from('<HH', data, pe+6)[0], struct.unpack_from('<H', data, pe+20)[0]
    for i in range(num_sections):
        loc = pe + 24 + optional_length + i * 40
        _name, virtual_size, section_rva, raw_size, raw_pointer = struct.unpack_from('<8sIIII', data, loc)
        if section_rva <= rva and rva + length <= section_rva + raw_size:
            off = raw_pointer + rva - section_rva
            return data[off:off+length]
    raise ValueError(f'Could not map RVA 0x{rva:x} to {length} backed bytes in PE sections')


def reconstruct(pkg: bytes, constant: bytes) -> bytes:
    if len(constant) != 32:
        raise ValueError('The static block must contain exactly 32 bytes')
    if len(pkg) <= 4:
        raise ValueError('Package too small')
    trailer = int.from_bytes(pkg[-4:], 'little')
    if trailer != len(pkg)-4:
        raise ValueError(f'Package trailer mismatch: 0x{trailer:x} != 0x{len(pkg)-4:x}')
    working_size = len(pkg) >> 2
    if working_size < 0x10000:
        raise ValueError('RUN minimum working size not met (need file >= 0x40000)')
    # HeapAlloc(HEAP_ZERO_MEMORY): working buffer initially all zeros.
    work = bytearray(working_size)
    # memcpy(work, pkg, 0x20); scrambler(work, 0x20)
    work[0:0x20] = pkg[0:0x20]
    work[0:0x20] = transform(work[0:0x20])
    # memcpy(work+0x20, dll_static, 0x20); scrambler(work, 0x40)
    work[0x20:0x40] = constant
    work[0:0x40] = transform(work[0:0x40])
    # memcpy(work+0x40, pkg+0x20, working_size-0x40); scrambler(work, working_size)
    work[0x40:] = pkg[0x20:0x20 + working_size-0x40]
    work[:] = transform(work)
    return bytes(work)


def main():
    p = argparse.ArgumentParser(description='Offline Catchlight RUN reconstruction: no execution, no DLL loading.')
    p.add_argument('package', type=pathlib.Path, nargs='?', help='Downloaded .pkg or .exe content (must have length trailer)')
    p.add_argument('--dll', type=pathlib.Path, help='Extract 32-byte constant from matching nsis7z.dll at RVA 0x60d08')
    p.add_argument('--constant-hex', help='Alternative: exact 32 byte constant as 64 hex digits')
    p.add_argument('-o', '--output', type=pathlib.Path, help='Write reconstructed working buffer to this path')
    p.add_argument('--self-test', action='store_true', help='Check known LFSR test and loaded DLL block')
    args = p.parse_args()
    if args.self_test:
        assert transform(bytes(68))[64:68] == bytes.fromhex('f9d014e0')
        print('LFSR known-vector self-test: PASS')
        if args.dll:
            print('DLL constant at RVA 0x60d08:', read_pe_rva(args.dll, STATIC_RVA, 32).hex(' '))
        if args.package is None:
            return
    if args.package is None:
        p.error('package is required without --self-test')
    if bool(args.dll) == bool(args.constant_hex):
        p.error('provide exactly one of --dll or --constant-hex')
    constant = read_pe_rva(args.dll, STATIC_RVA, 32) if args.dll else bytes.fromhex(args.constant_hex)
    pkg = args.package.read_bytes()
    work = reconstruct(pkg, constant)
    working_size = len(work)
    embedded_size = struct.unpack_from('<I', work, 0x40)[0]
    upper = working_size - 0x44
    ok = (embedded_size > 0x10000 and embedded_size < upper)
    print(f'Package: {args.package} ({len(pkg):,} bytes)')
    print(f'Constant from: {args.dll if args.dll else "--constant-hex"} ({constant.hex(" ")})')
    print(f'Reconstructed working buffer: {working_size:,} bytes (0x{working_size:x})')
    print(f'Working-buffer SHA256: {hashlib.sha256(work).hexdigest()}')
    print('First 0x50 bytes:', work[:0x50].hex(' '))
    print(f'Embedded DWORD at work+0x40: 0x{embedded_size:08x} ({embedded_size:,})')
    print(f'RUN gate: 0x10000 < embedded DWORD < 0x{upper:x} => {"PASS" if ok else "FAIL"}')
    if ok:
        print('Candidate mapped-module bytes start at working buffer +0x44')
        candidate = work[0x44:0x44+embedded_size]
        print(f'Candidate bytes: {len(candidate):,}; MZ signature: {candidate[:2] == bytes.fromhex("4d5a")}')
        print('Candidate SHA256:', hashlib.sha256(candidate).hexdigest())
    else:
        print('Manual PE mapper is not reached under this gate; no candidate extracted.')
    if args.output:
        if args.output.resolve() in (args.package.resolve(), args.dll.resolve() if args.dll else None):
            p.error('Refusing to overwrite input')
        args.output.write_bytes(work)
        print(f'Saved reconstructed buffer: {args.output}')
        if ok:
            candidate_path = args.output.with_name(args.output.name + '.candidate-pe.bin')
            candidate_path.write_bytes(candidate)
            print(f'Saved static candidate: {candidate_path}')
    print('No code was executed. Validation after this gate is NOT reproduced.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)
