#!/usr/bin/env python3
"""Build inert synthetic Catchlight package satisfying the RUN embedded-size gate.
Does not create or run a PE; only controls DWORD at reconstructed buffer +0x40.
"""
import argparse
from pathlib import Path
from catchlight_lfsr import transform

def num(s): return int(s,0)

def build(length=524292, embedded=0x12000):
    if length < 0x40004 or length > 64*1024*1024: raise ValueError('size must be 0x40004..64 MiB')
    if length & 3: raise ValueError('size must be multiple of four')
    w = length >> 2
    if not (0x10000 < embedded < w-0x44): raise ValueError(f'embedded-size must satisfy 0x10000 < N < 0x{w-0x44:x}')
    # In RUN, work[0x40:] = pkg[0x20:...] before the third LFSR transform.
    # Choose a source DWORD whose XOR with the known keystream at +0x40 yields embedded.
    mask = transform(bytes(68))[64:68]
    desired = embedded.to_bytes(4,'little')
    encoded = bytes(a ^ b for a,b in zip(desired,mask))
    pkg = bytearray(length)
    pkg[0:8] = b'TESTTEST'
    pkg[0x20:0x24] = encoded
    pkg[-4:] = (length-4).to_bytes(4,'little')
    return bytes(pkg),mask,encoded

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('-o','--output',type=Path,default=Path('catchlight-gate-only.pkg'))
    p.add_argument('--size',type=num,default=524292)
    p.add_argument('--embedded-size',type=num,default=0x12000)
    a=p.parse_args()
    pkg,mask,encoded=build(a.size,a.embedded_size)
    a.output.write_bytes(pkg)
    assert bytes(x^y for x,y in zip(mask,encoded)) == a.embedded_size.to_bytes(4,'little')
    print(f'Output: {a.output} ({len(pkg):,} bytes)')
    print(f'Keystream at work+0x40: {mask.hex(" ")}')
    print(f'Encoded source at pkg+0x20: {encoded.hex(" ")}')
    print(f'Expected decoded DWORD: 0x{a.embedded_size:08x}')
    print('Gate-only synthetic fixture: candidate data is intentionally not a valid PE.')
if __name__=='__main__': main()
