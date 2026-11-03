#!/usr/bin/env python3
"""Hunt known Catchlight nsis7z.dll XOR-string forms in a binary (read-only).

Scans entire file and outputs candidates as CSV. PE RVA mapping is built from
section headers with standard library only. Both transformations are corroborated
by Catchlight call-site disassembly; a match does NOT establish an active string.
"""
import argparse,csv,struct,sys,re
from pathlib import Path

def sections_of(b):
    if len(b)<64 or b[:2]!=b'MZ': return []
    try:
        pe=struct.unpack_from('<I',b,0x3c)[0]
        if b[pe:pe+4]!=b'PE\0\0':return []
        n, opt=struct.unpack_from('<HH',b,pe+6)[0], struct.unpack_from('<H',b,pe+20)[0]
        secs=[]
        for i in range(min(n,96)):
            p=pe+24+opt+40*i
            name,vs,va,rs,raw=struct.unpack_from('<8sIIII',b,p)
            if raw<len(b):secs.append((name.split(b'\0')[0].decode('ascii','replace'),va,raw,min(rs,len(b)-raw)))
        return secs
    except (struct.error,OverflowError):return []

def rvafor(o,sec):
    for name,va,raw,rs in sec:
        if raw<=o<raw+rs:return f'0x{va+(o-raw):X}',name
    return '',''

def rows(b,sec,minimum_letters=2):
    # x86 helper sub_10045EAA: 3-byte encoded field; key byte(i) = (i-0x59)&255
    # Original sites are structures with zero padding/decoded buffer and 32-bit init flag.
    for i in range(len(b)-12):
        if b[i+3:i+12]!=b'\0'*9:continue
        val=bytes(b[i+j]^((j-0x59)&255) for j in range(3))
        if not all(0x30<=v<=0x39 or 0x41<=v<=0x5a or 0x61<=v<=0x7a or v==0x5f for v in val):continue
        s=val.decode('ascii')
        if sum(c.isalpha() for c in s)<minimum_letters:continue
        rva,section=rvafor(i,sec)
        yield ('xor_ascii3',i,rva,section,s,b[i:i+3].hex())
    # sub_10043B26: eight UTF16 encrypted characters, decoded to buffer at +0x10;
    # init flag at +0x24. Restrict to plausible printable text, no embedded NULs.
    for i in range(0,len(b)-0x28,2):
        if b[i+0x24:i+0x28] not in (b'\0'*4,b'\x01\0\0\0'):continue
        words=struct.unpack_from('<8H',b,i)
        plain=[x ^ (j+0xA7) for j,x in enumerate(words)]
        if all(32<=v<=126 for v in plain):
            txt=''.join(chr(v) for v in plain)
            if sum(c.isalpha() for c in txt)>=minimum_letters:
                rva,section=rvafor(i,sec)
                yield ('xor_utf16_8',i,rva,section,txt,b[i:i+16].hex())

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('binary',type=Path)
    ap.add_argument('-o','--output',type=Path,help='CSV path (default: standard output)')
    ap.add_argument('--contains',default='',help='Only include decoded text containing substring (case-insensitive)')
    ap.add_argument('--max-results',type=int,default=1000)
    args=ap.parse_args()
    b=args.binary.read_bytes();sec=sections_of(b)
    out=args.output.open('w',newline='',encoding='utf-8') if args.output else sys.stdout
    try:
        writer=csv.writer(out);writer.writerow(['type','raw_offset','rva','section','decoded','encoded_hex'])
        total=0
        for typ,off,rva,section,decoded,encoded in rows(b,sec):
            if args.contains.lower() not in decoded.lower():continue
            writer.writerow([typ,f'0x{off:X}',rva,section,decoded,encoded]);total+=1
            if total>=args.max_results:break
    finally:
        if args.output:out.close()
    print(f'[+] Wrote {total} candidates. Interpret as leads, not verified call sites.',file=sys.stderr)

if __name__=='__main__':main()
