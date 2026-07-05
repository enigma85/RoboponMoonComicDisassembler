#!/usr/bin/env python3
"""Experimental text-engine probe helpers.

These tools create reports only; they do not patch ROMs. Use them to identify
where Sun's English text/font implementation differs from Moon/Comic.
"""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path

BANK=0x4000

def read(p): return Path(p).read_bytes()

def printable_runs(data, min_len=6):
    start=None; buf=[]
    for i,b in enumerate(data+b'\0'):
        if 0x20 <= b <= 0x7e:
            if start is None: start=i
            buf.append(chr(b))
        else:
            if start is not None and len(buf)>=min_len:
                yield start,''.join(buf)
            start=None; buf=[]

def cmd_sun_strings(args):
    data=read(args.rom)
    out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', newline='') as f:
        w=csv.writer(f, delimiter='\t')
        w.writerow(['offset','bank','bank_offset','text'])
        for off,s in printable_runs(data,args.min_len):
            w.writerow([f'0x{off:06X}',f'0x{off//BANK:02X}',f'0x{off%BANK:04X}',s])
    print(f'wrote {out}')

def cmd_compare_window(args):
    a=read(args.a); b=read(args.b)
    off=int(args.offset,0); size=int(args.size,0)
    ca=a[off:off+size]; cb=b[off:off+size]
    print(json.dumps({
        'offset':f'0x{off:06X}', 'size':size,
        'same_bytes':sum(1 for x,y in zip(ca,cb) if x==y),
        'a_hex':ca[:64].hex(), 'b_hex':cb[:64].hex()
    }, indent=2))

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest='cmd', required=True)
    p=sub.add_parser('sun-strings'); p.add_argument('--rom',required=True); p.add_argument('--out',default='analysis/sun_strings.tsv'); p.add_argument('--min-len',type=int,default=6); p.set_defaults(func=cmd_sun_strings)
    p=sub.add_parser('compare-window'); p.add_argument('--a',required=True); p.add_argument('--b',required=True); p.add_argument('--offset',required=True); p.add_argument('--size',default='0x100'); p.set_defaults(func=cmd_compare_window)
    args=ap.parse_args(); args.func(args)
if __name__=='__main__': main()
