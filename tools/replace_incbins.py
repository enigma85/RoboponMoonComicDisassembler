#!/usr/bin/env python3
"""Helper for progressively replacing INCBIN ranges with assembly labels.

This is a placeholder workflow tool: it records intended replacements in JSON so
contributors can review them before editing generated bank files.
"""
from __future__ import annotations
import argparse, json
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--bank', required=True)
    ap.add_argument('--start', required=True)
    ap.add_argument('--end', required=True)
    ap.add_argument('--label', required=True)
    ap.add_argument('--kind', default='unknown')
    ap.add_argument('--out', default='analysis/replacements.json')
    a=ap.parse_args()
    out=Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    rows=[]
    if out.exists(): rows=json.loads(out.read_text())
    rows.append(vars(a))
    out.write_text(json.dumps(rows, indent=2))
    print(f'queued replacement {a.label} in bank {a.bank}')
if __name__=='__main__': main()
