#!/usr/bin/env python3
"""Robopon disassembly project helper.

This tool intentionally does not ship or generate copyrighted data in git.
It initializes a local RGBDS scaffold from a user-provided baserom, compares
builds, and produces analysis files to guide real reverse engineering.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Iterable

BANK_SIZE = 0x4000
TARGETS = {"sun", "moon", "comic"}
TARGET_ALIASES = {"comic_bombom": "comic", "comic-bombom": "comic", "bombom": "comic", "bom_bom": "comic", "bom-bom": "comic"}
TARGET_CHOICES = sorted(TARGETS | set(TARGET_ALIASES))

# Raw 2bpp font locations confirmed by visual scan.
# These are ROM file offsets, not CPU addresses.
# Moon/Sun share the early bank-1 font block; Comic is expected to be compatible,
# but should be verified with font-scan when its baserom is available.
PROFILE_FONT_DEFAULTS = {
    "sun": {"offset": 0x40B0, "tiles": 192, "columns": 16},
    "moon": {"offset": 0x40B0, "tiles": 192, "columns": 16},
    "comic": {"offset": 0x40B0, "tiles": 192, "columns": 16},
}

# Metadata-driven font definitions.  These are intentionally named logical
# assets instead of command-line offsets.  The first verified block is the
# kana/dialogue UI font found by visual comparison in Moon/Sun.  More font
# assets can be added here as they are confirmed.
PROFILE_FONTS = {
    "sun": {
        "dialogue": {"offset": 0x40B0, "tiles": 192, "columns": 16, "scale": 4, "description": "verified kana/latin dialogue/UI font block"},
        "kana": {"alias": "dialogue"},
    },
    "moon": {
        "dialogue": {"offset": 0x40B0, "tiles": 192, "columns": 16, "scale": 4, "description": "verified kana dialogue/UI font block"},
        "kana": {"alias": "dialogue"},
    },
    "comic": {
        "dialogue": {"offset": 0x40B0, "tiles": 192, "columns": 16, "scale": 4, "description": "probable kana dialogue/UI font block; verify on hardware/emulator"},
        "kana": {"alias": "dialogue"},
    },
}


def normalize_target(target: str) -> str:
    return TARGET_ALIASES.get(str(target), str(target))


def sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def read_rom(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) % BANK_SIZE:
        raise SystemExit(f"ROM size {len(data)} is not a multiple of 0x4000")
    return data


def rom_header(data: bytes) -> dict:
    title = data[0x134:0x144].split(b"\0", 1)[0]
    return {
        "title_raw_hex": data[0x134:0x144].hex(),
        "title_ascii_lossy": title.decode("ascii", "replace"),
        "cgb_flag": f"0x{data[0x143]:02X}",
        "cart_type": f"0x{data[0x147]:02X}",
        "rom_size_code": f"0x{data[0x148]:02X}",
        "ram_size_code": f"0x{data[0x149]:02X}",
        "header_checksum": f"0x{data[0x14D]:02X}",
        "global_checksum": f"0x{int.from_bytes(data[0x14E:0x150], 'big'):04X}",
    }


def split_banks(data: bytes, out_dir: Path, target: str) -> list[dict]:
    banks_dir = out_dir / "banks" / target
    banks_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for bank in range(len(data) // BANK_SIZE):
        chunk = data[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
        name = f"bank_{bank:02X}.bin"
        (banks_dir / name).write_bytes(chunk)
        manifest.append({
            "bank": bank,
            "file": str(Path("banks") / target / name),
            "sha1": sha1(chunk),
            "size": len(chunk),
            "non_ff_bytes": sum(1 for b in chunk if b != 0xFF),
            "non_00_bytes": sum(1 for b in chunk if b != 0x00),
        })
    return manifest


def write_asm_scaffold(root: Path, target: str, bank_count: int) -> None:
    asm_dir = root / "asm" / target
    asm_dir.mkdir(parents=True, exist_ok=True)
    main = asm_dir / "main.asm"
    lines = [
        '; Auto-generated RGBDS scaffold. Do not edit generated INCBIN lines blindly.\n',
        '; Replace ranges with labeled assembly/data as they are reverse engineered.\n',
        'INCLUDE "macros/hardware.inc"\n',
        'INCLUDE "macros/bank_macros.inc"\n',
        '\n',
        'SECTION "ROM0", ROM0[$0000]\n',
        f'INCBIN "banks/{target}/bank_00.bin"\n',
        '\n',
    ]
    for bank in range(1, bank_count):
        lines += [
            f'SECTION "Bank {bank:02X}", ROMX[$4000], BANK[${bank:02X}]\n',
            f'INCBIN "banks/{target}/bank_{bank:02X}.bin"\n',
            '\n',
        ]
    main.write_text(''.join(lines))




def byte_entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    counts = [0] * 256
    for b in chunk:
        counts[b] += 1
    ent = 0.0
    n = len(chunk)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def bank_address(file_offset: int) -> tuple[int, int, int]:
    bank = file_offset // BANK_SIZE
    bank_off = file_offset % BANK_SIZE
    if bank == 0:
        addr = bank_off
    else:
        addr = 0x4000 + bank_off
    return bank, bank_off, addr


def find_runs(data: bytes, value: int, min_len: int = 32) -> list[dict]:
    runs = []
    start = None
    for i, b in enumerate(data + bytes([(value + 1) & 0xFF])):
        if b == value:
            if start is None:
                start = i
        elif start is not None:
            length = i - start
            if length >= min_len:
                bank, bank_off, addr = bank_address(start)
                runs.append({
                    "offset": f"0x{start:06X}",
                    "bank": f"0x{bank:02X}",
                    "bank_offset": f"0x{bank_off:04X}",
                    "address": f"0x{addr:04X}",
                    "length": length,
                    "value": f"0x{value:02X}",
                })
            start = None
    return runs


def pointer_target_file_offset(table_bank: int, ptr: int) -> int | None:
    if 0 <= ptr <= 0x3FFF:
        return ptr
    if 0x4000 <= ptr <= 0x7FFF:
        return table_bank * BANK_SIZE + (ptr - 0x4000)
    return None


def discover_pointer_tables(data: bytes, min_count: int = 8) -> list[dict]:
    tables = []
    seen = set()
    for off in range(0, len(data) - min_count * 2, 2):
        ptrs = []
        p = off
        table_bank = off // BANK_SIZE
        while p + 1 < len(data):
            val = data[p] | (data[p + 1] << 8)
            if 0x4000 <= val <= 0x7FFF:
                ptrs.append(val)
                p += 2
            else:
                break
        if len(ptrs) < min_count:
            continue
        monotonic = all(a <= b for a, b in zip(ptrs, ptrs[1:]))
        span = ptrs[-1] - ptrs[0]
        score = len(ptrs) + (20 if monotonic else 0) - (0 if span < 0x4000 else 10)
        key = (off, len(ptrs))
        if key in seen:
            continue
        seen.add(key)
        targets = [pointer_target_file_offset(table_bank, x) for x in ptrs[:16]]
        valid_targets = [x for x in targets if x is not None and 0 <= x < len(data)]
        bank, bank_off, addr = bank_address(off)
        tables.append({
            "table_offset": f"0x{off:06X}",
            "bank": f"0x{bank:02X}",
            "bank_offset": f"0x{bank_off:04X}",
            "address": f"0x{addr:04X}",
            "count": len(ptrs),
            "byte_length": len(ptrs) * 2,
            "first_ptr": f"0x{ptrs[0]:04X}",
            "last_ptr": f"0x{ptrs[-1]:04X}",
            "monotonic": monotonic,
            "span": span,
            "valid_sample_targets": len(valid_targets),
            "score": score,
        })
    tables.sort(key=lambda r: (-r["score"], r["table_offset"]))
    return tables


def discover_text_like_runs(data: bytes, min_len: int = 8) -> list[dict]:
    """Heuristic only: finds dense non-control runs often worth inspecting as text/data."""
    rows = []
    start = None
    buf = []
    def flush(end_i: int):
        nonlocal start, buf
        if start is not None and len(buf) >= min_len:
            chunk = bytes(buf)
            bank, bank_off, addr = bank_address(start)
            printable = sum(1 for b in chunk if 0x20 <= b <= 0x7E)
            high = sum(1 for b in chunk if b >= 0x80)
            rows.append({
                "offset": f"0x{start:06X}",
                "bank": f"0x{bank:02X}",
                "bank_offset": f"0x{bank_off:04X}",
                "address": f"0x{addr:04X}",
                "length": len(chunk),
                "ascii_ratio": round(printable / len(chunk), 3),
                "high_byte_ratio": round(high / len(chunk), 3),
                "entropy": round(byte_entropy(chunk), 3),
                "sample_hex": chunk[:32].hex(),
                "sample_ascii_lossy": ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in chunk[:64]),
            })
        start = None
        buf = []
    for i, b in enumerate(data + b"\0"):
        # Treat long nonzero, non-ff, non-random-ish byte streams as candidates.
        if b not in (0x00, 0xFF) and b < 0xF8:
            if start is None:
                start = i
            buf.append(b)
        else:
            flush(i)
    rows.sort(key=lambda r: (r["bank"], r["offset"]))
    return rows


def discover_tile_runs(data: bytes) -> list[dict]:
    rows = []
    run_start = None
    run_tiles = 0
    for off in range(0, len(data) - 16, 16):
        tile = data[off:off + 16]
        unique = len(set(tile))
        plausible = unique >= 2 and tile != b"\0" * 16 and tile != b"\xff" * 16
        if plausible:
            if run_start is None:
                run_start = off
                run_tiles = 0
            run_tiles += 1
        else:
            if run_start is not None and run_tiles >= 16:
                chunk = data[run_start:run_start + run_tiles * 16]
                bank, bank_off, addr = bank_address(run_start)
                rows.append({
                    "offset": f"0x{run_start:06X}",
                    "bank": f"0x{bank:02X}",
                    "bank_offset": f"0x{bank_off:04X}",
                    "address": f"0x{addr:04X}",
                    "tiles": run_tiles,
                    "bytes": run_tiles * 16,
                    "nonzero_bytes": sum(1 for b in chunk if b),
                    "unique_bytes": len(set(chunk)),
                    "entropy": round(byte_entropy(chunk), 3),
                })
            run_start = None
            run_tiles = 0
    return rows


def write_tsv(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fields is None:
        fields = list(rows[0].keys()) if rows else []
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))

def write_analysis(root: Path, target: str, data: bytes, manifest: list[dict]) -> None:
    out = root / "analysis" / target
    out.mkdir(parents=True, exist_ok=True)
    info = {
        "target": target,
        "size": len(data),
        "banks": len(data) // BANK_SIZE,
        "sha1": sha1(data),
        "header": rom_header(data),
    }
    (out / "rom_info.json").write_text(json.dumps(info, indent=2))
    (out / "bank_manifest.json").write_text(json.dumps(manifest, indent=2))

    with (out / "byte_histogram.tsv").open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["byte", "count"])
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for i, c in enumerate(counts):
            w.writerow([f"0x{i:02X}", c])

    # Legacy TSVs kept for compatibility with earlier project snapshots.
    write_ascii_strings(out / "ascii_strings.tsv", data)
    write_pointer_candidates(out / "pointer_candidates.tsv", data)
    write_tile_runs(out / "tile_runs.tsv", data)

    banks = []
    for bank in range(len(data) // BANK_SIZE):
        chunk = data[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
        banks.append({
            "bank": f"0x{bank:02X}",
            "offset": f"0x{bank * BANK_SIZE:06X}",
            "size": BANK_SIZE,
            "sha1": sha1(chunk),
            "entropy": round(byte_entropy(chunk), 3),
            "zero_bytes": chunk.count(0),
            "ff_bytes": chunk.count(0xFF),
            "ascii_printable_bytes": sum(1 for b in chunk if 0x20 <= b <= 0x7E),
            "high_bytes": sum(1 for b in chunk if b >= 0x80),
        })
    write_json(out / "banks.json", banks)
    write_tsv(out / "banks.tsv", banks)

    pointer_tables = discover_pointer_tables(data)
    write_json(out / "pointer_tables.json", pointer_tables)
    write_tsv(out / "pointer_tables.tsv", pointer_tables)

    text_candidates = discover_text_like_runs(data)
    write_json(out / "text_candidates.json", text_candidates[:5000])
    write_tsv(out / "text_candidates.tsv", text_candidates[:5000])

    tile_candidates = discover_tile_runs(data)
    write_json(out / "tile_candidates.json", tile_candidates)
    write_tsv(out / "tile_candidates.tsv", tile_candidates)

    free_space = find_runs(data, 0xFF, 32) + find_runs(data, 0x00, 32)
    free_space.sort(key=lambda r: (r["bank"], r["offset"]))
    write_json(out / "free_space.json", free_space)
    write_tsv(out / "free_space.tsv", free_space)

    symbols = {
        "target": target,
        "note": "Auto-generated analysis symbols; verify manually before treating as code/data labels.",
        "entry_points": [
            {"name": "RST_00", "bank": "0x00", "address": "0x0000", "offset": "0x000000"},
            {"name": "Header", "bank": "0x00", "address": "0x0100", "offset": "0x000100"},
        ],
        "pointer_tables": pointer_tables[:100],
        "tile_candidates": tile_candidates[:100],
    }
    write_json(out / "symbols.json", symbols)

    report = [
        f"Robopon analysis report for {target}",
        "",
        f"ROM SHA1: {sha1(data)}",
        f"Banks: {len(data)//BANK_SIZE}",
        "",
        "Generated files:",
        "- rom_info.json",
        "- banks.json / banks.tsv",
        "- pointer_tables.json / pointer_tables.tsv",
        "- text_candidates.json / text_candidates.tsv",
        "- tile_candidates.json / tile_candidates.tsv",
        "- free_space.json / free_space.tsv",
        "- symbols.json",
        "",
        "These are heuristics. Use them to guide manual labeling, then replace INCBIN ranges gradually.",
    ]
    (out / "REPORT.md").write_text("\n".join(report) + "\n")


def write_ascii_strings(path: Path, data: bytes, min_len: int = 4) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["offset", "bank", "bank_offset", "text"])
        start = None
        buf = []
        for i, b in enumerate(data + b"\0"):
            if 0x20 <= b <= 0x7E:
                if start is None:
                    start = i
                buf.append(chr(b))
            else:
                if start is not None and len(buf) >= min_len:
                    bank = start // BANK_SIZE
                    boff = start % BANK_SIZE
                    w.writerow([f"0x{start:06X}", f"0x{bank:02X}", f"0x{boff:04X}", ''.join(buf)])
                start = None
                buf = []


def write_pointer_candidates(path: Path, data: bytes) -> None:
    with path.open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["table_offset", "bank", "count", "first_ptr", "last_ptr", "monotonic"])
        # Simple scanner for runs of little-endian ROMX pointers $4000-$7FFF.
        for off in range(0, len(data) - 8, 2):
            ptrs = []
            p = off
            while p + 1 < len(data):
                val = data[p] | (data[p + 1] << 8)
                if 0x4000 <= val <= 0x7FFF:
                    ptrs.append(val)
                    p += 2
                else:
                    break
            if len(ptrs) >= 8:
                monotonic = all(a <= b for a, b in zip(ptrs, ptrs[1:]))
                if monotonic or len(ptrs) >= 16:
                    w.writerow([f"0x{off:06X}", f"0x{off // BANK_SIZE:02X}", len(ptrs), f"0x{ptrs[0]:04X}", f"0x{ptrs[-1]:04X}", int(monotonic)])


def write_tile_runs(path: Path, data: bytes) -> None:
    # Heuristic: runs that look like Game Boy 2bpp tiles and are not all blank/full.
    with path.open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["offset", "bank", "tiles", "nonzero_bytes", "unique_bytes"])
        run_start = None
        run_tiles = 0
        for off in range(0, len(data) - 16, 16):
            tile = data[off:off + 16]
            unique = len(set(tile))
            plausible = unique >= 2 and tile != b"\0" * 16 and tile != b"\xff" * 16
            if plausible:
                if run_start is None:
                    run_start = off
                    run_tiles = 0
                run_tiles += 1
            else:
                if run_start is not None and run_tiles >= 16:
                    chunk = data[run_start:run_start + run_tiles * 16]
                    w.writerow([f"0x{run_start:06X}", f"0x{run_start // BANK_SIZE:02X}", run_tiles, sum(1 for b in chunk if b), len(set(chunk))])
                run_start = None
                run_tiles = 0



def hex_to_int(x) -> int:
    if isinstance(x, int):
        return x
    return int(str(x), 16) if str(x).lower().startswith('0x') else int(x)


def rgbds_label(s: str) -> str:
    out = []
    for ch in s:
        if ch.isalnum() or ch == '_':
            out.append(ch)
        else:
            out.append('_')
    name = ''.join(out).strip('_') or 'Label'
    if name[0].isdigit():
        name = '_' + name
    return name


def load_analysis_anchors(root: Path, target: str, max_per_kind: int = 64) -> dict[int, list[tuple[int, str, str]]]:
    """Return bank -> list of (bank_offset, label, comment) from analysis files.

    These labels are intentionally conservative: they only mark suspected data starts and
    never replace bytes. The generated assembly still emits the original bytes via INCBIN.
    """
    out: dict[int, list[tuple[int, str, str]]] = {}
    analysis = root / 'analysis' / target

    def add(bank: int, bank_off: int, label: str, comment: str) -> None:
        if not (0 <= bank_off < BANK_SIZE):
            return
        out.setdefault(bank, []).append((bank_off, rgbds_label(label), comment))

    # Fixed hardware-visible labels for ROM0.
    add(0, 0x0000, 'RST_00', 'reset vector / rst table area')
    add(0, 0x0100, 'EntryPoint', 'cartridge entry point')
    add(0, 0x0104, 'NintendoLogo', 'Nintendo logo data')
    add(0, 0x0134, 'ROMHeader_Title', 'ROM header title')
    add(0, 0x0143, 'ROMHeader_CGBFlag', 'ROM header CGB flag')
    add(0, 0x0147, 'ROMHeader_CartType', 'ROM header cart type')
    add(0, 0x014D, 'ROMHeader_HeaderChecksum', 'ROM header checksum')
    add(0, 0x014E, 'ROMHeader_GlobalChecksum', 'ROM header global checksum')
    add(0, 0x0150, 'StartAfterHeader', 'first byte after ROM header')

    sources = [
        ('pointer_tables.json', 'PtrTable', 'suspected pointer table'),
        ('text_candidates.json', 'TextCandidate', 'suspected text/data run'),
        ('tile_candidates.json', 'TileCandidate', 'suspected 2bpp tile run'),
        ('free_space.json', 'FreeSpace', 'free-space run'),
    ]
    for filename, prefix, comment in sources:
        path = analysis / filename
        if not path.exists():
            continue
        try:
            rows = json.loads(path.read_text())
        except Exception:
            continue
        for i, row in enumerate(rows[:max_per_kind]):
            try:
                bank = hex_to_int(row.get('bank', 0))
                boff = hex_to_int(row.get('bank_offset', row.get('address', 0)))
                # If an address in ROMX was used, convert it to a bank-local offset.
                if bank != 0 and 0x4000 <= boff <= 0x7FFF:
                    boff -= 0x4000
                add(bank, boff, f'{target}_{prefix}_{bank:02X}_{boff:04X}', comment)
            except Exception:
                pass
    return out


def write_progressive_disasm(root: Path, target: str, data: bytes, max_labels: int = 256) -> None:
    """Generate RGBDS assembly made of labeled INCBIN slices.

    This is a real disassembly scaffold: it preserves exact ROM bytes while giving us
    safe replacement points. A future manual edit can replace any single INCBIN slice
    with actual instructions/data and `make && compare` proves correctness.
    """
    bank_count = len(data) // BANK_SIZE
    # Ensure split bank binaries exist; these are local build artifacts, not source ROMs.
    split_banks(data, root, target)

    asm_dir = root / 'asm' / target
    asm_dir.mkdir(parents=True, exist_ok=True)
    anchors_by_bank = load_analysis_anchors(root, target)

    main_lines = [
        '; Auto-generated progressive RGBDS disassembly scaffold.\n',
        '; Each bank file emits exact original bytes using labeled INCBIN ranges.\n',
        '; Replace individual ranges with hand-written asm/data, then run make + compare.\n',
        'INCLUDE "macros/hardware.inc"\n',
        'INCLUDE "macros/bank_macros.inc"\n',
        '\n',
    ]
    for bank in range(bank_count):
        main_lines.append(f'INCLUDE "asm/{target}/bank_{bank:02X}.asm"\n')
    (asm_dir / 'main.asm').write_text(''.join(main_lines))

    symbol_rows = []
    for bank in range(bank_count):
        base_addr = 0x0000 if bank == 0 else 0x4000
        section = f'SECTION "ROM0", ROM0[$0000]' if bank == 0 else f'SECTION "Bank {bank:02X}", ROMX[$4000], BANK[${bank:02X}]'
        anchors = [(0, f'{target}_Bank{bank:02X}_Start', 'bank start')]
        anchors += anchors_by_bank.get(bank, [])
        # Deduplicate by offset while preserving first useful name.
        dedup = {}
        for boff, label, comment in anchors:
            if 0 <= boff < BANK_SIZE and boff not in dedup:
                dedup[boff] = (label, comment)
        sorted_anchors = sorted(dedup.items())[:max_labels]
        points = sorted({0, BANK_SIZE, *[boff for boff, _ in sorted_anchors]})
        lines = [
            f'; Auto-generated bank {bank:02X} progressive scaffold.\n',
            f'; Source bytes: banks/{target}/bank_{bank:02X}.bin\n',
            f'{section}\n',
            '\n',
        ]
        label_at = {boff: meta for boff, meta in sorted_anchors}
        for a, b in zip(points, points[1:]):
            if a in label_at:
                label, comment = label_at[a]
                addr = base_addr + a
                lines.append(f'; ${addr:04X} / bank offset ${a:04X}: {comment}\n')
                lines.append(f'{label}::\n')
                symbol_rows.append({
                    'bank': f'0x{bank:02X}',
                    'bank_offset': f'0x{a:04X}',
                    'address': f'0x{addr:04X}',
                    'label': label,
                    'comment': comment,
                })
            length = b - a
            if length:
                lines.append(f'    INCBIN "banks/{target}/bank_{bank:02X}.bin", ${a:04X}, ${length:04X}\n')
                lines.append('\n')
        (asm_dir / f'bank_{bank:02X}.asm').write_text(''.join(lines))

    disasm_dir = root / 'analysis' / target
    write_tsv(disasm_dir / 'disasm_labels.tsv', symbol_rows, ['bank','bank_offset','address','label','comment'])
    write_json(disasm_dir / 'disasm_labels.json', symbol_rows)
    (disasm_dir / 'DISASM_REPORT.md').write_text('\n'.join([
        f'Progressive disassembly scaffold for {target}',
        '',
        f'Banks emitted: {bank_count}',
        f'Labels emitted: {len(symbol_rows)}',
        '',
        'The generated asm preserves exact ROM bytes because every range is still emitted with INCBIN.',
        'To progress the disassembly, replace one labeled INCBIN range at a time with RGBDS code/data,',
        'then run `make TARGET` and `python3 tools/robopon.py compare ...`.',
        '',
        'Generated files:',
        f'- asm/{target}/main.asm',
        f'- asm/{target}/bank_XX.asm',
        f'- analysis/{target}/disasm_labels.tsv',
    ]) + '\n')


def cmd_disasm(args: argparse.Namespace) -> None:
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    data = read_rom(Path(args.rom))
    # Make sure current heuristics are available for labels. This does not alter asm.
    manifest = []
    for bank in range(len(data) // BANK_SIZE):
        chunk = data[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
        manifest.append({
            'bank': bank,
            'sha1': sha1(chunk),
            'size': len(chunk),
            'non_ff_bytes': sum(1 for b in chunk if b != 0xFF),
            'non_00_bytes': sum(1 for b in chunk if b != 0x00),
        })
    write_analysis(root, target, data, manifest)
    write_progressive_disasm(root, target, data, max_labels=args.max_labels)
    print(f"generated progressive RGBDS disassembly for {target}")
    print(f"wrote asm/{target}/main.asm and asm/{target}/bank_XX.asm")
    print(f"wrote analysis/{target}/disasm_labels.tsv")
    print("run: make %s && python3 tools/robopon.py compare --rom %s --built build/%s.gbc" % (target, args.rom, target))


def cmd_init(args: argparse.Namespace) -> None:
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    rom_path = Path(args.rom)
    data = read_rom(rom_path)
    manifest = split_banks(data, root, target)
    write_asm_scaffold(root, target, len(data) // BANK_SIZE)
    write_analysis(root, target, data, manifest)
    print(f"initialized {target}: {len(data)} bytes, {len(data)//BANK_SIZE} banks")
    print(f"generated asm/{target}/main.asm and banks/{target}/bank_XX.bin")



def cmd_analyze(args: argparse.Namespace) -> None:
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    rom_path = Path(args.rom)
    data = read_rom(rom_path)
    # Do not overwrite bank files or assembly during analyze. This command only writes analysis output.
    manifest = []
    for bank in range(len(data) // BANK_SIZE):
        chunk = data[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
        manifest.append({
            "bank": bank,
            "sha1": sha1(chunk),
            "size": len(chunk),
            "non_ff_bytes": sum(1 for b in chunk if b != 0xFF),
            "non_00_bytes": sum(1 for b in chunk if b != 0x00),
        })
    write_analysis(root, target, data, manifest)
    out = root / "analysis" / target
    print(f"analyzed {target}: {len(data)} bytes, {len(data)//BANK_SIZE} banks")
    print(f"wrote {out}")
    print("key files: banks.tsv, pointer_tables.tsv, text_candidates.tsv, tile_candidates.tsv, free_space.tsv")


def cmd_text_dump(args: argparse.Namespace) -> None:
    from lib.text_engine import dump_all_text, write_text_outputs, read_charmap, render_tokens_with_charmap, parse_token_hex
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    data = read_rom(Path(args.rom))
    out = Path(args.out) if args.out else root / "text" / target
    rows = dump_all_text(data, target)
    if getattr(args, 'charmap', None):
        cmap = read_charmap(Path(args.charmap))
        for r in rows:
            r['text_japanese'] = r.get('text', '')
            r['text'] = render_tokens_with_charmap(parse_token_hex(str(r.get('raw_tokens', ''))), cmap)
    write_text_outputs(rows, out)
    print(f"decoded {len(rows)} compressed text entries for {target}")
    print(f"wrote {out / 'text_dump.tsv'}")
    print(f"wrote {out / 'text_dump.json'}")


def cmd_text_roundtrip(args: argparse.Namespace) -> None:
    from lib.text_engine import roundtrip_report
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    data = read_rom(Path(args.rom))
    report = roundtrip_report(data, target)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["entries"] != report["roundtrip_ok"]:
        raise SystemExit(1)


def cmd_text_tree(args: argparse.Namespace) -> None:
    from lib.text_engine import rip_tree, code_map, iter_leaves, stream_specs_for_target
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    data = read_rom(Path(args.rom))
    out_dir = Path(args.out) if args.out else root / "analysis" / target / "text_engine"
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = []
    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        cmap = code_map(tree)
        rows = []
        for token, bits in sorted(cmap.items(), key=lambda x: (len(x[1]), x[1], x[0])):
            rows.append({"token": f"0x{token:02X}", "bits": bits, "bit_length": len(bits)})
        with (out_dir / f"{spec.name}_tree_codes.tsv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["token", "bits", "bit_length"], delimiter="\t")
            w.writeheader(); w.writerows(rows)
        summary.append({"stream": spec.name, "table": f"0x{spec.table:06X}", "tree": f"0x{spec.tree:06X}", "leaf_count": len(list(iter_leaves(tree)))})
    (out_dir / "tree_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote text tree reports to {out_dir}")




def cmd_huffman_export(args: argparse.Namespace) -> None:
    """Export the actual Huffman leaf token map from the ROM text engine.

    This is the authoritative source for which one-byte tokens the current ROM's
    text encoder can emit.  The font PNG only tells you what each glyph looks
    like; this command tells you which tokens exist in the compressed text tree.
    """
    from lib.text_engine import rip_tree, code_map, stream_specs_for_target, render_tokens
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    data = read_rom(Path(args.rom))
    out_dir = Path(args.out_dir) if getattr(args, 'out_dir', None) else root / 'translation' / target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_tsv = Path(args.out) if getattr(args, 'out', None) else out_dir / 'huffman_token_map.tsv'
    out_json = out_tsv.with_suffix('.json')

    specs = stream_specs_for_target(target)
    stream_maps: dict[str, dict[int, str]] = {}
    all_tokens: set[int] = set()
    for spec in specs:
        tree = rip_tree(data, spec.tree)
        cmap = code_map(tree)
        stream_maps[spec.name] = cmap
        all_tokens.update(cmap.keys())

    rows = []
    stream_names = [s.name for s in specs]
    for token in sorted(all_tokens):
        row = {
            'token_hex': f'0x{token:02X}',
            'token_dec': token,
            'default_text': render_tokens([token, 0x00]),
            'kind': 'control' if token < 0x20 or token in (0x28, 0x29) else ('ascii' if 0x20 <= token < 0x7F else 'kana_or_symbol'),
        }
        for name in stream_names:
            bits = stream_maps[name].get(token)
            row[f'{name}_encodable'] = 'yes' if bits is not None else 'no'
            row[f'{name}_bits'] = bits or ''
            row[f'{name}_bit_length'] = len(bits) if bits is not None else ''
        rows.append(row)

    fieldnames = ['token_hex', 'token_dec', 'default_text', 'kind']
    for name in stream_names:
        fieldnames += [f'{name}_encodable', f'{name}_bits', f'{name}_bit_length']
    with out_tsv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter='\t')
        w.writeheader()
        w.writerows(rows)

    # Also write a starter charmap template using only tokens encodable by every stream.
    common = sorted(set.intersection(*(set(m.keys()) for m in stream_maps.values()))) if stream_maps else []
    template = out_dir / 'charmap_from_huffman.template.tsv'
    with template.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['char', 'tokens', 'default_text', 'note'], delimiter='\t')
        w.writeheader()
        for token in common:
            txt = render_tokens([token, 0x00])
            # Leave char blank intentionally; the user assigns the English glyph
            # based on the edited font sheet.
            w.writerow({'char': '', 'tokens': f'{token:02X}', 'default_text': txt, 'note': 'fill char with the English glyph you drew for this token'})

    report = {
        'target': target,
        'rom': str(args.rom),
        'streams': [{
            'name': spec.name,
            'table': f'0x{spec.table:06X}',
            'tree': f'0x{spec.tree:06X}',
            'leaf_count': len(stream_maps[spec.name]),
        } for spec in specs],
        'union_token_count': len(all_tokens),
        'common_token_count': len(common),
        'outputs': {
            'token_map_tsv': str(out_tsv),
            'token_map_json': str(out_json),
            'charmap_template': str(template),
        }
    }
    out_json.write_text(json.dumps({'report': report, 'rows': rows}, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'wrote Huffman token map: {out_tsv}')
    print(f'wrote JSON: {out_json}')
    print(f'wrote starter charmap template: {template}')
    print(json.dumps(report, ensure_ascii=False, indent=2))


def cmd_punctuation_scan(args: argparse.Namespace) -> None:
    """Find punctuation-like Huffman tokens that are safe to use in translations.

    This command is intentionally conservative.  It reports every one-byte token
    in the target text trees that renders as punctuation or a small printable
    symbol, marks whether it is encodable by each stream, counts how often it is
    used in decoded text, and writes a starter punctuation charmap.
    """
    from lib.text_engine import (
        rip_tree, code_map, stream_specs_for_target, render_tokens,
        dump_all_text,
    )

    target = normalize_target(args.target)
    if target not in TARGETS:
        raise SystemExit(f"unknown target {args.target}")
    data = read_rom(Path(args.rom))
    root = Path(args.root).resolve()
    out_dir = Path(args.out_dir) if getattr(args, 'out_dir', None) else root / 'translation' / target
    out_dir.mkdir(parents=True, exist_ok=True)
    out_tsv = Path(args.out) if getattr(args, 'out', None) else out_dir / 'punctuation_tokens.tsv'
    out_json = out_tsv.with_suffix('.json')
    out_charmap = Path(args.charmap_out) if getattr(args, 'charmap_out', None) else out_dir / 'punctuation_charmap.template.tsv'

    # Punctuation candidates we commonly want in English translation.
    wanted = set(" .,!?\"'():;-+/&%#@[]<>*_=")
    # Treat these as engine controls even if they are printable-looking.
    hard_controls = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x28, 0x29}

    specs = stream_specs_for_target(target)
    stream_maps: dict[str, dict[int, str]] = {}
    all_tokens: set[int] = set()
    for spec in specs:
        tree = rip_tree(data, spec.tree)
        cmap = code_map(tree)
        stream_maps[spec.name] = cmap
        all_tokens.update(cmap.keys())

    # Count observed usage in the dumped streams.  This is useful for deciding
    # whether a token is normal text punctuation or a rare control/special byte.
    usage: dict[int, dict[str, int]] = {t: {s.name: 0 for s in specs} for t in all_tokens}
    try:
        rows_dump = dump_all_text(data, target)
        for row in rows_dump:
            stream = row.get('stream', '')
            raw = row.get('raw_tokens', '')
            for part in str(raw).split():
                try:
                    tok = int(part, 16)
                except Exception:
                    continue
                if tok in usage and stream in usage[tok]:
                    usage[tok][stream] += 1
    except Exception:
        # Punctuation scan should still work even if full text dumping fails.
        pass

    rows = []
    for token in sorted(all_tokens):
        rendered = render_tokens([token, 0x00])
        # render_tokens hides font-page mode tokens and renders control aliases;
        # add explicit labels for important controls.
        if token == 0x20:
            display = '<SPACE>'
            english = ' '
        elif rendered == '\\n':
            display = '<NEWLINE>'
            english = ''
        elif rendered == '':
            display = '<MODE/EMPTY>'
            english = ''
        else:
            display = rendered
            english = rendered if rendered in wanted else ''

        is_control = token in hard_controls or (display.startswith('<') and display.endswith('>') and display not in ('<SPACE>',))
        is_candidate = (english in wanted and english != '') or token == 0x20
        # A safe punctuation token must exist in the dialogue tree, not be a
        # hard control, and render to a desired printable punctuation/symbol.
        safe = bool(is_candidate and not is_control and stream_maps.get('dialogue', {}).get(token) is not None)
        reason = []
        if token in hard_controls:
            reason.append('reserved/control')
        if not is_candidate:
            reason.append('not common English punctuation')
        if stream_maps.get('dialogue', {}).get(token) is None:
            reason.append('not encodable by dialogue stream')
        if not reason:
            reason.append('printable punctuation candidate')

        row = {
            'token_hex': f'0x{token:02X}',
            'token_dec': token,
            'display': display,
            'suggested_char': english,
            'safe_for_translation': 'yes' if safe else 'no',
            'reason': '; '.join(reason),
        }
        for spec in specs:
            bits = stream_maps[spec.name].get(token)
            row[f'{spec.name}_encodable'] = 'yes' if bits is not None else 'no'
            row[f'{spec.name}_bits'] = bits or ''
            row[f'{spec.name}_bit_length'] = len(bits) if bits is not None else ''
            row[f'{spec.name}_uses'] = usage.get(token, {}).get(spec.name, 0)
        rows.append(row)

    fieldnames = ['token_hex', 'token_dec', 'display', 'suggested_char', 'safe_for_translation', 'reason']
    for spec in specs:
        fieldnames += [f'{spec.name}_encodable', f'{spec.name}_bits', f'{spec.name}_bit_length', f'{spec.name}_uses']
    with out_tsv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, delimiter='\t')
        w.writeheader(); w.writerows(rows)

    # Starter charmap rows for safe punctuation only. The user can paste these
    # into translation/<target>/charmap.tsv.
    with out_charmap.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['char', 'tokens', 'note'], delimiter='\t')
        w.writeheader()
        for row in rows:
            if row['safe_for_translation'] == 'yes' and row['suggested_char'] != '':
                ch = row['suggested_char']
                visible = '<SPACE>' if ch == ' ' else ch
                w.writerow({
                    'char': visible,
                    'tokens': row['token_hex'].replace('0x', ''),
                    'note': f"original punctuation token; {row['display']}; {row['reason']}",
                })

    report = {
        'target': target,
        'rom': str(args.rom),
        'output': str(out_tsv),
        'json': str(out_json),
        'charmap_template': str(out_charmap),
        'safe_count': sum(1 for r in rows if r['safe_for_translation'] == 'yes'),
        'candidate_count': sum(1 for r in rows if r['suggested_char'] != ''),
        'note': 'Use safe_for_translation=yes rows as punctuation tokens in charmap.tsv. Do not use END/newline/mode/control tokens as printable characters.',
    }
    out_json.write_text(json.dumps({'report': report, 'rows': rows}, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'wrote punctuation scan: {out_tsv}')
    print(f'wrote JSON: {out_json}')
    print(f'wrote punctuation charmap template: {out_charmap}')
    print(json.dumps(report, ensure_ascii=False, indent=2))


def cmd_charmap_export(args: argparse.Namespace) -> None:
    from lib.text_engine import default_latin_kana_charmap, write_charmap_tsv, charmap_coverage_report
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    data = read_rom(Path(args.rom))
    mapping = default_latin_kana_charmap(start_token=int(args.start_token, 0))
    out = Path(args.out) if args.out else Path(args.root) / 'translation' / target / 'charmap.tsv'
    write_charmap_tsv(out, mapping, note='kana-slot English character; edit tokens only if your font slot order differs')
    report = charmap_coverage_report(data, target, mapping)
    out.with_suffix('.validate.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'wrote charmap: {out}')
    print(f'wrote validation: {out.with_suffix(".validate.json")}')
    print(json.dumps(report, ensure_ascii=False, indent=2))



def cmd_charmap_from_font(args: argparse.Namespace) -> None:
    """Generate token -> tile mapping rows from a dialogue font sheet.

    This command does not try to OCR the glyphs. It only records the mechanical
    relationship needed by the translation tooling: each row-major font tile can
    be associated with an engine/Huffman token range. Character labels can be
    filled later in the char column, or generated separately by charmap-export.
    """
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")

    if not (args.font or args.png):
        raise SystemExit('charmap-from-font requires --font or --png')
    font_path = Path(args.font or args.png)
    if not font_path.exists():
        raise SystemExit(f"font PNG not found: {font_path}")

    meta = {}
    meta_path = Path(args.meta) if args.meta else font_path.with_suffix('.json')
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding='utf-8'))

    # Prefer export metadata because it records the logical tile count/columns,
    # even if the PNG has padding or a display scale. Fall back to image geometry.
    columns = int(args.columns or meta.get('columns') or 16)
    scale = int(args.scale or meta.get('scale') or 1)
    tiles = args.tiles or meta.get('tiles')
    if tiles is None:
        try:
            from PIL import Image
            im = Image.open(font_path)
            tile_px = 8 * scale
            columns = max(1, im.width // tile_px)
            rows = max(1, im.height // tile_px)
            tiles = columns * rows
        except Exception as e:
            raise SystemExit(f"could not infer tile count from {font_path}; pass --tiles: {e}")
    tiles = int(tiles)

    start_token = int(args.start_token, 0)
    tile_start = int(args.tile_start, 0)
    count = int(args.count) if args.count is not None else tiles - tile_start
    if count < 0:
        raise SystemExit("--count cannot be negative")
    if tile_start < 0 or tile_start >= tiles:
        raise SystemExit(f"--tile-start 0x{tile_start:X} is outside the font tile range 0..0x{tiles-1:X}")
    count = min(count, tiles - tile_start)

    chars = args.chars or ''
    rows = []
    for i in range(count):
        tile = tile_start + i
        token = start_token + i
        rows.append({
            'token_hex': f'0x{token:02X}',
            'tile_hex': f'0x{tile:02X}',
            'tile_index': tile,
            'row': tile // columns,
            'col': tile % columns,
            'char': chars[i] if i < len(chars) else '',
            'comment': 'token to row-major font tile mapping; fill char after visual verification' if not chars else 'character label supplied by --chars',
        })

    out = Path(args.out) if args.out else Path(args.root) / 'translation' / target / 'token_tile_map.tsv'
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['token_hex','tile_hex','tile_index','row','col','char','comment'], delimiter='	')
        w.writeheader(); w.writerows(rows)

    report = {
        'target': target,
        'font': str(font_path),
        'metadata': str(meta_path) if meta_path.exists() else None,
        'tiles_in_font': tiles,
        'columns': columns,
        'scale': scale,
        'start_token': f'0x{start_token:02X}',
        'tile_start': f'0x{tile_start:02X}',
        'count': count,
        'out': str(out),
        'note': 'This file maps engine tokens to font tile indexes. It does not infer glyph identity from pixels.',
    }
    out.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f"wrote token->tile map: {out}")
    print(f"wrote report: {out.with_suffix('.json')}")
    print(json.dumps(report, ensure_ascii=False, indent=2))



def _parse_ordered_charmap_rows(path: Path) -> list[dict[str, object]]:
    """Read a charmap TSV preserving order and raw token values.

    Returns rows with char and first token. This intentionally accepts tokens
    above 0xFF so an oversized visual map can be used as a source-location map
    before compacting it into real Huffman byte tokens.
    """
    rows: list[dict[str, object]] = []
    with path.open('r', encoding='utf-8', errors='replace', newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        for r in reader:
            ch = (r.get('char') or r.get('glyph') or '').replace('\r','').replace('\n','')
            aliases = {'<SPACE>':' ', '[SPACE]':' ', 'SPACE':' ', '\\s':' ', '<NL>':'\\n', '<NEWLINE>':'\\n', '[NEWLINE]':'\\n'}
            ch = aliases.get(ch, ch)
            raw = (r.get('tokens') or r.get('token') or r.get('token_hex') or '').strip()
            if not ch or not raw:
                continue
            raw_first = raw.replace(',', ' ').split()[0]
            try:
                tok = int(raw_first, 0) if raw_first.lower().startswith('0x') else int(raw_first, 16)
            except Exception:
                continue
            rows.append({'char': ch, 'token': tok, 'raw': raw})
    return rows


def _copy_font_tile(src, dst, src_tile: int, dst_tile: int, *, columns: int, tile_px: int) -> None:
    sx = (src_tile % columns) * tile_px
    sy = (src_tile // columns) * tile_px
    dx = (dst_tile % columns) * tile_px
    dy = (dst_tile // columns) * tile_px
    if sx < 0 or sy < 0 or sx + tile_px > src.width or sy + tile_px > src.height:
        return
    tile = src.crop((sx, sy, sx + tile_px, sy + tile_px))
    dst.paste(tile, (dx, dy))


def cmd_font_compact(args: argparse.Namespace) -> None:
    """Move selected English glyphs into real 00-FF Huffman byte-token slots.

    Robopon text tokens are bytes. A visual font sheet can have more tiles than
    the original Huffman tree can encode, but translation-build can only emit
    tokens that are leaves in the tree. This command copies chosen glyphs into
    encodable token slots and writes a matching charmap.
    """
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    png = Path(args.png or args.font)
    source_charmap = Path(args.charmap)
    if not png.exists():
        raise SystemExit(f"font PNG not found: {png}")
    if not source_charmap.exists():
        raise SystemExit(f"charmap not found: {source_charmap}")
    try:
        from PIL import Image
    except Exception as e:
        raise SystemExit(f"font-compact requires Pillow/PIL: {e}")
    from lib.text_engine import rip_tree, code_map, stream_specs_for_target

    data = read_rom(Path(args.rom))
    specs = stream_specs_for_target(target)
    if args.stream == 'all':
        valid_sets = []
        for spec in specs:
            cmap = code_map(rip_tree(data, spec.tree))
            valid_sets.append(set(cmap.keys()))
        valid = set.intersection(*valid_sets) if valid_sets else set()
    else:
        spec = next((x for x in specs if x.name == args.stream), None)
        if spec is None:
            raise SystemExit(f"unknown stream {args.stream!r}; use one of: " + ', '.join(x.name for x in specs))
        valid = set(code_map(rip_tree(data, spec.tree)).keys())

    min_token = int(args.min_token, 0)
    max_token = int(args.max_token, 0)
    start_token = int(args.start_token, 0)
    valid_tokens = sorted(t for t in valid if min_token <= t <= max_token)
    if not valid_tokens:
        raise SystemExit(f"no encodable tokens found in range 0x{min_token:02X}-0x{max_token:02X}")

    rows = _parse_ordered_charmap_rows(source_charmap)
    by_char: dict[str, int] = {}
    for r in rows:
        ch = str(r['char'])
        tok = int(r['token'])
        # A visual oversized map usually used token = start_token + tile_index.
        # Convert back to the source tile index.
        tile = tok - start_token
        if tile < 0:
            tile = tok
        if ch not in by_char:
            by_char[ch] = tile

    default_chars = ' ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?\'\"-:/()'
    chars = args.chars if args.chars is not None else default_chars
    # Decode escapes so users can pass "\\n" if desired, but do not include newline by default.
    chars = chars.encode('utf-8').decode('unicode_escape')
    wanted = []
    seen = set()
    for ch in chars:
        if ch in seen:
            continue
        seen.add(ch)
        if ch not in by_char:
            raise SystemExit(f"character {ch!r} is not present in source charmap {source_charmap}")
        wanted.append(ch)
    if len(wanted) > len(valid_tokens):
        raise SystemExit(f"selected {len(wanted)} characters but only {len(valid_tokens)} encodable tokens are available in {args.stream} range 0x{min_token:02X}-0x{max_token:02X}. Use fewer chars or rebuild/patch the Huffman tree.")

    meta = {}
    meta_path = Path(args.meta) if args.meta else png.with_suffix('.json')
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding='utf-8'))
        except Exception:
            meta = {}
    columns = int(args.columns or meta.get('columns') or 16)
    scale = int(args.scale or meta.get('scale') or 1)
    tile_px = int(args.tile_px or meta.get('tile_px') or (8 * scale))
    im = Image.open(png).convert('RGBA')
    out_png = Path(args.out_png) if args.out_png else png.with_name(png.stem + '.compact.png')
    out_charmap = Path(args.out_charmap) if args.out_charmap else source_charmap.with_name(source_charmap.stem + '.compact.tsv')
    out_png.parent.mkdir(parents=True, exist_ok=True)
    out_charmap.parent.mkdir(parents=True, exist_ok=True)

    # Start with the existing sheet so UI/non-character tiles remain intact.
    dst = im.copy()
    charmap_out: dict[str, list[int]] = {}
    placement_rows = []
    for ch, token in zip(wanted, valid_tokens):
        src_tile = by_char[ch]
        dst_tile = token - start_token
        if dst_tile < 0:
            raise SystemExit(f"token 0x{token:02X} is below start-token 0x{start_token:02X}; cannot convert to destination tile")
        _copy_font_tile(im, dst, src_tile, dst_tile, columns=columns, tile_px=tile_px)
        charmap_out[ch] = [token]
        placement_rows.append({'char': '<SPACE>' if ch == ' ' else ch, 'token_hex': f'0x{token:02X}', 'source_tile': f'0x{src_tile:02X}', 'dest_tile': f'0x{dst_tile:02X}'})
    # Preserve newline control.
    charmap_out['\\n'] = [0x0A]
    dst.save(out_png)

    with out_charmap.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['char','tokens','note'], delimiter='\t')
        w.writeheader()
        for ch in wanted:
            v = '<SPACE>' if ch == ' ' else ch
            w.writerow({'char': v, 'tokens': f'{charmap_out[ch][0]:02X}', 'note': 'compacted into encodable Huffman token range'})
        w.writerow({'char': '\\n', 'tokens': '0A', 'note': 'newline control'})

    placements = out_charmap.with_suffix('.placements.tsv')
    with placements.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['char','token_hex','source_tile','dest_tile'], delimiter='\t')
        w.writeheader(); w.writerows(placement_rows)
    report = {
        'target': target,
        'stream': args.stream,
        'source_png': str(png),
        'source_charmap': str(source_charmap),
        'out_png': str(out_png),
        'out_charmap': str(out_charmap),
        'placements': str(placements),
        'available_tokens': len(valid_tokens),
        'characters_written': len(wanted),
        'token_range': f'0x{min_token:02X}-0x{max_token:02X}',
        'note': 'Import out_png, then build translations using out_charmap. Full upper+lower+punctuation requires a rebuilt/expanded Huffman tree because the stock tree has too few encodable byte tokens.',
    }
    out_charmap.with_suffix('.report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'wrote compact font PNG: {out_png}')
    print(f'wrote compact charmap: {out_charmap}')
    print(f'wrote placements: {placements}')
    print(json.dumps(report, ensure_ascii=False, indent=2))
def cmd_font_token_grid(args: argparse.Namespace) -> None:
    """Overlay engine/Huffman token numbers directly on a font PNG grid.

    This is for translators editing kana-slot English fonts.  The number shown
    on each tile is the token to put in charmap.tsv for the glyph drawn in that
    tile, not the tile index and not ASCII.
    """
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    png = Path(args.png or args.font)
    if not png.exists():
        raise SystemExit(f"font PNG not found: {png}")
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception as e:
        raise SystemExit(f"font-token-grid requires Pillow/PIL: {e}")

    meta = {}
    meta_path = Path(args.meta) if args.meta else png.with_suffix('.json')
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding='utf-8'))
        except Exception:
            meta = {}

    im = Image.open(png).convert('RGBA')
    columns = int(args.columns or meta.get('columns') or 16)
    scale = int(args.scale or meta.get('scale') or 1)
    tile_px = int(args.tile_px or meta.get('tile_px') or (8 * scale))
    if tile_px <= 0:
        raise SystemExit('--tile-px must be positive')
    rows = (im.height + tile_px - 1) // tile_px
    inferred_tiles = columns * rows
    tiles = int(args.tiles or meta.get('tiles') or inferred_tiles)
    tiles = min(tiles, inferred_tiles)
    start_token = int(args.start_token, 0)
    tile_start = int(args.tile_start, 0)
    count = int(args.count) if args.count is not None else tiles - tile_start
    count = max(0, min(count, tiles - tile_start))

    # Make a scaled copy if source is unscaled 1x so labels are readable.
    display_scale = int(args.display_scale or (2 if max(im.width, im.height) < 512 else 1))
    base = im.resize((im.width * display_scale, im.height * display_scale), Image.Resampling.NEAREST) if display_scale != 1 else im.copy()
    draw = ImageDraw.Draw(base)
    try:
        font = ImageFont.truetype('DejaVuSansMono-Bold.ttf', max(9, 8 * display_scale))
        small = ImageFont.truetype('DejaVuSansMono.ttf', max(8, 7 * display_scale))
    except Exception:
        font = small = ImageFont.load_default()

    cell = tile_px * display_scale
    # grid lines
    for c in range(columns + 1):
        x = c * cell
        draw.line([(x, 0), (x, base.height)], fill=(255, 0, 0, 180), width=max(1, display_scale))
    for r in range(rows + 1):
        y = r * cell
        draw.line([(0, y), (base.width, y)], fill=(255, 0, 0, 180), width=max(1, display_scale))

    # labels: token on top-left; tile index on bottom-left for reference.
    for i in range(count):
        tile = tile_start + i
        token = start_token + tile
        r, c = divmod(tile, columns)
        x, y = c * cell, r * cell
        # light background behind token label
        draw.rectangle([x+1, y+1, x + min(cell-1, 34*display_scale), y + 11*display_scale], fill=(255,255,255,215))
        draw.text((x + 2*display_scale, y + 1*display_scale), f'{token:02X}', fill=(0,0,220,255), font=font)
        draw.rectangle([x+1, y + cell - 10*display_scale, x + min(cell-1, 30*display_scale), y + cell - 1], fill=(255,255,255,190))
        draw.text((x + 2*display_scale, y + cell - 10*display_scale), f't{tile:02X}', fill=(80,80,80,255), font=small)

    out = Path(args.out) if args.out else png.with_name(png.stem + '.token-grid.png')
    out.parent.mkdir(parents=True, exist_ok=True)
    base.save(out)

    tsv = Path(args.tsv) if args.tsv else out.with_suffix('.tsv')
    rows_out = []
    for i in range(count):
        tile = tile_start + i
        token = start_token + tile
        rows_out.append({
            'token_hex': f'0x{token:02X}',
            'tile_hex': f'0x{tile:02X}',
            'tile_index': tile,
            'row': tile // columns,
            'col': tile % columns,
            'char': '',
            'comment': 'read glyph from PNG; put this token in charmap.tsv for that glyph'
        })
    with tsv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['token_hex','tile_hex','tile_index','row','col','char','comment'], delimiter='\t')
        w.writeheader(); w.writerows(rows_out)
    report = {
        'target': target,
        'png': str(png),
        'out': str(out),
        'tsv': str(tsv),
        'start_token': f'0x{start_token:02X}',
        'rule': 'token_hex = start_token + tile_index',
        'note': 'Use token_hex values in encoder charmap.tsv. tile_hex/tile_index are only visual font positions.'
    }
    out.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'wrote token overlay grid: {out}')
    print(f'wrote token/tile TSV: {tsv}')
    print(json.dumps(report, ensure_ascii=False, indent=2))


def cmd_charmap_validate(args: argparse.Namespace) -> None:
    from lib.text_engine import read_charmap, charmap_coverage_report
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    data = read_rom(Path(args.rom))
    mapping = read_charmap(Path(args.charmap))
    report = charmap_coverage_report(data, target, mapping)
    out = Path(args.out) if args.out else Path(args.charmap).with_suffix('.validate.json')
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f'wrote {out}')
    if not report.get('ok'):
        raise SystemExit(1)

def cmd_translation_export(args: argparse.Namespace) -> None:
    from lib.text_engine import export_translation_files
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    data = read_rom(Path(args.rom))
    out = Path(args.out) if args.out else root / 'translation' / target
    rows = export_translation_files(data, target, out)
    print(f"exported {len(rows)} translation rows for {target}")
    print(f"wrote {out / 'translation.tsv'}")
    print(f"wrote {out / 'translation.json'}")



def _resolve_charmap_arg(root: str, target: str, translation: str, explicit: str | None) -> Path | None:
    """Use explicit --charmap, or auto-load translation/<target>/charmap.tsv.

    This keeps the normal workflow simple after the user edits charmap.tsv.
    """
    if explicit:
        return Path(explicit)
    candidates = [
        Path(root) / 'translation' / target / 'charmap.tsv',
        Path(translation).parent / 'charmap.tsv',
    ]
    for c in candidates:
        if c.exists():
            return c
    return None

def cmd_translation_validate(args: argparse.Namespace) -> None:
    from lib.text_engine import validate_translation
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    data = read_rom(Path(args.rom))
    charmap_path = _resolve_charmap_arg(args.root, target, args.translation, args.charmap)
    report = validate_translation(data, target, Path(args.translation), charmap_path)
    out = Path(args.out) if args.out else Path(args.translation).with_suffix('.validate.json')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"wrote {out}")
    if not report.get('ok'):
        raise SystemExit(1)


def cmd_translation_build(args: argparse.Namespace) -> None:
    from lib.text_engine import build_translation_rom
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    data = read_rom(Path(args.rom))
    try:
        charmap_path = _resolve_charmap_arg(args.root, target, args.translation, args.charmap)
        built, report, skipped = build_translation_rom(data, target, Path(args.translation), allow_partial=args.partial, charmap_path=charmap_path, pointer_mode=getattr(args, 'pointer_mode', 'same-bank'))
    except ValueError as e:
        raise SystemExit('translation build failed:\n' + str(e))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(built)
    report_path = out.with_suffix(out.suffix + '.report.json')
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    if skipped:
        skipped_path = out.with_suffix(out.suffix + '.skipped.tsv')
        with skipped_path.open('w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=['stream','index','reason','translation'], delimiter='\t')
            w.writeheader(); w.writerows(skipped)
        print(f"wrote skipped translations: {skipped_path}")
    print(f"wrote translated ROM: {out}")
    print(f"wrote report: {report_path}")
    if not report.get('ok'):
        raise SystemExit(1)




def cmd_translation_build_expanded(args: argparse.Namespace) -> None:
    from lib.text_engine import build_translation_rom_expanded
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    data = read_rom(Path(args.rom))
    try:
        charmap_path = _resolve_charmap_arg(args.root, target, args.translation, args.charmap)
        built, report = build_translation_rom_expanded(
            data, target, Path(args.translation), charmap_path=charmap_path,
            start_bank=int(args.start_bank, 0), max_size=int(args.max_size, 0),
            install_hook=getattr(args, 'install_hook', False),
        )
    except ValueError as e:
        raise SystemExit('expanded translation build failed:\n' + str(e))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(built)
    report_path = out.with_suffix(out.suffix + '.expanded-report.json')
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    # Write a convenient TSV pointer manifest for engine-patch work.
    ptr_path = out.with_suffix(out.suffix + '.expanded-pointers.tsv')
    with ptr_path.open('w', newline='', encoding='utf-8') as f:
        fields = ['stream','index','bank','gb_addr','offset','bank_offset','packed_bytes','bits','changed','dedup_of','translation']
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t')
        w.writeheader()
        for stream, entries in report.get('expanded_pointer_tables', {}).items():
            for ent in entries:
                row = {k: ent.get(k, '') for k in fields}
                row['stream'] = stream
                w.writerow(row)
    print(f"wrote expanded translated ROM data: {out}")
    print(f"wrote expanded report: {report_path}")
    print(f"wrote expanded pointer manifest: {ptr_path}")
    
    if report.get('expanded_runtime_header'):
        print('installed expanded runtime header:', report['expanded_runtime_header']['header_offset'])
        print('NOTE: v29 installs the bank-aware runtime manifest. CPU trampoline wiring is target-specific and reported in JSON.')
    else:
        print('NOTE: this packs expanded text data and pointer manifest. Add --install-hook to also write the runtime header.')


def _font_score_tile(data: bytes, off: int) -> float:
    if off < 0 or off + 16 > len(data):
        return -999.0
    ink = 0
    trans = 0
    rows = []
    for y in range(8):
        lo = data[off + y*2]
        hi = data[off + y*2 + 1]
        row = []
        for x in range(8):
            bit = 7 - x
            v = ((hi >> bit) & 1) * 2 + ((lo >> bit) & 1)
            row.append(v)
            if v:
                ink += 1
        rows.append(row)
    for row in rows:
        trans += sum(row[i] != row[i+1] for i in range(7))
    for x in range(8):
        trans += sum(rows[y][x] != rows[y+1][x] for y in range(7))
    if ink == 0:
        return 5.0
    if not (2 <= ink <= 44 and 3 <= trans <= 44):
        return -999.0
    border = rows[0] + rows[7] + [rows[y][0] for y in range(1, 7)] + [rows[y][7] for y in range(1, 7)]
    blank_border = sum(1 for v in border if v == 0) / len(border)
    return (50 - abs(ink - 18)) + blank_border * 20 + (44 - trans) * 0.30


def _font_range_score(data: bytes, offset: int, tiles: int) -> tuple[float, int, int]:
    scores = [_font_score_tile(data, offset + i*16) for i in range(tiles)]
    good = sum(1 for s in scores if s > -900)
    blank = sum(1 for s in scores if s == 5.0)
    if good == 0:
        return (-999.0, good, blank)
    return (sum(max(0.0, s) for s in scores) / tiles + good * 2 - blank, good, blank)


def _resolve_named_font(target: str, name: str) -> dict:
    if target not in PROFILE_FONTS:
        raise SystemExit(f"unknown target {target}")
    fonts = PROFILE_FONTS[target]
    if name not in fonts:
        known = ', '.join(sorted(fonts))
        raise SystemExit(f"unknown font '{name}' for {target}; known fonts: {known}")
    spec = dict(fonts[name])
    seen = {name}
    while 'alias' in spec:
        name = spec['alias']
        if name in seen:
            raise SystemExit(f"font alias loop for {target}:{name}")
        seen.add(name)
        spec = dict(fonts[name])
    spec['name'] = name
    spec['target'] = target
    spec['offset'] = int(spec['offset'])
    spec['tiles'] = int(spec['tiles'])
    spec['columns'] = int(spec.get('columns', 16))
    spec['scale'] = int(spec.get('scale', 4))
    return spec


def _font_paths(root: Path, target: str, name: str, out: str | None = None) -> tuple[Path, Path, Path]:
    if out:
        base = Path(out)
        # --out can be a directory, a .png path, or a stem.
        if base.suffix.lower() == '.png':
            png = base
            stem = base.with_suffix('')
        elif base.suffix:
            stem = base
            png = base.with_suffix('.png')
        else:
            stem = base / name if base.name != name else base
            png = stem.with_suffix('.png')
    else:
        stem = root / 'gfx' / target / 'fonts' / name
        png = stem.with_suffix('.png')
    return png, png.with_suffix('.json'), png.with_suffix('.tbl')


def _write_font_tbl(path: Path, tiles: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8') as f:
        f.write('# Robopon font table scaffold\n')
        f.write('# tile_index\ttoken_hex\tchar\tnote\n')
        for i in range(tiles):
            f.write(f'{i}\t0x{i:02X}\t\t\n')


def _load_font_meta(png_path: Path, explicit_meta: str | None = None) -> dict:
    meta_path = Path(explicit_meta) if explicit_meta else png_path.with_suffix('.json')
    if not meta_path.exists():
        raise SystemExit(f"font metadata not found: {meta_path}\nRun font-export first, then edit the exported PNG without moving/renaming the .json file.")
    return json.loads(meta_path.read_text(encoding='utf-8'))


def _validate_font_region(data: bytes, offset: int, tiles: int, *, force: bool = False) -> tuple[float, int, int]:
    if offset < 0 or offset + tiles * 16 > len(data):
        raise SystemExit(f'font range 0x{offset:X}..0x{offset+tiles*16:X} is outside the ROM')
    score, good, blank = _font_range_score(data, offset, tiles)
    if score < 40 and not force:
        raise SystemExit(
            f'font range at 0x{offset:X} does not look like raw GB 2bpp font data '
            f'(score={score:.1f}, good_tiles={good}/{tiles}).\n'
            'Run font-scan or pass --force only if you intentionally want to export/import arbitrary tiles.'
        )
    return score, good, blank



# ---------------------------------------------------------------------------
# Menu / fixed-width UI string translation helpers
# ---------------------------------------------------------------------------
def _fix_gb_checksums(rom: bytearray) -> None:
    """Update Game Boy header/global checksums after binary patching."""
    x = 0
    for i in range(0x134, 0x14D):
        x = (x - rom[i] - 1) & 0xFF
    rom[0x14D] = x
    total = (sum(rom[:0x14E]) + sum(rom[0x150:])) & 0xFFFF
    rom[0x14E] = (total >> 8) & 0xFF
    rom[0x14F] = total & 0xFF


def _menu_byte_allowed(b: int) -> bool:
    # Plain menu/UI strings tend to use direct engine bytes, not Huffman bits.
    # Keep the set conservative to avoid producing enormous false-positive dumps.
    if b in (0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x3A, 0x3B, 0x3F):
        return True
    if 0x30 <= b <= 0x39:
        return True
    if 0xA0 <= b <= 0xDF:
        return True
    return False


def _decode_menu_bytes(bs: bytes, *, katakana: bool = False) -> str:
    """Decode plain menu/UI bytes into Japanese display text.

    Menu strings are usually not Huffman-compressed; they are stored as raw
    engine tokens.  Earlier versions accidentally tried to call a non-existent
    helper and therefore exported hex instead of Japanese.  This uses the same
    token renderer as dialogue dumps so menu.tsv has readable Japanese source
    text.

    If katakana=True, we seed the renderer with the katakana mode token.  This is
    useful because some fixed menu labels omit explicit 0x28/0x29 page tokens.
    """
    try:
        from lib.text_engine import render_tokens
        toks = ([0x29] if katakana else []) + list(bs) + [0x00]
        return render_tokens(toks)
    except Exception:
        return ' '.join(f'{b:02X}' for b in bs)


def _find_menu_strings(data: bytes, min_len: int = 2, max_len: int = 24) -> list[dict]:
    rows = []
    i = 0
    n = len(data)
    while i < n:
        if _menu_byte_allowed(data[i]):
            start = i
            while i < n and _menu_byte_allowed(data[i]) and (i - start) < max_len:
                i += 1
            length = i - start
            # String should usually be followed by 00/FF/control/table boundary.
            nextb = data[i] if i < n else 0
            if length >= min_len and nextb in (0x00, 0xFF, 0xFE, 0xFD, 0x20):
                chunk = data[start:i]
                # Require at least one high kana/UI byte so normal code doesn't dominate.
                if any(b >= 0xA0 for b in chunk):
                    bank, bank_off, addr = bank_address(start)
                    rows.append({
                        'id': f'menu_{len(rows):04d}',
                        'offset': f'0x{start:06X}',
                        'bank': f'0x{bank:02X}',
                        'address': f'0x{addr:04X}',
                        'max_bytes': length + 1,  # include terminator/pad byte
                        'source_bytes': ' '.join(f'{b:02X}' for b in chunk),
                        'source_text': _decode_menu_bytes(chunk),
                        'source_katakana': _decode_menu_bytes(chunk, katakana=True),
                        'translation': '',
                        'note': 'fixed-width menu/UI candidate; translation must fit max_bytes including END',
                    })
        else:
            i += 1
    return rows


def _menu_category(row: dict) -> str:
    """Best-effort grouping for human translators.  This is intentionally heuristic."""
    off = int(str(row.get('offset', '0')).replace('0x',''), 16)
    src = row.get('source_text','') or ''
    raw = row.get('source_bytes','') or ''
    if off < 0x4000:
        return 'home/bank00 ui'
    bank = off // BANK_SIZE
    if bank in (0x01, 0x02):
        return 'early ui / menus'
    if any(ch in src for ch in ['はい', 'いいえ', 'YES', 'NO']) or raw in ('B1 B2', 'B3 B4'):
        return 'choice/menu option'
    if len(raw.split()) <= 4:
        return 'short label'
    return 'menu/ui candidate'


def _guess_english_hint(source_text: str) -> str:
    """Small built-in hints for common menu words; translators can overwrite freely."""
    hints = {
        'はい': 'Yes', 'いいえ': 'No', 'つよさ': 'Stats', 'もちもの': 'Items',
        'セーブ': 'Save', 'でんわ': 'Phone', 'ロボポン': 'Robopon', 'そうび': 'Equip',
        'かう': 'Buy', 'うる': 'Sell', 'やめる': 'Quit', 'もどる': 'Back',
        'スタート': 'Start', 'オプション': 'Options', 'ニューゲーム': 'New Game',
        'つづき': 'Continue', 'なまえ': 'Name', 'レベル': 'Level', 'おかね': 'Money',
    }
    for k, v in hints.items():
        if k in source_text:
            return v
    return ''


def _write_easy_menu_tsv(rows: list[dict], path: Path) -> None:
    """Write a translator-friendly TSV while preserving patch metadata columns."""
    fields = [
        'id', 'category', 'source_text', 'source_katakana', 'english_hint', 'translation',
        'max_bytes', 'max_visible_chars', 'offset', 'bank', 'address',
        'source_bytes', 'status', 'note'
    ]
    easy_rows = []
    for r in rows:
        maxb = int(r.get('max_bytes') or 0)
        src = r.get('source_text','') or ''
        easy_rows.append({
            'id': r.get('id',''),
            'category': _menu_category(r),
            'source_text': src,
            'source_katakana': r.get('source_katakana',''),
            'english_hint': _guess_english_hint(src) or _guess_english_hint(r.get('source_katakana','')),
            'translation': r.get('translation',''),
            'max_bytes': maxb,
            # One byte is usually needed for END/padding in fixed menu strings.
            'max_visible_chars': max(0, maxb - 1),
            'offset': r.get('offset',''),
            'bank': r.get('bank',''),
            'address': r.get('address',''),
            'source_bytes': r.get('source_bytes',''),
            'status': 'needs review',
            'note': 'Edit only translation. Keep it within max_visible_chars unless menu-build --partial is used.',
        })
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t')
        w.writeheader(); w.writerows(easy_rows)


def cmd_menu_export(args: argparse.Namespace) -> None:
    """Export fixed-width/plain menu/UI string candidates for manual translation."""
    target = normalize_target(args.target)
    data = read_rom(Path(args.rom))
    out_dir = Path(args.out) if args.out else Path(args.root) / 'translation' / target / 'menu'
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = _find_menu_strings(data, min_len=args.min_len, max_len=args.max_len)

    # Machine-oriented file used by menu-build.  Keep exact patch metadata.
    tsv = out_dir / 'menu.tsv'
    fields = ['id','category','source','source_katakana','translation','notes','raw_tokens','offset','bank','address','max_bytes','max_visible_chars']
    menu_rows = []
    for r in rows:
        menu_rows.append({
            'id': r.get('id',''),
            'category': _menu_category(r),
            'source': r.get('source_text',''),
            'source_katakana': r.get('source_katakana',''),
            'translation': '',
            'notes': '',
            'raw_tokens': r.get('source_bytes',''),
            'offset': r.get('offset',''),
            'bank': r.get('bank',''),
            'address': r.get('address',''),
            'max_bytes': r.get('max_bytes',''),
            'max_visible_chars': max(0, int(r.get('max_bytes') or 0) - 1),
        })
    with tsv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t')
        w.writeheader(); w.writerows(menu_rows)

    # Human-oriented file for translators.
    easy_tsv = out_dir / 'menu_easy.tsv'
    _write_easy_menu_tsv(rows, easy_tsv)

    # Deduped glossary view: one source string per row.
    glossary = {}
    for r in rows:
        key = r.get('source_text','') or r.get('source_bytes','')
        g = glossary.setdefault(key, {
            'source_text': r.get('source_text',''),
            'english_hint': _guess_english_hint(r.get('source_text','') or ''),
            'source_katakana': r.get('source_katakana',''),
            'translation': '',
            'count': 0,
            'ids': [],
            'shortest_max_visible_chars': 999,
            'notes': 'Translate once here for reference; copy final wording into menu_easy.tsv/menu.tsv rows.'
        })
        g['count'] += 1
        g['ids'].append(r.get('id',''))
        g['shortest_max_visible_chars'] = min(g['shortest_max_visible_chars'], max(0, int(r.get('max_bytes') or 0) - 1))
    glossary_tsv = out_dir / 'menu_glossary.tsv'
    with glossary_tsv.open('w', newline='', encoding='utf-8') as f:
        fields2 = ['source_text','source_katakana','english_hint','translation','count','shortest_max_visible_chars','ids','notes']
        w = csv.DictWriter(f, fieldnames=fields2, delimiter='\t')
        w.writeheader()
        for g in glossary.values():
            g = dict(g); g['ids'] = ','.join(g['ids'])
            if g['shortest_max_visible_chars'] == 999:
                g['shortest_max_visible_chars'] = ''
            w.writerow(g)

    (out_dir / 'menu.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'exported {len(rows)} menu/UI candidates for {target}')
    print(f'wrote {tsv}')
    print(f'wrote {easy_tsv}')
    print(f'wrote {glossary_tsv}')


def _load_menu_rows(path: Path) -> list[dict]:
    if path.suffix.lower() == '.json':
        return json.loads(path.read_text(encoding='utf-8'))
    with path.open('r', newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f, delimiter='\t'))


def cmd_menu_build(args: argparse.Namespace) -> None:
    """Patch translated fixed-width/plain menu/UI strings in-place."""
    from lib.text_engine import read_charmap, text_to_tokens_with_charmap
    target = normalize_target(args.target)
    rom = bytearray(read_rom(Path(args.rom)))
    rows = _load_menu_rows(Path(args.menu))
    cmap = read_charmap(Path(args.charmap) if args.charmap else None)
    report = {'target': target, 'menu': str(args.menu), 'mode': 'fixed-width-in-place', 'written': 0, 'skipped': 0, 'errors': [], 'warnings': []}
    for r in rows:
        text = (r.get('translation') or '').strip('\ufeff')
        if text == '':
            continue
        try:
            off = int(str(r.get('offset','0')).replace('0x',''), 16)
            max_bytes = int(r.get('max_bytes') or r.get('length') or 0)
            if max_bytes <= 0:
                raise ValueError('missing max_bytes')
            toks = text_to_tokens_with_charmap(text, cmap)
            if len(toks) > max_bytes:
                msg = f'too long: encoded {len(toks)} bytes, max {max_bytes}'
                if args.partial:
                    report['warnings'].append({'id': r.get('id'), 'offset': r.get('offset'), 'warning': msg})
                    report['skipped'] += 1
                    continue
                raise ValueError(msg)
            rom[off:off+max_bytes] = bytes(toks) + bytes([0x00]) * (max_bytes - len(toks))
            report['written'] += 1
        except Exception as e:
            report['errors'].append({'id': r.get('id'), 'offset': r.get('offset'), 'error': str(e), 'translation': text})
    report['ok'] = not report['errors']
    if report['errors'] and not args.partial:
        raise SystemExit('menu build failed:\n' + json.dumps(report, ensure_ascii=False, indent=2))
    _fix_gb_checksums(rom)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(rom)
    rp = out.with_suffix(out.suffix + '.menu-report.json')
    rp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'wrote menu-patched ROM: {out}')
    print(f'wrote report: {rp}')
    if not report['ok']:
        raise SystemExit(1)


def cmd_font_list(args: argparse.Namespace) -> None:
    target = args.target
    rows = []
    for name in sorted(PROFILE_FONTS[target]):
        spec = PROFILE_FONTS[target][name]
        if 'alias' in spec:
            rows.append({'name': name, 'alias': spec['alias'], 'offset': '', 'tiles': '', 'description': 'alias'})
        else:
            rows.append({
                'name': name,
                'alias': '',
                'offset': f'0x{int(spec["offset"]):06X}',
                'tiles': spec['tiles'],
                'description': spec.get('description', ''),
            })
    for r in rows:
        if r['alias']:
            print(f"{r['name']} -> {r['alias']}")
        else:
            print(f"{r['name']}: offset={r['offset']} tiles={r['tiles']} {r['description']}")


def cmd_font_export(args: argparse.Namespace) -> None:
    from lib.text_engine import export_font_png
    root = Path(args.root).resolve()
    data = read_rom(Path(args.rom))
    spec = _resolve_named_font(args.target, args.name)
    if args.offset:
        spec['offset'] = int(args.offset, 0)
    if args.tiles:
        spec['tiles'] = args.tiles
    if args.columns:
        spec['columns'] = args.columns
    if args.scale:
        spec['scale'] = args.scale
    offset = spec['offset']; tiles = spec['tiles']; columns = spec['columns']; scale = spec['scale']
    score, good, blank = _validate_font_region(data, offset, tiles, force=args.force)
    png, meta_path, tbl_path = _font_paths(root, args.target, spec['name'], args.out)
    export_font_png(data, offset, tiles, png, scale=scale, columns=columns)
    region = data[offset:offset + tiles * 16]
    bank, bank_off, addr = bank_address(offset)
    meta = {
        'format': 'robopon-font-v2',
        'target': args.target,
        'name': spec['name'],
        'description': spec.get('description', ''),
        'source_rom': str(args.rom),
        'source_rom_sha1': sha1(data),
        'source_region_sha1': sha1(region),
        'offset': f'0x{offset:06X}',
        'bank': f'0x{bank:02X}',
        'bank_offset': f'0x{bank_off:04X}',
        'address': f'0x{addr:04X}',
        'tiles': tiles,
        'tile_bytes': 16,
        'bpp': 2,
        'tile_width': 8,
        'tile_height': 8,
        'columns': columns,
        'scale': scale,
        'png': png.name,
        'tbl': tbl_path.name,
        'score': round(score, 2),
        'good_tiles': good,
        'blank_tiles': blank,
        'workflow': 'Edit the PNG only. Keep dimensions, scale, tile order, and this JSON next to it. Reimport with font-import --png <png>.',
    }
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2), encoding='utf-8')
    if not tbl_path.exists() or args.overwrite_tbl:
        _write_font_tbl(tbl_path, tiles)
    print(f"wrote font PNG: {png}")
    print(f"wrote metadata: {meta_path}")
    print(f"wrote table scaffold: {tbl_path}")
    print(f"{args.target}:{spec['name']} offset=0x{offset:X} tiles={tiles} score={score:.1f} good_tiles={good}/{tiles}")


def cmd_font_scan(args: argparse.Namespace) -> None:
    from lib.text_engine import export_font_png
    data = read_rom(Path(args.rom))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tiles = args.tiles
    candidates = []
    for off in range(0, len(data) - tiles*16 + 1, 16):
        score, good, blank = _font_range_score(data, off, tiles)
        if score >= args.min_score and good >= max(8, int(tiles * 0.35)):
            candidates.append((score, off, good, blank))
    selected = []
    for score, off, good, blank in sorted(candidates, reverse=True):
        if all(abs(off - prev_off) > args.separation for _, prev_off, _, _ in selected):
            selected.append((score, off, good, blank))
        if len(selected) >= args.limit:
            break
    tsv = out / 'font_candidates.tsv'
    with tsv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f, delimiter='\t')
        w.writerow(['rank', 'offset', 'bank', 'bank_offset', 'tiles', 'score', 'good_tiles', 'blank_tiles', 'png'])
        for i, (score, off, good, blank) in enumerate(selected, 1):
            png = out / f'candidate_{i:02d}_off_{off:06X}.png'
            export_font_png(data, off, tiles, png, scale=args.scale, columns=args.columns)
            w.writerow([i, f'0x{off:06X}', f'0x{off//BANK_SIZE:02X}', f'0x{off % BANK_SIZE:04X}', tiles, f'{score:.2f}', good, blank, png.name])
    summary = {
        'rom': args.rom,
        'tiles': tiles,
        'candidates': [
            {'rank': i, 'offset': hex(off), 'bank': hex(off//BANK_SIZE), 'bank_offset': hex(off % BANK_SIZE), 'score': round(score, 2), 'good_tiles': good, 'blank_tiles': blank}
            for i, (score, off, good, blank) in enumerate(selected, 1)
        ],
        'named_fonts': PROFILE_FONTS.get(args.target, {}) if getattr(args, 'target', None) else None,
        'note': 'When a candidate is verified, add it to PROFILE_FONTS and use metadata-driven font-export/font-import by name.'
    }
    (out / 'font_scan.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(f'wrote {tsv}')
    print(f'wrote {out / "font_scan.json"}')


def cmd_font_import(args: argparse.Namespace) -> None:
    from lib.text_engine import import_font_png
    data = read_rom(Path(args.rom))
    png = Path(args.png)
    meta = _load_font_meta(png, args.meta)
    if meta.get('format') != 'robopon-font-v2' and not args.force:
        raise SystemExit('font metadata is not robopon-font-v2. Re-export with the new font subsystem, or pass --force.')
    offset = int(str(meta['offset']), 0)
    tiles = int(meta['tiles'])
    columns = int(meta.get('columns', 16))
    scale = int(meta.get('scale', args.scale or 1))
    expected_rom_sha1 = meta.get('source_rom_sha1')
    if expected_rom_sha1 and expected_rom_sha1 != sha1(data) and not args.force:
        raise SystemExit(
            'ROM SHA1 does not match the ROM used for font-export.\n'
            f'exported from: {expected_rom_sha1}\ncurrent ROM:   {sha1(data)}\n'
            'Use the matching baserom or pass --force if you know this target is compatible.'
        )
    expected_region_sha1 = meta.get('source_region_sha1')
    current_region = data[offset:offset + tiles * 16]
    if expected_region_sha1 and expected_region_sha1 != sha1(current_region) and not args.force:
        raise SystemExit(
            'Font destination bytes differ from the exported region. This prevents accidental patching of the wrong ROM/version.\n'
            f'exported region: {expected_region_sha1}\ncurrent region:  {sha1(current_region)}\n'
            'Use --force only if you intentionally want to apply this PNG to this ROM.'
        )
    _validate_font_region(data, offset, tiles, force=args.force)
    built = import_font_png(data, offset, tiles, png, scale=scale, columns=columns)
    # Safety check: only the font region should differ.
    diffs = [i for i, (a, b) in enumerate(zip(data, built)) if a != b]
    allowed_start = offset; allowed_end = offset + tiles * 16
    outside = [i for i in diffs if not (allowed_start <= i < allowed_end)]
    if outside:
        raise SystemExit(f'internal error: font import changed bytes outside font region; first outside diff 0x{outside[0]:06X}')
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(built)
    report = {
        'ok': True,
        'target': meta.get('target'),
        'name': meta.get('name'),
        'out': str(out),
        'offset': f'0x{offset:06X}',
        'tiles': tiles,
        'changed_bytes': len(diffs),
        'changed_region_start': f'0x{allowed_start:06X}',
        'changed_region_end': f'0x{allowed_end:06X}',
        'input_png': str(png),
    }
    out.with_suffix(out.suffix + '.font-report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f"wrote font-patched ROM: {out}")
    print(f"changed {len(diffs)} bytes inside 0x{allowed_start:06X}..0x{allowed_end:06X}")
    print(f"wrote report: {out.with_suffix(out.suffix + '.font-report.json')}")



# ---------------------------------------------------------------------------
# English dialogue font generation
# ---------------------------------------------------------------------------

DEFAULT_ENGLISH_FONT_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " .,!?'\"-:;()/&%+*=#@[]<>"
)

# In the current Japanese text engine, translated Latin is first practical as a
# kana-slot alphabet: the script can emit the original kana token values, while
# the dialogue font tiles are redrawn to Latin glyphs in the same order.
# This table documents that workflow for translators and future engine work.
def _english_font_slots(chars: str, start_token: int = 0xA6) -> list[dict]:
    rows = []
    seen = set()
    tile = 0
    for ch in chars:
        if ch in seen:
            continue
        seen.add(ch)
        rows.append({
            'tile_index': tile,
            'token_hex': f'0x{start_token + tile:02X}',
            'char': ch,
            'note': 'kana-slot Latin glyph',
        })
        tile += 1
    return rows


def _draw_glyph_tile(ch: str, scale: int = 4):
    try:
        from PIL import Image, ImageDraw, ImageFont
    except Exception as e:
        raise RuntimeError('Pillow is required for English font generation: python3 -m pip install pillow') from e
    img = Image.new('RGBA', (8, 8), (255,255,255,0))
    d = ImageDraw.Draw(img)
    # Pillow's built-in bitmap font is intentionally used here so no font file
    # is shipped with the repository.  The slight clipping is acceptable for the
    # first editable template; translators can polish pixels by hand.
    font = ImageFont.load_default()
    if ch == ' ':
        return img.resize((8*scale, 8*scale), Image.Resampling.NEAREST)
    bbox = d.textbbox((0,0), ch, font=font)
    w = bbox[2]-bbox[0]; h = bbox[3]-bbox[1]
    x = max(0, (8-w)//2 - bbox[0])
    # Put most glyphs high enough to keep descenders visible when possible.
    y = max(-2, (8-h)//2 - bbox[1] - 1)
    d.text((x,y), ch, fill=(0,0,0,255), font=font)
    return img.resize((8*scale, 8*scale), Image.Resampling.NEAREST)


def _write_english_font_png(base_png: Path, out_png: Path, chars: str, columns: int, scale: int) -> None:
    try:
        from PIL import Image
    except Exception as e:
        raise RuntimeError('Pillow is required for English font generation: python3 -m pip install pillow') from e
    img = Image.open(base_png).convert('RGBA')
    tile_w = tile_h = 8 * scale
    rows = _english_font_slots(chars)
    if img.width % tile_w or img.height % tile_h:
        raise SystemExit(f'{base_png} dimensions do not match scale={scale}')
    max_tiles = (img.width // tile_w) * (img.height // tile_h)
    if len(rows) > max_tiles:
        raise SystemExit(f'English character set needs {len(rows)} tiles but PNG only has {max_tiles}')
    for r in rows:
        t = int(r['tile_index'])
        ox = (t % columns) * tile_w
        oy = (t // columns) * tile_h
        glyph = _draw_glyph_tile(r['char'], scale=scale)
        img.paste((255,255,255,0), (ox, oy, ox + tile_w, oy + tile_h))
        img.paste(glyph, (ox, oy), glyph)
    out_png.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_png)


def _write_english_map(path: Path, chars: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['tile_index','token_hex','char','note'], delimiter='\t')
        w.writeheader()
        for r in _english_font_slots(chars):
            w.writerow(r)


def cmd_font_english(args: argparse.Namespace) -> None:
    """Create an editable English dialogue font PNG using font-export metadata."""
    root = Path(args.root).resolve()
    # First make sure the canonical font export + metadata exists.
    spec = _resolve_named_font(args.target, args.name)
    default_png, meta_path, tbl_path = _font_paths(root, args.target, spec['name'], None)
    if not default_png.exists() or not meta_path.exists() or args.reexport:
        export_args = argparse.Namespace(
            root=args.root, target=args.target, rom=args.rom, name=args.name, out=None,
            offset=None, tiles=None, scale=None, columns=None,
            overwrite_tbl=False, force=args.force,
        )
        cmd_font_export(export_args)
    meta = _load_font_meta(default_png)
    columns = int(meta.get('columns', 16))
    scale = int(meta.get('scale', 4))
    chars = args.chars if args.chars is not None else DEFAULT_ENGLISH_FONT_CHARS
    out_png = Path(args.out) if args.out else default_png
    # Preserve the original kana export if overwriting the canonical PNG.
    if out_png.resolve() == default_png.resolve():
        backup = default_png.with_name(default_png.stem + '.kana-original.png')
        if not backup.exists() or args.overwrite_backup:
            backup.write_bytes(default_png.read_bytes())
    _write_english_font_png(default_png, out_png, chars, columns=columns, scale=scale)
    # Copy metadata next to alternate output PNGs so font-import remains metadata-driven.
    if out_png.with_suffix('.json').resolve() != meta_path.resolve():
        new_meta = dict(meta)
        new_meta['png'] = out_png.name
        new_meta['derived_from'] = str(default_png)
        new_meta['workflow'] = 'Generated by font-english. Edit pixels, then import with font-import --png <png>.'
        out_png.with_suffix('.json').write_text(json.dumps(new_meta, indent=2), encoding='utf-8')
    map_path = out_png.with_suffix('.english-map.tsv')
    _write_english_map(map_path, chars)
    print(f'wrote English dialogue font PNG: {out_png}')
    print(f'wrote kana-slot map: {map_path}')
    if out_png.resolve() == default_png.resolve():
        print(f'preserved original kana PNG as: {default_png.with_name(default_png.stem + ".kana-original.png")}')
    print('Next: edit the PNG if desired, then run font-import --png <that png> --out build/<target>_english_font.gbc')


def cmd_font_glyph_test(args: argparse.Namespace) -> None:
    """Create a one-glyph diagnostic font PNG from the exported dialogue font."""
    root = Path(args.root).resolve()
    spec = _resolve_named_font(args.target, args.name)
    default_png, meta_path, _ = _font_paths(root, args.target, spec['name'], None)
    if not default_png.exists() or not meta_path.exists() or args.reexport:
        export_args = argparse.Namespace(
            root=args.root, target=args.target, rom=args.rom, name=args.name, out=None,
            offset=None, tiles=None, scale=None, columns=None,
            overwrite_tbl=False, force=args.force,
        )
        cmd_font_export(export_args)
    meta = _load_font_meta(default_png)
    columns = int(meta.get('columns', 16)); scale = int(meta.get('scale', 4))
    out_png = Path(args.out) if args.out else default_png.with_name(default_png.stem + '.glyph-test.png')
    try:
        from PIL import Image
    except Exception as e:
        raise RuntimeError('Pillow is required: python3 -m pip install pillow') from e
    img = Image.open(default_png).convert('RGBA')
    tile_w = tile_h = 8 * scale
    t = int(args.tile, 0) if isinstance(args.tile, str) else int(args.tile)
    ox = (t % columns) * tile_w; oy = (t // columns) * tile_h
    glyph = _draw_glyph_tile(args.char, scale=scale)
    img.paste((255,255,255,0), (ox, oy, ox + tile_w, oy + tile_h))
    img.paste(glyph, (ox, oy), glyph)
    out_png.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_png)
    new_meta = dict(meta)
    new_meta['png'] = out_png.name
    new_meta['derived_from'] = str(default_png)
    new_meta['diagnostic'] = {'tile_index': t, 'char': args.char}
    out_png.with_suffix('.json').write_text(json.dumps(new_meta, indent=2), encoding='utf-8')
    print(f'wrote glyph-test PNG: {out_png}')
    print(f'tile {t} replaced with {args.char!r}; import it to confirm this is the active runtime font')


# ---------------------------------------------------------------------------
# Sun-based kana-slot English font port
# ---------------------------------------------------------------------------

# Conservative dialogue kana slots.  These intentionally skip the first row of
# digits/icons/control glyphs and the later UI/status glyph rows.  The range is
# large enough for Sun's Latin alphabet, punctuation, lowercase letters, and
# translation punctuation while preserving non-character UI tiles.
DEFAULT_KANA_SLOT_RANGES = [(0x10, 0x80)]


def _parse_slot_ranges(text: str | None) -> list[int]:
    if not text:
        ranges = DEFAULT_KANA_SLOT_RANGES
    else:
        ranges = []
        for part in text.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                a,b = part.split('-',1)
                ranges.append((int(a,0), int(b,0)+1))
            else:
                v = int(part,0)
                ranges.append((v, v+1))
    slots=[]
    for a,b in ranges:
        if a < 0 or b < a:
            raise SystemExit(f'invalid slot range {a}:{b}')
        slots.extend(range(a,b))
    return sorted(dict.fromkeys(slots))


def _copy_tiles_between_font_pngs(base_png: Path, source_png: Path, out_png: Path, slots: list[int], *, columns: int, scale: int) -> None:
    try:
        from PIL import Image
    except Exception as e:
        raise RuntimeError('Pillow is required: python3 -m pip install pillow') from e
    base = Image.open(base_png).convert('RGBA')
    src = Image.open(source_png).convert('RGBA')
    if base.size != src.size:
        raise SystemExit(f'font PNG size mismatch: {base_png}={base.size}, {source_png}={src.size}')
    tile_w = tile_h = 8 * scale
    for t in slots:
        ox = (t % columns) * tile_w
        oy = (t // columns) * tile_h
        if ox + tile_w > base.width or oy + tile_h > base.height:
            raise SystemExit(f'slot {t} outside font sheet')
        base.paste(src.crop((ox, oy, ox+tile_w, oy+tile_h)), (ox, oy))
    out_png.parent.mkdir(parents=True, exist_ok=True)
    base.save(out_png)


def _write_slot_copy_map(path: Path, slots: list[int], source: str, target: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f, delimiter='\t')
        w.writerow(['tile_index','source','target','note'])
        for t in slots:
            w.writerow([t, source, target, 'copied from Sun English font; non-kana slots preserved'])


def cmd_font_port_sun_english(args: argparse.Namespace) -> None:
    """Create a target font PNG by copying only kana slots from the English Sun ROM."""
    root = Path(args.root).resolve()
    target = args.target
    if target == 'sun' and not args.allow_sun_target:
        raise SystemExit('target is sun; this command is intended to port Sun English glyphs to moon/comic. Pass --allow-sun-target for testing.')
    target_data = read_rom(Path(args.rom))
    sun_data = read_rom(Path(args.sun_rom))
    # Export both source sheets through the verified metadata system.
    spec = _resolve_named_font(target, args.name)
    target_png, target_meta_path, _ = _font_paths(root, target, spec['name'], None)
    if not target_png.exists() or not target_meta_path.exists() or args.reexport:
        cmd_font_export(argparse.Namespace(root=args.root, target=target, rom=args.rom, name=args.name, out=None, offset=None, tiles=None, scale=None, columns=None, overwrite_tbl=False, force=args.force))
    sun_png, sun_meta_path, _ = _font_paths(root, 'sun', spec['name'], root / 'gfx' / 'sun' / 'fonts' / f'{spec["name"]}.sun-source.png')
    if not sun_png.exists() or not sun_meta_path.exists() or args.reexport:
        cmd_font_export(argparse.Namespace(root=args.root, target='sun', rom=args.sun_rom, name=args.name, out=str(sun_png), offset=None, tiles=None, scale=None, columns=None, overwrite_tbl=False, force=args.force))
    meta = _load_font_meta(target_png)
    sun_meta = _load_font_meta(sun_png)
    columns = int(meta.get('columns', 16)); scale = int(meta.get('scale', 4))
    if int(sun_meta.get('columns', columns)) != columns or int(sun_meta.get('scale', scale)) != scale:
        raise SystemExit('Sun and target font metadata do not use the same columns/scale; re-export both with matching metadata')
    slots = _parse_slot_ranges(args.slots)
    max_tiles = int(meta['tiles'])
    slots = [s for s in slots if s < max_tiles]
    out_png = Path(args.out) if args.out else target_png.with_name(target_png.stem + '.sun-english-kana-slots.png')
    _copy_tiles_between_font_pngs(target_png, sun_png, out_png, slots, columns=columns, scale=scale)
    new_meta = dict(meta)
    new_meta['png'] = out_png.name
    new_meta['derived_from'] = str(target_png)
    new_meta['sun_source_rom_sha1'] = sha1(sun_data)
    new_meta['sun_source_png'] = str(sun_png)
    new_meta['slot_policy'] = 'copy only kana slots from English Sun; preserve non-character/digit/UI tiles from target'
    new_meta['copied_slots'] = [f'0x{s:02X}' for s in slots]
    new_meta['workflow'] = 'Generated by font-port-sun-english. Import with font-import --png <png> --out build/<target>_sun_english_font.gbc.'
    out_png.with_suffix('.json').write_text(json.dumps(new_meta, indent=2), encoding='utf-8')
    map_path = out_png.with_suffix('.slot-map.tsv')
    _write_slot_copy_map(map_path, slots, 'sun:dialogue', f'{target}:dialogue')
    print(f'wrote Sun-style English kana-slot font: {out_png}')
    print(f'wrote metadata: {out_png.with_suffix(".json")}')
    print(f'wrote slot map: {map_path}')
    print(f'copied {len(slots)} kana slots; preserved all other tiles from {target}')
    print(f'Next: python3 tools/robopon.py font-import --rom {args.rom} --png {out_png} --out build/{target}_sun_english_font.gbc')


def cmd_profile_check(args: argparse.Namespace) -> None:
    target = normalize_target(args.target)
    data = read_rom(Path(args.rom))
    header = rom_header(data)
    info = {
        'target': target,
        'rom': str(args.rom),
        'sha1': sha1(data),
        'size': len(data),
        'banks': len(data) // BANK_SIZE,
        'header': header,
        'known_text_streams': [x.__dict__ for x in stream_specs_for_target(target)],
        'known_fonts': PROFILE_FONTS.get(target, {}),
        'notes': [],
    }
    if target == 'comic':
        info['notes'].append('Comic BomBom support uses the shared Robopon text-engine profile by default. Run text-roundtrip after init to verify this baserom.')
        info['notes'].append('If roundtrip fails, run analyze and bankdiff against Moon/Sun, then update profiles/comic.yaml and tools/lib/text_engine.py DEFAULT_STREAMS.')
    out = Path(args.out) if args.out else None
    text = json.dumps(info, indent=2, ensure_ascii=False)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + '\n', encoding='utf-8')
        print(f'wrote {out}')
    else:
        print(text)


def cmd_setup_comic(args: argparse.Namespace) -> None:
    root = Path(args.root)
    rom = Path(args.rom)
    target = 'comic'
    data = read_rom(rom)
    # Copy baserom only if requested; this keeps repos free of copyrighted data unless local user chooses it.
    dest = root / 'baseroms' / 'comic.gbc'
    dest.parent.mkdir(parents=True, exist_ok=True)
    if args.copy:
        dest.write_bytes(data)
        rom_for_init = dest
    else:
        rom_for_init = rom
    manifest = split_banks(data, root, target)
    write_asm_scaffold(root, target, len(data)//BANK_SIZE)
    write_analysis(root, target, data, manifest)
    write_progressive_disasm(root, target, data)
    print('Comic BomBom target initialized.')
    print('Next run:')
    print('  make comic')
    print('  python3 tools/robopon.py compare --rom baseroms/comic.gbc --built build/comic.gbc')
    print('  python3 tools/robopon.py text-roundtrip --target comic --rom baseroms/comic.gbc')

def cmd_compare(args: argparse.Namespace) -> None:
    a = Path(args.rom).read_bytes()
    b = Path(args.built).read_bytes()
    if a == b:
        print("OK: files are byte-identical")
        print(f"sha1 {sha1(a)}")
        return
    limit = min(len(a), len(b))
    first = next((i for i in range(limit) if a[i] != b[i]), None)
    print("DIFFERENT")
    print(f"original size={len(a)} sha1={sha1(a)}")
    print(f"built    size={len(b)} sha1={sha1(b)}")
    if first is not None:
        print(f"first difference at 0x{first:06X}: original=0x{a[first]:02X} built=0x{b[first]:02X}")
    elif len(a) != len(b):
        print(f"same prefix, size differs at 0x{limit:06X}")
    raise SystemExit(1)


def cmd_bankdiff(args: argparse.Namespace) -> None:
    a = read_rom(Path(args.a))
    b = read_rom(Path(args.b))
    banks = min(len(a), len(b)) // BANK_SIZE
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t")
        w.writerow(["bank", "same", "same_bytes", "total", "sha1_a", "sha1_b"])
        for bank in range(banks):
            ca = a[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
            cb = b[bank * BANK_SIZE:(bank + 1) * BANK_SIZE]
            same_bytes = sum(1 for x, y in zip(ca, cb) if x == y)
            w.writerow([f"0x{bank:02X}", int(ca == cb), same_bytes, BANK_SIZE, sha1(ca), sha1(cb)])
    print(f"wrote {out}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="robopon.py")
    ap.add_argument("--root", default=".", help="repository root")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="initialize scaffold from a baserom")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("analyze", help="generate reverse-engineering analysis reports from a ROM")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.set_defaults(func=cmd_analyze)


    p = sub.add_parser("disasm", help="generate progressive labeled RGBDS assembly while preserving exact bytes")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--max-labels", type=int, default=256, help="maximum labels to emit per bank")
    p.set_defaults(func=cmd_disasm)


    p = sub.add_parser("text-dump", help="decode known Huffman/tree text streams to TSV/JSON")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", help="output directory; default text/<target>")
    p.add_argument("--charmap", help="optional translator charmap TSV/JSON used only to render decoded tokens for inspection")
    p.set_defaults(func=cmd_text_dump)

    p = sub.add_parser("text-roundtrip", help="verify decode -> encode -> decode against the same Huffman trees")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", default="analysis/text_roundtrip.json")
    p.set_defaults(func=cmd_text_roundtrip)

    p = sub.add_parser("text-tree", help="dump Huffman/tree code tables for known text streams")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", help="output directory; default analysis/<target>/text_engine")
    p.set_defaults(func=cmd_text_tree)

    p = sub.add_parser("huffman-export", help="export actual one-byte Huffman token map from the ROM text engine")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", help="output TSV; default translation/<target>/huffman_token_map.tsv")
    p.add_argument("--out-dir", help="output directory for companion files; default translation/<target>")
    p.set_defaults(func=cmd_huffman_export)



    p = sub.add_parser("punctuation-scan", help="scan Huffman trees for safe original punctuation tokens")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", help="output TSV; default translation/<target>/punctuation_tokens.tsv")
    p.add_argument("--out-dir", help="output directory for companion files; default translation/<target>")
    p.add_argument("--charmap-out", help="starter charmap TSV for safe punctuation; default translation/<target>/punctuation_charmap.template.tsv")
    p.set_defaults(func=cmd_punctuation_scan)


    p = sub.add_parser("charmap-export", help="export kana-slot English charmap for the imported English dialogue font")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", help="output TSV; default translation/<target>/charmap.tsv")
    p.add_argument("--start-token", default="0xA6", help="first engine token used by the English font mapping")
    p.set_defaults(func=cmd_charmap_export)


    p = sub.add_parser("charmap-from-font", help="generate token -> tile mappings from an exported dialogue font PNG")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--font", help="font PNG path; alias of --png")
    p.add_argument("--png", help="font PNG path; alias of --font")
    p.add_argument("--meta", help="font metadata JSON; default is PNG with .json suffix")
    p.add_argument("--out", help="output TSV; default translation/<target>/token_tile_map.tsv")
    p.add_argument("--start-token", default="0xA6", help="first engine/Huffman token to map")
    p.add_argument("--tile-start", default="0x00", help="first row-major font tile index to map")
    p.add_argument("--count", type=int, help="number of token/tile rows to emit; default through end of font")
    p.add_argument("--tiles", type=int, help="font tile count if no metadata is available")
    p.add_argument("--columns", type=int, help="font grid columns; default from metadata or 16")
    p.add_argument("--scale", type=int, help="PNG export scale; default from metadata or 1")
    p.add_argument("--chars", help="optional row-major character labels to include; no OCR is performed")
    p.set_defaults(func=cmd_charmap_from_font)



    p = sub.add_parser("font-compact", help="copy selected glyphs into real encodable 00-FF Huffman token slots and write a matching charmap")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True, help="ROM used to read the real Huffman tree")
    p.add_argument("--png", help="source font PNG path; alias of --font")
    p.add_argument("--font", help="source font PNG path; alias of --png")
    p.add_argument("--charmap", required=True, help="current visual charmap that says where each glyph is now")
    p.add_argument("--out-png", help="output compacted font PNG; default adds .compact.png")
    p.add_argument("--out-charmap", help="output encoder charmap; default adds .compact.tsv")
    p.add_argument("--stream", default="dialogue", help="tree to target: dialogue, descriptions, or all")
    p.add_argument("--chars", help="exact characters to keep, in priority/order; default uppercase, digits, common punctuation")
    p.add_argument("--start-token", default="0xA6", help="token corresponding to font tile 0; default 0xA6")
    p.add_argument("--min-token", default="0xA6", help="lowest usable font token; default 0xA6")
    p.add_argument("--max-token", default="0xFF", help="highest usable byte token; default 0xFF")
    p.add_argument("--meta", help="font metadata JSON; default is PNG with .json suffix")
    p.add_argument("--columns", type=int, help="font grid columns; default metadata or 16")
    p.add_argument("--scale", type=int, help="font export scale; default metadata or 1")
    p.add_argument("--tile-px", type=int, help="tile size in PNG pixels; default 8*scale")
    p.set_defaults(func=cmd_font_compact)

    p = sub.add_parser("font-token-grid", help="overlay Huffman/engine token values directly on a font PNG grid")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--png", help="font PNG path; alias of --font")
    p.add_argument("--font", help="font PNG path; alias of --png")
    p.add_argument("--meta", help="font metadata JSON; default is PNG with .json suffix")
    p.add_argument("--out", help="output labeled PNG; default adds .token-grid.png")
    p.add_argument("--tsv", help="output token/tile TSV; default next to output PNG")
    p.add_argument("--start-token", default="0xA6", help="token corresponding to tile 0; default 0xA6")
    p.add_argument("--tile-start", default="0x00", help="first tile index to label")
    p.add_argument("--count", type=int, help="number of tiles to label")
    p.add_argument("--tiles", type=int, help="font tile count if metadata is missing")
    p.add_argument("--columns", type=int, help="font grid columns; default metadata or 16")
    p.add_argument("--scale", type=int, help="font export scale; default metadata or 1")
    p.add_argument("--tile-px", type=int, help="tile size in PNG pixels; default 8*scale")
    p.add_argument("--display-scale", type=int, help="scale output before labeling; default auto")
    p.set_defaults(func=cmd_font_token_grid)

    p = sub.add_parser("charmap-validate", help="verify all charmap tokens exist in the target Huffman trees")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--charmap", required=True)
    p.add_argument("--out", help="validation JSON path")
    p.set_defaults(func=cmd_charmap_validate)

    p = sub.add_parser("translation-export", help="export editable TSV/JSON translation files from known text streams")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", help="output directory; default translation/<target>")
    p.set_defaults(func=cmd_translation_export)

    p = sub.add_parser("translation-validate", help="validate a translation TSV/JSON before building")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--translation", required=True)
    p.add_argument("--charmap", help="TSV/JSON charmap; use after importing English kana-slot font")
    p.add_argument("--out", help="validation JSON path")
    p.set_defaults(func=cmd_translation_validate)

    p = sub.add_parser("translation-build", help="build a translated ROM with rebuilt text pointers")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--translation", required=True)
    p.add_argument("--charmap", help="TSV/JSON charmap; use after importing English kana-slot font")
    p.add_argument("--out", required=True)
    p.add_argument("--partial", action="store_true", help="skip unsupported/overflowing translated rows and keep originals")
    p.add_argument("--pointer-mode", choices=["same-bank", "window14"], default="same-bank",
                   help="where repointed strings may live. same-bank is safest. window14 uses Robopon 16-bit pointers with two high window bits, allowing the table bank plus the next three 16 KiB windows for longer English strings.")
    p.set_defaults(func=cmd_translation_build)

    p = sub.add_parser("translation-build-expanded", help="pack full translated script into expanded ROM banks and write bank-aware pointer manifest")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--translation", required=True)
    p.add_argument("--charmap", help="TSV/JSON charmap; use after importing English font")
    p.add_argument("--out", required=True)
    p.add_argument("--start-bank", default="0x40", help="first expanded bank for text data; default 0x40")
    p.add_argument("--max-size", default="0x400000", help="maximum expanded ROM size; default 4 MiB")
    p.add_argument("--install-hook", action="store_true", help="install the expanded runtime manifest/header for a bank-aware text-loader hook")
    p.set_defaults(func=cmd_translation_build_expanded)


    p = sub.add_parser("menu-export", help="export menu/UI text to menu.tsv plus translator-friendly menu_easy.tsv")
    p.add_argument("--target", default="moon", choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out")
    p.add_argument("--min-len", type=int, default=2)
    p.add_argument("--max-len", type=int, default=24)
    p.set_defaults(func=cmd_menu_export)

    p = sub.add_parser("menu-build", help="patch translated fixed-width/plain menu and UI strings in-place")
    p.add_argument("--target", default="moon", choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--menu", required=True, help="menu.tsv/menu.json from menu-export")
    p.add_argument("--charmap", help="English charmap TSV/JSON")
    p.add_argument("--out", required=True)
    p.add_argument("--partial", action="store_true", help="skip rows that are too long instead of failing")
    p.set_defaults(func=cmd_menu_build)

    p = sub.add_parser("font-list", help="list named font assets for a target")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.set_defaults(func=cmd_font_list)

    p = sub.add_parser("font-export", help="export a named font asset to PNG + JSON + TBL metadata")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--name", default="dialogue", help="named font asset; use font-list to see options")
    p.add_argument("--out", help="output PNG, stem, or directory; default gfx/<target>/fonts/<name>.png")
    p.add_argument("--offset", help="override ROM file offset for research only")
    p.add_argument("--tiles", type=int, help="override tile count for research only")
    p.add_argument("--scale", type=int, help="PNG scale; default comes from font metadata")
    p.add_argument("--columns", type=int, help="tile columns; default comes from font metadata")
    p.add_argument("--overwrite-tbl", action="store_true", help="overwrite an existing .tbl scaffold")
    p.add_argument("--force", action="store_true", help="export even if the range does not look like font data")
    p.set_defaults(func=cmd_font_export)

    p = sub.add_parser("font-scan", help="scan ROM for likely raw 2bpp font/tile blocks and export candidate PNGs")
    p.add_argument("--target", choices=TARGET_CHOICES, help="include known named font definitions in the scan summary")
    p.add_argument("--rom", required=True)
    p.add_argument("--out", default="analysis/font_scan")
    p.add_argument("--tiles", type=int, default=128)
    p.add_argument("--limit", type=int, default=24)
    p.add_argument("--min-score", type=float, default=40.0)
    p.add_argument("--separation", type=lambda x: int(x,0), default=0x400)
    p.add_argument("--scale", type=int, default=3)
    p.add_argument("--columns", type=int, default=16)
    p.set_defaults(func=cmd_font_scan)

    p = sub.add_parser("font-import", help="import an edited named font PNG using the JSON metadata created by font-export")
    p.add_argument("--rom", required=True)
    p.add_argument("--png", required=True, help="edited PNG exported by font-export")
    p.add_argument("--out", required=True)
    p.add_argument("--meta", help="metadata JSON; default is PNG path with .json suffix")
    p.add_argument("--scale", type=int, help="fallback scale for old metadata only")
    p.add_argument("--force", action="store_true", help="bypass ROM/region checks; use only for deliberate cross-version patches")
    p.set_defaults(func=cmd_font_import)




    p = sub.add_parser("font-english", help="generate an editable English replacement for a named dialogue font")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--name", default="dialogue")
    p.add_argument("--out", help="output PNG; default overwrites gfx/<target>/fonts/<name>.png after making .kana-original.png")
    p.add_argument("--chars", help="custom character order to draw into kana slots")
    p.add_argument("--reexport", action="store_true", help="re-export the original font before generating the English template")
    p.add_argument("--overwrite-backup", action="store_true", help="overwrite existing .kana-original.png backup")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_font_english)


    p = sub.add_parser("font-port-sun-english", help="copy only kana-slot English glyphs from the English Sun ROM into Moon/Comic font PNG")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True, help="target Moon/Comic ROM")
    p.add_argument("--sun-rom", required=True, help="English Robopon Sun ROM to use as the style/source font")
    p.add_argument("--name", default="dialogue")
    p.add_argument("--out", help="output PNG; default gfx/<target>/fonts/dialogue.sun-english-kana-slots.png")
    p.add_argument("--slots", help="comma/range list of tile slots to copy, e.g. 0x10-0x7F; default is safe kana slots only")
    p.add_argument("--reexport", action="store_true", help="re-export source/target font PNGs before copying")
    p.add_argument("--allow-sun-target", action="store_true", help="allow --target sun for diagnostics")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_font_port_sun_english)

    p = sub.add_parser("font-glyph-test", help="make a one-glyph diagnostic PNG to verify the active dialogue font")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--name", default="dialogue")
    p.add_argument("--tile", default="0", help="tile index to replace, e.g. 0 or 0x10")
    p.add_argument("--char", default="A", help="single character to draw into the tile")
    p.add_argument("--out", help="output PNG; default gfx/<target>/fonts/<name>.glyph-test.png")
    p.add_argument("--reexport", action="store_true")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_font_glyph_test)

    p = sub.add_parser("profile-check", help="show target profile assumptions for a ROM, including Comic BomBom")
    p.add_argument("--target", choices=TARGET_CHOICES, required=True)
    p.add_argument("--rom", required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_profile_check)

    p = sub.add_parser("setup-comic", help="initialize/analyze/disasm the Comic BomBom target from a user-provided ROM")
    p.add_argument("--rom", required=True)
    p.add_argument("--copy", action="store_true", help="copy the ROM into baseroms/comic.gbc for local builds")
    p.set_defaults(func=cmd_setup_comic)

    p = sub.add_parser("compare", help="byte-compare baserom and rebuilt ROM")
    p.add_argument("--rom", required=True)
    p.add_argument("--built", required=True)
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("bankdiff", help="compare banks between two ROMs")
    p.add_argument("--a", required=True)
    p.add_argument("--b", required=True)
    p.add_argument("--out", default="analysis/bankdiff.tsv")
    p.set_defaults(func=cmd_bankdiff)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
