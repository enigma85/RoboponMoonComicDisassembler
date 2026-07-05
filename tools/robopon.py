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
    from lib.text_engine import dump_all_text, write_text_outputs
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    root = Path(args.root).resolve()
    data = read_rom(Path(args.rom))
    out = Path(args.out) if args.out else root / "text" / target
    rows = dump_all_text(data, target)
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


def cmd_translation_validate(args: argparse.Namespace) -> None:
    from lib.text_engine import validate_translation
    target = args.target
    if target not in TARGETS:
        raise SystemExit(f"unknown target {target}")
    data = read_rom(Path(args.rom))
    report = validate_translation(data, target, Path(args.translation))
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
        built, report, skipped = build_translation_rom(data, target, Path(args.translation), allow_partial=args.partial)
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


    p = sub.add_parser("translation-export", help="export editable TSV/JSON translation files from known text streams")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--out", help="output directory; default translation/<target>")
    p.set_defaults(func=cmd_translation_export)

    p = sub.add_parser("translation-validate", help="validate a translation TSV/JSON before building")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--translation", required=True)
    p.add_argument("--out", help="validation JSON path")
    p.set_defaults(func=cmd_translation_validate)

    p = sub.add_parser("translation-build", help="build a translated ROM with rebuilt text pointers")
    p.add_argument("--target", required=True, choices=TARGET_CHOICES)
    p.add_argument("--rom", required=True)
    p.add_argument("--translation", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--partial", action="store_true", help="skip unsupported/overflowing translated rows and keep originals")
    p.set_defaults(func=cmd_translation_build)

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
