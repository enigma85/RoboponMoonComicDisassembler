# Robopon Open Disassembly

A clean-room, ROM-data-free disassembly workspace for **Robot Poncots / Robopon** Game Boy Color games. This is AI-Driven so it sucks but it is intended to help get English translation completed of the 2 non-English games. And as a bonus could help get it into other languages as well. Again its AI so it sucks.

Supported targets:

- `sun` — English Robopon Sun Version reference
- `moon` — Japanese Robot Poncots Moon Version
- `comic` — Robot Poncots Comic BomBom Special Version

This repository does **not** contain copyrighted ROM data. Put your own legally obtained baseroms in `baseroms/` and run the initializer.

## Quick start

```bash
python3 tools/robopon.py init --target moon --rom "baseroms/moon.gbc"
make moon
python3 tools/robopon.py compare --rom baseroms/moon.gbc --built build/moon.gbc
python3 tools/robopon.py analyze --target moon --rom baseroms/moon.gbc
```

For Sun:

```bash
python3 tools/robopon.py init --target sun --rom "baseroms/sun.gbc"
make sun
```

For Comic BomBom:

```bash
python3 tools/robopon.py init --target comic --rom "baseroms/comic.gbc"
make comic
```

## What this gives you now

The first milestone is a byte-identical RGBDS scaffold. It splits a baserom into 16 KiB banks and creates assembly files using `INCBIN`. That gives contributors a working build immediately. Banks can then be replaced piece by piece with real annotated assembly, data, text, graphics, and engine code.


## Analysis command

`analyze` generates the first real reverse-engineering workspace for a target without modifying the build scaffold:

```bash
python3 tools/robopon.py analyze --target moon --rom baseroms/moon.gbc
```

It writes `analysis/<target>/` with:

- `rom_info.json` — ROM header, size, SHA1, bank count
- `banks.tsv` / `banks.json` — per-bank entropy and byte statistics
- `pointer_tables.tsv` / `pointer_tables.json` — likely little-endian ROMX pointer tables
- `text_candidates.tsv` / `text_candidates.json` — dense byte runs worth checking as text/script data
- `tile_candidates.tsv` / `tile_candidates.json` — likely Game Boy 2bpp tile regions
- `free_space.tsv` / `free_space.json` — long `$00`/`$FF` runs
- `symbols.json` — provisional labels for follow-up disassembly work
- `REPORT.md` — quick summary of generated outputs

These reports are heuristic. Treat them as a map for manual labeling, not as final truth.

## Project goals

1. Rebuild each supported ROM byte-for-byte.
2. Identify engine code, data tables, text streams, fonts, and compression.
3. Replace raw `INCBIN` banks with labeled RGBDS assembly.
4. Document the text engine and Huffman/tree compression.
5. Build translation tooling on top of the disassembly rather than fragile binary patching.
6. Support complete English translation of Moon and Comic BomBom using the Sun English release as reference.

## Repository map

```text
asm/          RGBDS assembly entry points and generated bank files
baseroms/     user-provided ROMs, ignored by git
build/        generated ROMs, ignored by git
constants/    hardware/game constants
macros/       RGBDS macros
data/         structured data replacing raw banks over time
docs/         reverse engineering notes and specs
gfx/          extracted/rebuildable graphics
include/      generated include files and version constants
profiles/     target metadata
text/         extracted text, charmaps, script macros
tools/        analysis, init, compare, extraction tools
tests/        pytest-based validation helpers
```

## Requirements

- Python 3.10+
- RGBDS 0.6+ (`rgbasm`, `rgblink`, `rgbfix`)
- Optional: `pytest` for tests

## Legal note

Do not commit ROMs, generated bank binaries, or rebuilt ROMs. The `.gitignore` is set up to prevent that.

## Progressive disassembly

After `init` or `analyze`, generate a real RGBDS disassembly scaffold:

```bash
python3 tools/robopon.py disasm --target moon --rom baseroms/moon.gbc
make moon
python3 tools/robopon.py compare --rom baseroms/moon.gbc --built build/moon.gbc
```

`disasm` writes `asm/<target>/bank_XX.asm` files made of labeled `INCBIN` slices. This preserves exact ROM bytes while creating safe boundaries for progressive replacement. Replace one range at a time with real RGBDS instructions/data and verify after every edit.


## Text engine milestone

Decode known compressed text streams:

```bash
python3 tools/robopon.py text-dump --target moon --rom baseroms/moon.gbc
```

Verify decode/encode roundtrip against the same Huffman trees:

```bash
python3 tools/robopon.py text-roundtrip --target moon --rom baseroms/moon.gbc --out analysis/moon/text_roundtrip.json
```

Dump tree code tables:

```bash
python3 tools/robopon.py text-tree --target moon --rom baseroms/moon.gbc
```

See `docs/TEXT_ENGINE.md` for the currently documented tree format and control-code notes.

## v6 translation layer

New commands:

```sh
python3 tools/robopon.py translation-export --target moon --rom baseroms/moon.gbc
python3 tools/robopon.py translation-validate --target moon --rom baseroms/moon.gbc --translation translation/moon/translation.tsv
python3 tools/robopon.py translation-build --target moon --rom baseroms/moon.gbc --translation translation/moon/translation.tsv --out build/moon_translated.gbc
python3 tools/robopon.py font-export --rom baseroms/moon.gbc --offset 0x12345 --tiles 96 --out gfx/font_probe.png
python3 tools/robopon.py font-import --rom baseroms/moon.gbc --offset 0x12345 --tiles 96 --png gfx/font_probe.png --out build/moon_font_test.gbc
```

See `docs/TRANSLATION_LAYER.md`.


### Font editing

Use the verified profile font export instead of arbitrary offsets:

```bash
python3 tools/robopon.py font-export --target moon --rom baseroms/moon.gbc --out gfx/moon/font.png
```

See `docs/FONT_WORKFLOW.md`.

## v8 font subsystem

Fonts are now exported/imported as named assets with metadata instead of raw offsets.

```bash
python3 tools/robopon.py font-list --target moon
python3 tools/robopon.py font-export --target moon --rom baseroms/moon.gbc --name dialogue
python3 tools/robopon.py font-import --rom baseroms/moon.gbc --png gfx/moon/fonts/dialogue.png --out build/moon_font.gbc
```

See `docs/FONT_SUBSYSTEM.md`.

## Comic BomBom quick start

```bash
cp "Robot Poncots - Comic BomBom Special Version.gbc" baseroms/comic.gbc
python3 tools/robopon.py setup-comic --rom baseroms/comic.gbc
make comic
python3 tools/robopon.py compare --rom baseroms/comic.gbc --built build/comic.gbc
python3 tools/robopon.py text-roundtrip --target comic --rom baseroms/comic.gbc
```

See `docs/COMIC_BOMBOM_SUPPORT.md` for the full Comic workflow.
