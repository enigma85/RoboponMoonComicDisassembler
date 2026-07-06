# Robopon Open Disassembly
THIS IS AI CODED SO IT SUCKS JUST A WARNING!

This archive intentionally excludes ROMs, built ROMs, generated translation TSV/JSON, analysis outputs, and Python cache files. Add your own legally obtained ROMs under `baseroms/`.

## Quick start

```bash
cp "Robot Poncots - Moon Version.gbc" baseroms/moon.gbc
python3 tools/robopon.py init --target moon --rom baseroms/moon.gbc
make moon
python3 tools/robopon.py compare --rom baseroms/moon.gbc --built build/moon.gbc
```

## Expanded text build

```bash
python3 tools/robopon.py translation-build-expanded \
  --target moon \
  --rom build/moon_font.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.tsv \
  --install-hook \
  --out build/moon_expanded_text.gbc
```

See `docs/EXPANDED_TEXT_HOOK.md` and `docs/EXPANDED_TEXT_STORAGE.md`.

---

# Robopon Open Disassembly

A clean-room, ROM-data-free disassembly workspace for **Robot Poncots / Robopon** Game Boy Color games.

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

## English dialogue font

Generate a kana-slot English replacement font:

```bash
python3 tools/robopon.py font-english --target moon --rom baseroms/moon.gbc
python3 tools/robopon.py font-import --rom baseroms/moon.gbc --png gfx/moon/fonts/dialogue.png --out build/moon_english_font.gbc
```

See `docs/ENGLISH_DIALOGUE_FONT.md` for the single-glyph verification workflow.

## Sun-style English font port

To replace only the kana dialogue-font slots with the English Sun font style:

```bash
python3 tools/robopon.py font-port-sun-english --target moon --rom baseroms/moon.gbc --sun-rom baseroms/sun.gbc
python3 tools/robopon.py font-import --rom baseroms/moon.gbc --png gfx/moon/fonts/dialogue.sun-english-kana-slots.png --out build/moon_sun_english_font.gbc
```

See `docs/SUN_STYLE_ENGLISH_FONT.md`.

## English-font translation workflow

After importing the Sun-style English font into Moon/Comic, use the charmap-based translation layer:

```bash
python3 tools/robopon.py charmap-export --target moon --rom baseroms/moon.gbc
python3 tools/robopon.py translation-export --target moon --rom baseroms/moon.gbc
python3 tools/robopon.py translation-validate --target moon --rom baseroms/moon.gbc --translation translation/moon/translation.tsv --charmap translation/moon/charmap.tsv
python3 tools/robopon.py translation-build --target moon --rom build/moon_sun_english_font.gbc --translation translation/moon/translation.tsv --charmap translation/moon/charmap.tsv --out build/moon_translated.gbc
```

See `docs/TRANSLATING_WITH_ENGLISH_FONT.md`.


## v13 charmap encoder fix

`translation-validate` and `translation-build` now correctly pass the supplied charmap into patch-edited-row mode. Use `charmap-export`; do not use visual grid tile indices as text tokens. See `docs/CHARMAP_TOKENS.md`.

## Added in v14

- `charmap-from-font`: generates token -> tile mapping TSVs from exported dialogue font PNGs. See `docs/CHARMAP_FROM_FONT.md`.


## v15 charmap build fix

`translation-build` now strictly encodes through the edited `charmap.tsv` and auto-loads `translation/<target>/charmap.tsv` when present. See `docs/CHARMAP_BUILD_FIX.md`.

## v17 patch-edited-rows translation fix

`translation-build` now patches only rows with a non-empty `translation` column. Unedited text stays byte-for-byte unchanged. This avoids overflowing the original text banks while you test or incrementally translate Moon/Comic with the edited English dialogue font.


## Font compacting

If an English font sheet uses token labels above `0xFF`, use `font-compact` to move selected glyphs into real encodable Huffman byte-token slots. See `docs/FONT_COMPACT.md`.

## v23 punctuation scan

Added `punctuation-scan` to identify safe original punctuation Huffman tokens for English charmap files. See `docs/PUNCTUATION_SCAN.md`.

### v24: longer English strings

`translation-build` now supports `--pointer-mode window14`, which lets edited
rows be repointed into the table bank plus the next three 16 KiB pointer windows.
Use it when English is longer than the original Japanese slot:

```bash
python3 tools/robopon.py translation-build --target moon --rom build/moon_font.gbc \
  --translation translation/moon/translation.tsv --charmap translation/moon/charmap.tsv \
  --pointer-mode window14 --out build/moon_translated.gbc
```

See `docs/EXPANDED_TEXT_STORAGE.md`.

## v25 menu translation

Added `menu-export` and `menu-build` for fixed-width/plain menu and UI strings. See `docs/MENU_TRANSLATION.md`.


### Easy menu translation

```bash
python3 tools/robopon.py menu-export --target moon --rom baseroms/moon.gbc
```

This now writes `menu.tsv`, `menu_easy.tsv`, and `menu_glossary.tsv`. Edit `translation/<target>/menu/menu_easy.tsv`, then build with `menu-build`. See `docs/MENU_TRANSLATION_EASY_TSV.md`.


## v27 Japanese menu source export

`menu-export` now decodes menu/UI byte strings into Japanese text columns (`source` and `source_katakana`) so `menu.tsv` is easier to translate like dialogue `translation.tsv`.

## v29 expanded text packing

Added `translation-build-expanded` for full-script expanded ROM text packing. See `docs/EXPANDED_TEXT_STORAGE.md`.


## v29 expanded text hook

Use `translation-build-expanded --install-hook` to pack translated text into expanded banks and write the `RPEXT1` runtime header/manifest. See `docs/EXPANDED_TEXT_HOOK.md`.
