# Font subsystem

The font workflow is now metadata driven. Do not pass raw offsets during normal editing.

## List known fonts

```bash
python3 tools/robopon.py font-list --target moon
```

Known names currently include:

- `dialogue` — verified kana dialogue/UI font block
- `kana` — alias for `dialogue`

## Export

```bash
python3 tools/robopon.py font-export \
  --target moon \
  --rom baseroms/moon.gbc \
  --name dialogue
```

This writes:

```text
gfx/moon/fonts/dialogue.png
gfx/moon/fonts/dialogue.json
gfx/moon/fonts/dialogue.tbl
```

The JSON records the ROM SHA-1, region SHA-1, ROM offset, bank, tile count, tile size, scale, and columns. Keep it next to the PNG.

## Edit

Edit only the PNG using a hard-edge pixel editor. Preserve:

- image dimensions
- tile grid
- tile order
- scale
- transparent/white background behavior

The `.tbl` file is a scaffold for documenting which tile/token corresponds to which character. It is not required for raw graphics import yet.

## Import

```bash
python3 tools/robopon.py font-import \
  --rom baseroms/moon.gbc \
  --png gfx/moon/fonts/dialogue.png \
  --out build/moon_font.gbc
```

`font-import` reads `dialogue.json` automatically. It refuses to patch if:

- the ROM SHA-1 does not match the export ROM,
- the destination bytes differ from the exported region,
- the PNG dimensions no longer match the metadata-derived tile grid,
- or any bytes outside the font region would change.

Use `--force` only when deliberately applying a verified font PNG to another compatible ROM.

## Research overrides

For reverse engineering only, `font-export` still supports `--offset`, `--tiles`, `--columns`, and `--scale`. These overrides are recorded in the exported JSON, so import still remains metadata driven.

## Verify active font

Before redrawing the whole font, change one common glyph into an obvious marker, import it, and boot the game. If that glyph changes in dialogue/menu text, the named font is active for that renderer.
