# `charmap-from-font`

`charmap-from-font` generates a mechanical token-to-tile map from an exported dialogue font PNG.

It does **not** OCR the bitmap or guess what letter a glyph represents. It records the row-major tile index for each glyph and assigns a sequential engine token range to those tiles.

## Basic use

```bash
python3 tools/robopon.py charmap-from-font \
  --target moon \
  --font gfx/moon/fonts/dialogue.png \
  --out translation/moon/token_tile_map.tsv \
  --start-token 0xA6
```

Output columns:

```text
token_hex    tile_hex    tile_index    row    col    char    comment
```

- `token_hex` is the engine/Huffman token the text compressor must emit.
- `tile_hex` / `tile_index` is the row-major tile position in `dialogue.png`.
- `char` is intentionally blank unless supplied with `--chars`.

## Limit the range

```bash
python3 tools/robopon.py charmap-from-font \
  --target moon \
  --font gfx/moon/fonts/dialogue.png \
  --tile-start 0x20 \
  --start-token 0xA6 \
  --count 80
```

## Add character labels manually or with `--chars`

```bash
python3 tools/robopon.py charmap-from-font \
  --target moon \
  --font gfx/moon/fonts/dialogue.png \
  --tile-start 0x20 \
  --start-token 0xA6 \
  --chars "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
```

Only use `--chars` when the order exactly matches the glyph order in the PNG.
