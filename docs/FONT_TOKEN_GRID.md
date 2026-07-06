# Font token grid

`font-token-grid` overlays the engine/Huffman token value directly on top of a font PNG.

This is useful after replacing the kana dialogue font with English. The visible tile position is not the value the encoder needs. The encoder needs the engine token that the Huffman tree can emit.

For the kana-slot English font, the default rule is:

```text
token_hex = 0xA6 + tile_index
```

Example:

```text
Tile 0x21 contains A -> token 0xC7
Tile 0x25 contains E -> token 0xCB
Tile 0x2C contains L -> token 0xD2
```

Run:

```bash
python3 tools/robopon.py font-token-grid \
  --target moon \
  --png gfx/moon/fonts/dialogue.png \
  --out gfx/moon/fonts/dialogue.token-grid.png
```

The command also writes a TSV with `token_hex`, `tile_hex`, row, and column. Use `token_hex` in `translation/<target>/charmap.tsv`. Do not use `tile_hex` as a text token.
