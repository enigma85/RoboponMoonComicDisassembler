# Charmap build fix

`translation-build` now uses the edited `charmap.tsv` as the source of truth
when converting translated English text into Robopon engine/Huffman tokens.

Previously, if a character was missing or the charmap was not passed correctly,
the builder could fall back to ASCII byte values such as `0x48` for `H`.  Those
ASCII values are font/tile-like values and are usually not present in the Moon or
Comic Huffman tree, causing errors like:

```text
tokens not present in Huffman tree: 0x48,0x68,0x75
```

The fixed behavior is:

```text
translation.tsv text -> charmap.tsv -> engine tokens -> Huffman encoder
```

## Build

Pass the edited charmap explicitly:

```bash
python3 tools/robopon.py translation-build \
  --target moon \
  --rom build/moon_english_font.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.tsv \
  --out build/moon_translated.gbc
```

Or place it at `translation/<target>/charmap.tsv`; the command will auto-load it
when `--charmap` is omitted.

## Valid charmap format

```tsv
char	tokens	note
A	C7	English glyph in kana slot
B	C8	English glyph in kana slot
 	A6	space
\\n	0A	newline
```

The `tokens` column must contain Robopon engine tokens, not font tile numbers and
not ASCII bytes.
