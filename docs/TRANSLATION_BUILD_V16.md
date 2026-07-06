# v16 translation-build fix

`translation-build` now rebuilds each complete text stream instead of patching
only edited rows in-place.

This matters because Robopon dialogue is bit-packed Huffman data. Rebuilding the
whole stream makes the pointer table and compressed text agree exactly.

Build:

```bash
python3 tools/robopon.py translation-build \
  --target moon \
  --rom build/moon_english_font.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.tsv \
  --out build/moon_translated.gbc
```

A valid charmap maps visible characters to engine tokens, not ASCII/tile IDs:

```tsv
char	tokens
A	C7
B	C8
a	E7
 	A6
```

Untranslated original Japanese strings will look garbled after replacing the
font with English. That is expected until those rows are translated.
