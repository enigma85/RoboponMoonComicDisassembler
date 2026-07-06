# Font compacting for translation

Robopon text symbols are one byte (`0x00`-`0xFF`), and the stock Moon/Comic
Huffman trees do **not** contain every possible byte.  In Moon dialogue, the
normal kana/font token range is only `0xA6`-`0xDF`, so a visual font sheet that
labels tiles as `0x115`, `0x122`, etc. cannot be encoded by the existing text
engine.

Use `font-compact` to copy the English glyphs you actually want into tokens
that the current Huffman tree can encode, then build translations using the
new charmap it writes.

Example Moon workflow:

```bash
python3 tools/robopon.py font-compact \
  --target moon \
  --rom baseroms/moon.gbc \
  --png gfx/moon/fonts/dialogue.png \
  --charmap translation/moon/charmap.tsv \
  --out-png gfx/moon/fonts/dialogue.compact.png \
  --out-charmap translation/moon/charmap.compact.tsv

python3 tools/robopon.py font-import \
  --rom baseroms/moon.gbc \
  --png gfx/moon/fonts/dialogue.compact.png \
  --out build/moon_compact_font.gbc

python3 tools/robopon.py translation-build \
  --target moon \
  --rom build/moon_compact_font.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.compact.tsv \
  --out build/moon_translated.gbc
```

By default the command keeps uppercase letters, digits, and common punctuation.
To choose your own limited alphabet:

```bash
python3 tools/robopon.py font-compact \
  --target moon \
  --rom baseroms/moon.gbc \
  --png gfx/moon/fonts/dialogue.png \
  --charmap translation/moon/charmap.tsv \
  --chars " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.,!?" \
  --out-png gfx/moon/fonts/dialogue.compact.png \
  --out-charmap translation/moon/charmap.compact.tsv
```

If you request more characters than the tree can encode, the command stops and
reports the token capacity. Full uppercase + lowercase + numbers + punctuation
requires a rebuilt/expanded Huffman tree or a custom text-engine patch.
