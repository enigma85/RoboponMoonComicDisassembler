# Text dump with an English charmap

`text-dump` now accepts `--charmap`. This does not change the ROM. It only renders decoded Huffman tokens through your edited English charmap so you can verify that a patched row actually contains the intended English-token sequence.

Example:

```bash
python3 tools/robopon.py text-dump \
  --target moon \
  --rom build/moon_translated.gbc \
  --out analysis/moon_translated_text \
  --charmap translation/moon/charmap.tsv
```

If the dump shows `HELLO` but the game display looks wrong, the issue is font/page rendering. If the dump still shows the old line, the wrong dialogue row was edited or the build did not write that row.

## Unsupported tokens

`translation-build` can only encode tokens that are present in the target ROM's Huffman tree. Some lowercase/punctuation token slots may not exist in Moon or Comic's original tree. `translation-validate` will report those before build:

```bash
python3 tools/robopon.py translation-validate \
  --target comic \
  --rom build/comic_font.gbc \
  --translation translation/comic/translation.tsv \
  --charmap translation/comic/charmap.tsv
```

When it reports tokens like `0xEE`, `0xFB`, or `0xFA` as missing, either change that character's mapping to a token that exists in the tree, use uppercase-only text for testing, or implement the later full-tree rebuild/expanded text-engine patch.
