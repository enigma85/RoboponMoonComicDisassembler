# Charmap tokens vs font grid indices

The translation encoder needs **engine tokens**, not the visible tile index from `dialogue.png`.

For the Moon/Comic English-font workflow, use:

```bash
python3 tools/robopon.py charmap-export --target moon --rom baseroms/moon.gbc
python3 tools/robopon.py charmap-validate --target moon --rom baseroms/moon.gbc --charmap translation/moon/charmap.tsv
```

The generated `translation/<target>/charmap.tsv` maps English letters to original kana-slot Huffman tokens such as `A -> A6`, `B -> A7`, etc. These tokens exist in the original Moon/Comic Huffman trees.

A grid made from `dialogue.png` is only a visual reference. Do not use its `code_hex` or `tile_index` values as encoder tokens unless you have verified those values exist in `text-tree`.

If validation reports errors like:

```text
tokens not present in Huffman tree: 0x48,0x68,0x75
```

then the build is trying to encode raw ASCII/tile IDs instead of kana-slot engine tokens. Regenerate the charmap with `charmap-export` and pass it to both validate and build:

```bash
python3 tools/robopon.py translation-validate --target moon --rom build/moon_english_font.gbc --translation translation/moon/translation.tsv --charmap translation/moon/charmap.tsv
python3 tools/robopon.py translation-build --target moon --rom build/moon_english_font.gbc --translation translation/moon/translation.tsv --charmap translation/moon/charmap.tsv --out build/moon_translated.gbc
```
