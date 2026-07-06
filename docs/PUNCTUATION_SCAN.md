# Punctuation scan

`punctuation-scan` finds original printable punctuation tokens that already exist in the target ROM's Huffman text trees.

Use this when an apostrophe, quote, comma, period, or other punctuation fails to build because the token in `charmap.tsv` is not present in the Huffman tree.

## Usage

```bash
python3 tools/robopon.py punctuation-scan \
  --target moon \
  --rom baseroms/moon.gbc
```

For Comic BomBom:

```bash
python3 tools/robopon.py punctuation-scan \
  --target comic \
  --rom baseroms/comic.gbc
```

## Outputs

By default it writes:

```text
translation/<target>/punctuation_tokens.tsv
translation/<target>/punctuation_tokens.json
translation/<target>/punctuation_charmap.template.tsv
```

`punctuation_tokens.tsv` shows:

- `token_hex` — the byte token to use in `charmap.tsv`
- `display` — how the original engine renders the token
- `suggested_char` — an English punctuation character if one is obvious
- `safe_for_translation` — `yes` for printable punctuation candidates
- `<stream>_encodable` — whether the token exists in that stream's Huffman tree
- `<stream>_uses` — how often that token appears in the decoded stream

## Using the result

Copy rows from `punctuation_charmap.template.tsv` into your active `translation/<target>/charmap.tsv`, or manually use the `token_hex` values from `punctuation_tokens.tsv`.

Do not use tokens marked as controls, such as:

- `0x00` end token
- `0x0A` newline
- `0x28` / `0x29` font/page mode tokens
- player/name/control variable tokens
