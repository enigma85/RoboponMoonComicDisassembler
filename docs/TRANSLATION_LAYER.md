# Translation Layer

This layer sits on top of the verified text-engine decoder/encoder.

## Export editable files

```sh
python3 tools/robopon.py translation-export --target moon --rom baseroms/moon.gbc
```

Outputs:

- `translation/moon/translation.tsv`
- `translation/moon/translation.json`

TSV columns:

- `stream`: text stream name, such as `dialogue` or `descriptions`
- `index`: entry index in the stream
- `source`: decoded Japanese text
- `translation`: editable translation field
- `notes`: translator notes
- `raw_tokens`: original token bytes, preserved when `translation` is blank
- `pointer_word`, `offset`, `bytes`, `bits`: technical fields used for validation/builds

## Validate

```sh
python3 tools/robopon.py translation-validate \
  --target moon \
  --rom baseroms/moon.gbc \
  --translation translation/moon/translation.tsv
```

Validation checks:

- unsupported characters
- tokens not present in the current Huffman tree
- whether edited strings can be written in place
- whether edited strings need pointer rebuilding
- same-bank free-space availability

Important: Moon's Japanese Huffman trees may not contain ASCII letter tokens. In that case validation will report tokens such as `0x48` or `0x45` as missing. That is expected until the English text tree/font system is ported from Sun or a new English tree is installed.

## Build

```sh
python3 tools/robopon.py translation-build \
  --target moon \
  --rom baseroms/moon.gbc \
  --translation translation/moon/translation.tsv \
  --out build/moon_translated.gbc
```

Build behavior:

- Blank `translation` rows keep the original ROM bytes untouched.
- Short edited rows are written in place.
- Longer edited rows are written into same-bank free space and the pointer table entry is rebuilt automatically.
- `--partial` skips rows that cannot be encoded or placed and writes a `.skipped.tsv` report.

This is deliberately conservative. It does not yet expand the ROM or patch the text engine for bank-aware pointers.

## Font editing

Raw Game Boy 2bpp tile ranges can be exported and imported:

```sh
python3 tools/robopon.py font-export \
  --rom baseroms/moon.gbc \
  --offset 0x12345 \
  --tiles 96 \
  --out gfx/font_probe.png

python3 tools/robopon.py font-import \
  --rom baseroms/moon.gbc \
  --offset 0x12345 \
  --tiles 96 \
  --png gfx/font_probe.png \
  --out build/moon_font_test.gbc
```

The command requires Pillow:

```sh
python3 -m pip install pillow
```

The font commands intentionally require an explicit offset. Use `analyze`, `tile_candidates.tsv`, and Sun/Moon comparisons to identify verified font regions before committing offsets to a profile.

## Current limitation

The translation layer can rebuild pointers and patch encoded text using the known tree format. A complete English Moon/Comic BomBom translation still needs one of these engine milestones:

1. Port Sun's English text tree/charset/font behavior into Moon/Comic, or
2. Build and install a new English Huffman tree plus any required renderer/font patches, or
3. Add an expanded text-bank loader with bank-aware pointers.

The validation command is designed to make these limitations explicit instead of creating garbled or misleading ROMs.
