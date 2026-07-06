# Expanded Text Storage

`translation-build-expanded` packs the full translated dialogue/description streams into expanded ROM banks and writes a bank-aware pointer manifest.

```bash
python3 tools/robopon.py translation-build-expanded \
  --target moon \
  --rom build/moon_font.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.tsv \
  --out build/moon_expanded_text.gbc
```

Outputs:

- `build/moon_expanded_text.gbc`
- `build/moon_expanded_text.gbc.expanded-report.json`
- `build/moon_expanded_text.gbc.expanded-pointers.tsv`

Important: Robopon's stock text pointers are 16-bit and do not include a bank number. This command solves text packing and produces the bank-aware manifest required by the next engine-hook step. The stock game will not automatically read expanded banks until a text-engine trampoline/hook is installed.

Useful options:

```bash
--start-bank 0x40     # first expanded text bank
--max-size 0x400000   # max ROM size, default 4 MiB
```

The pointer TSV contains `stream`, `index`, `bank`, `gb_addr`, `offset`, `packed_bytes`, and `bits` for every translated row. That file is the input for the future bank-aware text reader patch.
