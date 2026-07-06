# Expanded Text Hook (v29)

`translation-build-expanded` now supports `--install-hook`.

It writes translated text into expanded banks and installs a compact runtime
manifest named `RPEXT1` containing bank-aware pointer tables. The manifest is
stored in expanded ROM space and is described in the generated
`.expanded-report.json`.

Run:

```bash
python3 tools/robopon.py translation-build-expanded \
  --target moon \
  --rom build/moon_font.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.tsv \
  --install-hook \
  --out build/moon_expanded_text.gbc
```

Outputs:

- `build/moon_expanded_text.gbc`
- `build/moon_expanded_text.gbc.expanded-report.json`
- `build/moon_expanded_text.gbc.expanded-pointers.tsv`

The report includes `expanded_runtime_header`, including the header offset and
per-stream banked pointer table locations.

## Important

v29 lays down the runtime data format required by an expanded text loader. The
CPU-side trampoline still needs to be connected to the exact text decoder call
site for each target if the stock engine does not already consult this manifest.
The manifest format is stable so that the next ASM patch can be small and
reproducible.
