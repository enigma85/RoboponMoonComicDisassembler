# Menu Japanese source export

`menu-export` now writes Japanese source text into the menu TSV files, similar to `translation.tsv` for dialogue.

Run:

```bash
python3 tools/robopon.py menu-export --target moon --rom baseroms/moon.gbc
```

Outputs:

```text
translation/moon/menu/menu.tsv
translation/moon/menu/menu_easy.tsv
translation/moon/menu/menu_glossary.tsv
```

Important columns:

- `source` / `source_text`: decoded Japanese from the raw menu bytes.
- `source_katakana`: alternate katakana-page rendering for fixed UI labels that omit explicit page control bytes.
- `translation`: edit this column only.
- `raw_tokens`: original menu bytes.
- `max_visible_chars`: approximate maximum visible English characters for fixed-width in-place menu strings.

Menu/UI strings are heuristic candidates. Some rows may be code/data false positives; leave suspicious rows blank.
