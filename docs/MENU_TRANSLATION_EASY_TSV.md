# Easy menu translation TSV

`menu-export` now writes three files:

```text
translation/<target>/menu/menu.tsv
translation/<target>/menu/menu_easy.tsv
translation/<target>/menu/menu_glossary.tsv
```

## Files

- `menu.tsv` is the build file. It keeps the exact offsets and metadata needed by `menu-build`.
- `menu_easy.tsv` is the translator-friendly file. Edit the `translation` column here.
- `menu_glossary.tsv` groups duplicate source strings so you can decide consistent English wording.

## Recommended workflow

```bash
python3 tools/robopon.py menu-export --target moon --rom baseroms/moon.gbc
```

Open:

```text
translation/moon/menu/menu_easy.tsv
```

Edit only the `translation` column. Keep each entry within `max_visible_chars` when possible.

Build:

```bash
python3 tools/robopon.py menu-build \
  --target moon \
  --rom build/moon_translated.gbc \
  --menu translation/moon/menu/menu_easy.tsv \
  --charmap translation/moon/charmap.tsv \
  --out build/moon_menu_translated.gbc
```

The menu builder accepts either `menu.tsv` or `menu_easy.tsv` because both keep `id`, `offset`, `max_bytes`, and `translation`.

## Notes

Menu strings are fixed-width/plain byte strings, not the compressed dialogue stream. Long translations must fit in the original menu slot unless we later add menu repointing.
