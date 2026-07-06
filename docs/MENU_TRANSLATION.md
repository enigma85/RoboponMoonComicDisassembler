# Menu / UI translation

Dialogue and descriptions use the Huffman text engine, but many menu labels and short UI strings are stored as plain fixed-width byte strings. After replacing the kana dialogue font with English glyphs, those original menu bytes may look garbled until the menu strings are patched too.

This workflow adds a conservative menu candidate exporter and an in-place menu builder.

## 1. Export menu candidates

```bash
python3 tools/robopon.py menu-export \
  --target moon \
  --rom baseroms/moon.gbc
```

For Comic BomBom:

```bash
python3 tools/robopon.py menu-export \
  --target comic \
  --rom baseroms/comic.gbc
```

Output:

```text
translation/<target>/menu/menu.tsv
translation/<target>/menu/menu.json
```

The exporter is heuristic. It intentionally over-finds short fixed-width UI strings. Translate only rows you can identify in-game.

## 2. Edit menu.tsv

Fill the `translation` column only for strings you want to patch. The encoded text must fit in `max_bytes`, including the ending `00` byte.

Example:

```tsv
id        offset     max_bytes  source_text  translation
menu_0012 0x012345   6          ...          ITEM
```

Use the same English `charmap.tsv` you use for dialogue. For spaces, prefer token `20`.

## 3. Build the menu-patched ROM

Patch menus on top of your already font-patched ROM:

```bash
python3 tools/robopon.py menu-build \
  --target moon \
  --rom build/moon_translated.gbc \
  --menu translation/moon/menu/menu.tsv \
  --charmap translation/moon/charmap.tsv \
  --out build/moon_menu_translated.gbc
```

For Comic:

```bash
python3 tools/robopon.py menu-build \
  --target comic \
  --rom build/comic_translated.gbc \
  --menu translation/comic/menu/menu.tsv \
  --charmap translation/comic/charmap.tsv \
  --out build/comic_menu_translated.gbc
```

If some menu entries are too long but you want to patch the ones that fit:

```bash
python3 tools/robopon.py menu-build ... --partial
```

## Notes

- This command is for plain fixed-width menu/UI strings, not Huffman dialogue.
- It does not yet repoint menu strings. Many menu labels must stay short.
- It updates Game Boy header/global checksums after patching.
- Longer menu translation will require locating the menu pointer tables or rewriting menu layout code.
