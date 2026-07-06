# Translating Robopon

This project contains a complete workflow for translating Robopon into another language.

The recommended workflow is:

1. Export the font
2. Edit the font
3. Export the script
4. Translate the TSV
5. Import the font
6. Build the translated ROM

---

# Step 1 — Export the dialogue font

```bash
python3 tools/robopon.py font-export \
    --target moon \
    --rom baseroms/moon.gbc
```

This creates:

```
gfx/moon/fonts/dialogue.png
gfx/moon/fonts/dialogue.json
gfx/moon/fonts/dialogue.tbl
```

Edit only the PNG.

Do not rename or move the JSON file.

---

# Step 2 — Create an English font

Replace the kana glyphs with English glyphs.

The recommended workflow is:

- uppercase
- lowercase
- numbers
- punctuation

Keep every tile in the same position.

---

# Step 3 — Import the font

```bash
python3 tools/robopon.py font-import \
    --target moon \
    --rom baseroms/moon.gbc \
    --png gfx/moon/fonts/dialogue.png \
    --out build/moon_font.gbc
```

---

# Step 4 — Export the script

```bash
python3 tools/robopon.py translation-export \
    --target moon \
    --rom baseroms/moon.gbc
```

This creates:

```
translation/moon/translation.tsv
```

Columns:

| Column | Description |
|---------|-------------|
| index | Text ID |
| source | Japanese text |
| translation | English translation |

Only edit the **translation** column.

---

# Step 5 — Edit the character map

Edit:

```
translation/moon/charmap.tsv
```

The character map defines which Huffman token produces each glyph.

The font PNG and charmap must always match.

---

# Step 6 — Build the translated ROM

```bash
python3 tools/robopon.py translation-build \
    --target moon \
    --rom build/moon_font.gbc \
    --translation translation/moon/translation.tsv \
    --charmap translation/moon/charmap.tsv \
    --out build/moon_translated.gbc
```

---

# Step 7 — Translate menus

Export:

```bash
python3 tools/robopon.py menu-export \
    --target moon \
    --rom baseroms/moon.gbc
```

Edit:

```
translation/moon/menu/menu.tsv
```

Then build:

```bash
python3 tools/robopon.py menu-build \
    --target moon \
    --rom build/moon_translated.gbc \
    --menu translation/moon/menu/menu.tsv \
    --charmap translation/moon/charmap.tsv \
    --out build/moon_menu.gbc
```

---

# Expanded Translation (Future)

The project is being extended to support expanded text banks, allowing translations longer than the original Japanese script.

When available, use:

```bash
python3 tools/robopon.py translation-build-expanded
```

instead of

```
translation-build
```

to automatically rebuild pointer tables and store dialogue in expanded ROM banks.

---

# Recommended Workflow

```
Original ROM
      │
      ▼
Export Font
      │
      ▼
Edit dialogue.png
      │
      ▼
Import Font
      │
      ▼
Export Script
      │
      ▼
Translate translation.tsv
      │
      ▼
Build Translation
      │
      ▼
Translate Menus
      │
      ▼
Finished English ROM
```
