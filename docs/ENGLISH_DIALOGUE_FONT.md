# English dialogue font workflow

This project now treats the dialogue font as a named asset.  You do not need to
pass raw ROM offsets when editing the font.

## 1. Export the current dialogue font

```bash
python3 tools/robopon.py font-export --target moon --rom baseroms/moon.gbc --name dialogue
```

This writes:

```text
gfx/moon/fonts/dialogue.png
gfx/moon/fonts/dialogue.json
gfx/moon/fonts/dialogue.tbl
```

`dialogue.json` records the ROM offset, bank, tile count, scale, source ROM SHA1,
and source-region SHA1.  The importer reads this file automatically.

## 2. Confirm this is the active runtime font

Before redrawing every glyph, make a one-glyph test:

```bash
python3 tools/robopon.py font-glyph-test --target moon --rom baseroms/moon.gbc --tile 0 --char A
python3 tools/robopon.py font-import --rom baseroms/moon.gbc --png gfx/moon/fonts/dialogue.glyph-test.png --out build/moon_font_test.gbc
```

Boot `build/moon_font_test.gbc`.  If the first kana-slot glyph changes to `A`,
this is the active dialogue font.  If it does not, keep the PNG and report so the
font profile can be corrected.

## 3. Generate an English replacement sheet

```bash
python3 tools/robopon.py font-english --target moon --rom baseroms/moon.gbc
```

By default this overwrites `gfx/moon/fonts/dialogue.png` with an editable English
kana-slot font and saves the original as:

```text
gfx/moon/fonts/dialogue.kana-original.png
```

It also writes:

```text
gfx/moon/fonts/dialogue.english-map.tsv
```

The map shows which old kana token slot is being reused for each English glyph.
This is a graphics-layer step only; the text encoder still needs to emit matching
slots.

## 4. Import the edited font

```bash
python3 tools/robopon.py font-import --rom baseroms/moon.gbc --png gfx/moon/fonts/dialogue.png --out build/moon_english_font.gbc
```

The importer validates that:

- the PNG has matching metadata,
- the ROM SHA1 matches the export source,
- the destination font region still matches the export source,
- and only the expected font region changes.

## Comic BomBom

Comic uses the same named workflow:

```bash
python3 tools/robopon.py font-export --target comic --rom baseroms/comic.gbc --name dialogue
python3 tools/robopon.py font-glyph-test --target comic --rom baseroms/comic.gbc --tile 0 --char A
python3 tools/robopon.py font-import --rom baseroms/comic.gbc --png gfx/comic/fonts/dialogue.glyph-test.png --out build/comic_font_test.gbc
```

Once verified:

```bash
python3 tools/robopon.py font-english --target comic --rom baseroms/comic.gbc
python3 tools/robopon.py font-import --rom baseroms/comic.gbc --png gfx/comic/fonts/dialogue.png --out build/comic_english_font.gbc
```
