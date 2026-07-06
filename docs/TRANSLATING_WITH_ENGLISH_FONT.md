# Translating with the imported English font

After `font-port-sun-english` / `font-import`, Moon and Comic can draw English-looking glyphs from the original kana token slots.  The translator workflow now uses an explicit `charmap.tsv` so the text builder knows which original engine token draws each English character.

## 1. Export a charmap

```bash
python3 tools/robopon.py charmap-export --target moon --rom baseroms/moon.gbc
python3 tools/robopon.py charmap-export --target comic --rom baseroms/comic.gbc
```

This creates:

```text
translation/<target>/charmap.tsv
translation/<target>/charmap.validate.json
```

Edit `charmap.tsv` if your font sheet uses a different character order.  The format is:

```text
char    tokens  note
A       A6      kana-slot English character
B       A7      kana-slot English character
\n      0A      newline
```

A character may map to multiple tokens if needed, for example a styled symbol or a control sequence.

## 2. Export the script

```bash
python3 tools/robopon.py translation-export --target moon --rom baseroms/moon.gbc
```

Edit the `translation` column in:

```text
translation/moon/translation.tsv
```

Use plain English characters that exist in `charmap.tsv`.  Control tags like `<PLAYER>`, `<PAGE>`, `<WAIT>`, `<END>`, raw `<A6>`, and `\n` are still supported.

## 3. Validate

```bash
python3 tools/robopon.py translation-validate \
  --target moon \
  --rom baseroms/moon.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.tsv
```

Validation checks:

- every translated character exists in the charmap,
- every charmap token exists in the stream Huffman tree,
- the rebuilt stream fits the original bank,
- control/raw token syntax is valid.

## 4. Build

```bash
python3 tools/robopon.py translation-build \
  --target moon \
  --rom build/moon_sun_english_font.gbc \
  --translation translation/moon/translation.tsv \
  --charmap translation/moon/charmap.tsv \
  --out build/moon_translated.gbc
```

Use the font-patched ROM as the input ROM so the output contains both the English font and the translated script.

## Capacity note

This still rebuilds into the original text banks.  Full English script expansion may require abbreviation, partial builds, better compression, or a future expanded-bank text-engine patch.  The validation report tells you when a stream overflows.
