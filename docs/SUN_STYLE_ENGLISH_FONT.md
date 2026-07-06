# Sun-style English dialogue font

`font-english` generated a synthetic bitmap font and could overwrite tiles that
are not really dialogue characters. The safer workflow is now
`font-port-sun-english`: it uses the official English Sun ROM as the reference
font and copies only the kana-slot tile range into Moon or Comic BomBom.

This preserves the target ROM's first-row digits/icons/control symbols and later
UI/status glyphs while replacing the kana area with Sun-style English glyphs.

## Moon

```bash
python3 tools/robopon.py font-port-sun-english \
  --target moon \
  --rom baseroms/moon.gbc \
  --sun-rom baseroms/sun.gbc

python3 tools/robopon.py font-import \
  --rom baseroms/moon.gbc \
  --png gfx/moon/fonts/dialogue.sun-english-kana-slots.png \
  --out build/moon_sun_english_font.gbc
```

## Comic BomBom

```bash
python3 tools/robopon.py font-port-sun-english \
  --target comic \
  --rom baseroms/comic.gbc \
  --sun-rom baseroms/sun.gbc

python3 tools/robopon.py font-import \
  --rom baseroms/comic.gbc \
  --png gfx/comic/fonts/dialogue.sun-english-kana-slots.png \
  --out build/comic_sun_english_font.gbc
```

## Slot policy

Default copied slots:

```text
0x10-0x7F
```

This is the conservative kana area. It intentionally does not copy tile `0x00`
through `0x0F`, which include early icons/digits/control glyphs, and it does not
copy the later UI/status area.

To experiment with a larger or smaller range:

```bash
python3 tools/robopon.py font-port-sun-english \
  --target moon \
  --rom baseroms/moon.gbc \
  --sun-rom baseroms/sun.gbc \
  --slots 0x10-0x7F
```

The command writes a `.slot-map.tsv` showing exactly which tile indices were
copied.
