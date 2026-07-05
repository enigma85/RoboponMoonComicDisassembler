# Font workflow

The previous `font-export` examples used arbitrary offsets. Exporting from an arbitrary address such as `0x12345` will produce a noisy/garbled PNG because that address is not the kana font. The verified Moon/Sun font block is raw Game Boy 2bpp tile data at ROM file offset `0x40B0`.

## Export Moon kana/UI font

```bash
python3 tools/robopon.py font-export --target moon --rom baseroms/moon.gbc --out gfx/moon/font.png
```

This is equivalent to:

```bash
python3 tools/robopon.py font-export --rom baseroms/moon.gbc --offset 0x40B0 --tiles 192 --out gfx/moon/font.png
```

The export also writes `gfx/moon/font.json` with the offset, tile count, scale, and validation score. Keep that metadata with the PNG so import uses the same layout.

## Import edited font

```bash
python3 tools/robopon.py font-import --target moon --rom baseroms/moon.gbc --png gfx/moon/font.png --out build/moon_fonttest.gbc
```

## Find candidates manually

```bash
python3 tools/robopon.py font-scan --target moon --rom baseroms/moon.gbc --out analysis/moon/font_scan
```

Open the generated candidate PNGs and use the offset from `font_candidates.tsv`.

## Notes

- Offsets are ROM file offsets, not CPU addresses.
- The kana/UI block at `0x40B0` contains digits, hiragana/katakana-like glyphs, icons, menu labels, and UI glyphs.
- The scanner only finds raw 2bpp tile blocks. Compressed graphics need a separate decompressor.
