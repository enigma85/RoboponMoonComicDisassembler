# Comic BomBom support

The repository now treats Comic BomBom as a first-class target named `comic`.
Aliases accepted by the CLI include `comic_bombom`, `comic-bombom`, `bombom`,
`bom_bom`, and `bom-bom`.

## Local setup

Do not commit the ROM. Put your own copy at:

```bash
baseroms/comic.gbc
```

Then run:

```bash
python3 tools/robopon.py init --target comic --rom baseroms/comic.gbc
python3 tools/robopon.py analyze --target comic --rom baseroms/comic.gbc
python3 tools/robopon.py disasm --target comic --rom baseroms/comic.gbc
make comic
python3 tools/robopon.py compare --rom baseroms/comic.gbc --built build/comic.gbc
```

There is also a convenience command:

```bash
python3 tools/robopon.py setup-comic --rom /path/to/comic.gbc --copy
```

## Text engine verification

Comic currently inherits the Moon/Sun text stream assumptions:

- dialogue table: `0x38000`
- dialogue tree: `0x0016DA`
- descriptions table: `0x48000`
- descriptions tree: `0x04B900`

Verify before translating:

```bash
python3 tools/robopon.py text-dump --target comic --rom baseroms/comic.gbc
python3 tools/robopon.py text-roundtrip --target comic --rom baseroms/comic.gbc --out analysis/comic/text_roundtrip.json
```

A successful roundtrip means the current Comic text-engine profile is safe to
use for extraction and same-format reinsertion. If it fails, run:

```bash
python3 tools/robopon.py bankdiff --a baseroms/moon.gbc --b baseroms/comic.gbc --out analysis/moon_vs_comic_bankdiff.tsv
python3 tools/robopon.py analyze --target comic --rom baseroms/comic.gbc
```

Then update `profiles/comic.yaml` and `tools/lib/text_engine.py` with the verified
Comic offsets.

## Translation workflow

```bash
python3 tools/robopon.py translation-export --target comic --rom baseroms/comic.gbc
python3 tools/robopon.py translation-validate --target comic --rom baseroms/comic.gbc --translation translation/comic/translation.tsv
python3 tools/robopon.py translation-build --target comic --rom baseroms/comic.gbc --translation translation/comic/translation.tsv --out build/comic_translated.gbc --partial
```

## Font workflow

```bash
python3 tools/robopon.py font-list --target comic
python3 tools/robopon.py font-export --target comic --rom baseroms/comic.gbc --name dialogue
python3 tools/robopon.py font-import --rom baseroms/comic.gbc --png gfx/comic/fonts/dialogue.png --out build/comic_font_test.gbc
```

After export, edit one glyph in `gfx/comic/fonts/dialogue.png` and import it as a
probe. Confirm in an emulator that the visible glyph changes before redrawing the
full font.
