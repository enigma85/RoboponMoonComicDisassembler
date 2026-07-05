# Working Workflow

## Initialize

Copy baseroms locally:

```bash
cp /path/to/RoboponSun.gbc baseroms/sun.gbc
cp /path/to/RobotPoncotsMoon.gbc baseroms/moon.gbc
cp /path/to/ComicBomBom.gbc baseroms/comic.gbc
```

Then initialize each target:

```bash
python3 tools/robopon.py init --target sun --rom baseroms/sun.gbc
python3 tools/robopon.py init --target moon --rom baseroms/moon.gbc
python3 tools/robopon.py init --target comic --rom baseroms/comic.gbc
```

## Build and verify

```bash
make moon
python3 tools/robopon.py compare --rom baseroms/moon.gbc --built build/moon.gbc
```

## Compare Sun and Moon

```bash
python3 tools/robopon.py bankdiff --a baseroms/sun.gbc --b baseroms/moon.gbc --out analysis/sun_vs_moon_bankdiff.tsv
python3 tools/text_probe.py sun-strings --rom baseroms/sun.gbc --out analysis/sun_ascii.tsv
```

## Replacing raw banks safely

Start with small routines or tables. Keep the generated `INCBIN` as the truth, replace one range at a time, then rebuild and compare.

Preferred rule: every replacement must keep the target byte-identical until an intentional modification branch is started.
