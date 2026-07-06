# Building Robopon

This project can build byte-identical copies of the original Robopon ROMs.

## Requirements

- Python 3.11+
- RGBDS
- make

## Repository Layout

```
baseroms/
    moon.gbc
    comic.gbc
    sun.gbc
```

Place your legally obtained ROMs into the `baseroms/` directory.

---

## Verify the ROMs

Run:

```bash
python3 tools/robopon.py profile-check
```

This verifies the ROM hashes.

---

## Analyze the ROM

```bash
python3 tools/robopon.py analyze \
    --target moon \
    --rom baseroms/moon.gbc
```

This generates:

- ROM layout
- bank map
- text streams
- font locations
- pointer tables

---

## Generate the disassembly

```bash
python3 tools/robopon.py disasm \
    --target moon \
    --rom baseroms/moon.gbc
```

---

## Build

```bash
make moon
```

or

```bash
make comic
```

or

```bash
make sun
```

---

## Verify

```bash
python3 tools/robopon.py compare \
    --rom baseroms/moon.gbc \
    --built build/moon.gbc
```

The output should report:

```
OK: files are byte-identical
```

If the hashes match, the disassembly is correct.
