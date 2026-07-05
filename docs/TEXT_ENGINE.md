# Robopon Text Engine Notes

This repository now has a first real text-engine module. It is conservative and
roundtrip-focused: it decodes the currently known compressed streams, re-encodes
the exact same token sequence against the same tree, and verifies that the codec
is internally lossless.

## Known Moon streams

| Stream | Pointer table | Tree routine | Entries |
|---|---:|---:|---:|
| dialogue | `0x038000` | `0x0016DA` | 2000 |
| descriptions | `0x048000` | `0x04B900` | 2001 |

The pointer tables contain 16-bit words. The most common interpretation is a
14-bit byte offset relative to the bank containing the table. Some entries appear
to use bit-level/shared suffix references, so the decoder scores several pointer
interpretations and records the best one in the TSV/JSON output.

## Tree format

The compressed text tree is encoded as small LR35902 code fragments. The current
ripper recognizes these opcodes:

| Opcode | Meaning in tree ripper |
|---:|---|
| `3E nn` | leaf token `nn` |
| `38 rr` | relative branch form |
| `DA aa aa` | absolute branch form |
| `C3 aa aa` | jump/end boundary seen while ripping tree code |
| `CD aa aa` | call-like branch form, retained by the current heuristic |

The tool converts these routines into a Python binary tree. A left edge is bit
`0`, and a right edge is bit `1`.

## Token rendering

Known control tokens:

| Token | Meaning |
|---:|---|
| `00` | end of string |
| `01` | `<PLAYER>` |
| `02` | `<RIVAL>` |
| `03` | `<ROBOT>` |
| `04` | `<NUM>` |
| `05` | `<ITEM>` |
| `06` | `<PAUSE>` |
| `07` | `<PAGE>` |
| `08` | `<WAIT>` |
| `09` | `<TAB>` |
| `0A` | newline |
| `28` | switch to hiragana rendering mode |
| `29` | switch to katakana rendering mode |
| `A6..DF` | kana glyph range, interpreted using current kana mode |

This table is intentionally marked as research, not final documentation. Control
codes should be validated in emulator traces before they are treated as stable.

## Commands

Decode known streams:

```bash
python3 tools/robopon.py text-dump --target moon --rom baseroms/moon.gbc
```

This writes:

```text
text/moon/text_dump.tsv
text/moon/text_dump.json
```

Verify codec roundtrip:

```bash
python3 tools/robopon.py text-roundtrip --target moon --rom baseroms/moon.gbc --out analysis/moon/text_roundtrip.json
```

Dump tree code maps:

```bash
python3 tools/robopon.py text-tree --target moon --rom baseroms/moon.gbc
```

This writes code tables under:

```text
analysis/moon/text_engine/
```

## Current limitation

This milestone proves the decoder and encoder can preserve existing token
streams. It does not yet produce a complete English build. The next milestone is
a translation-aware encoder that either uses a verified English Sun character
system or rebuilds the tree and text renderer safely.
