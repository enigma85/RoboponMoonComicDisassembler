# Roadmap

## Milestone 0 — Rebuild scaffold

- [x] Split ROM into banks locally.
- [x] Generate RGBDS `INCBIN` assembly.
- [x] Rebuild ROM.
- [x] Byte-compare against baserom.

## Milestone 1 — Map the ROM

- [ ] Name interrupt vectors and reset/startup code.
- [ ] Identify bank switching routines.
- [ ] Identify graphics loading routines.
- [ ] Identify text decompression routine.
- [ ] Identify script command interpreter.

## Milestone 2 — Text engine

- [ ] Locate compressed text streams.
- [ ] Locate pointer tables.
- [ ] Document Huffman/tree format.
- [ ] Implement lossless decoder.
- [ ] Implement encoder.
- [ ] Rebuild text streams from source.

## Milestone 3 — Sun-to-Moon translation support

- [ ] Compare Sun English text engine to Moon Japanese engine.
- [ ] Locate English font/charmap in Sun.
- [ ] Port or recreate Latin font path for Moon/Comic.
- [ ] Build expanded text storage strategy.
- [ ] Validate text display in emulator.

## Milestone 4 — Full source replacement

- [ ] Replace raw banks with labeled assembly progressively.
- [ ] Extract graphics into rebuildable assets.
- [ ] Extract maps/data into structured sources.
- [ ] Maintain byte-identical builds after each replacement.
