Progressive disassembly scaffold for comic

Banks emitted: 64
Labels emitted: 300

The generated asm preserves exact ROM bytes because every range is still emitted with INCBIN.
To progress the disassembly, replace one labeled INCBIN range at a time with RGBDS code/data,
then run `make TARGET` and `python3 tools/robopon.py compare ...`.

Generated files:
- asm/comic/main.asm
- asm/comic/bank_XX.asm
- analysis/comic/disasm_labels.tsv
