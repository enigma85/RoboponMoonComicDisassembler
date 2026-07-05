Progressive disassembly scaffold for moon

Banks emitted: 64
Labels emitted: 300

The generated asm preserves exact ROM bytes because every range is still emitted with INCBIN.
To progress the disassembly, replace one labeled INCBIN range at a time with RGBDS code/data,
then run `make TARGET` and `python3 tools/robopon.py compare ...`.

Generated files:
- asm/moon/main.asm
- asm/moon/bank_XX.asm
- analysis/moon/disasm_labels.tsv
