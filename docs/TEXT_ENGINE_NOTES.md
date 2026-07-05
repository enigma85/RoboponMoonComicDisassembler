# Text Engine Notes

The current project intentionally does not assume a final character table or Huffman tree layout.

Known working facts from previous experiments:

- Moon has compressed streams that can be extracted in large pointer-table groups.
- Naive byte insertion can alter data but still display kana.
- Blind font offset patching is unsafe.
- Blind Huffman-tree leaf replacement corrupts other strings.
- Sun English is the correct reference for the Latin rendering path.

Next RE tasks:

1. Find the routine that reads text bits/tree nodes.
2. Identify how decoded symbols become tile/glyph IDs.
3. Compare the same routine in Sun and Moon.
4. Identify whether Sun uses a different tree, charmap, font, or renderer.
5. Build encoder only after the format is documented.
