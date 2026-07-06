# Huffman token map export

`huffman-export` extracts the actual one-byte leaf tokens from the ROM text engine's Huffman/tree decoder. Use this when building an English `charmap.tsv`: the font PNG shows glyph graphics, but this command shows which tokens the compressor can actually encode.

```bash
python3 tools/robopon.py huffman-export \
  --target moon \
  --rom baseroms/moon.gbc
```

Outputs:

```text
translation/<target>/huffman_token_map.tsv
translation/<target>/huffman_token_map.json
translation/<target>/charmap_from_huffman.template.tsv
```

Columns include:

- `token_hex`: byte token used by the text engine.
- `default_text`: how the original Japanese decoder renders that token.
- `<stream>_encodable`: whether that token exists in that stream's tree.
- `<stream>_bits`: Huffman bit code for that token in that stream.

For translation, copy token values from `token_hex` into your charmap. Do not use font tile indices or values above `0xFF`.
