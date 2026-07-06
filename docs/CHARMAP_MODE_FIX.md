# Charmap mode wrapper fix

When the Moon/Comic kana font is redrawn as English, translated strings still
need the original text renderer's font-page control tokens.

The dialogue engine uses tokens like `0x28` and `0x29` as mode/page selectors.
They are not just normal printable parentheses in the compressed stream.  If an
edited line is encoded as plain English tokens without the original leading mode
selector, the game can draw the correct tokens through the wrong glyph page,
which appears as garbled text.

`translation-build` now preserves the original row's leading and trailing mode
selector tokens around the text produced from `charmap.tsv`.

Example: if the original row was:

```text
28 C4 DE B3 ... 29 00
```

and the translation is:

```text
What?
```

then the builder encodes:

```text
28 <tokens for What?> 29 00
```

instead of only:

```text
<tokens for What?> 00
```
