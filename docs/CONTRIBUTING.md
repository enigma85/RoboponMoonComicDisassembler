# Contributing

Do not submit copyrighted ROM data or generated bank binaries.

Good contributions:

- Labeling routines and data tables.
- Replacing `INCBIN` ranges with documented assembly/data.
- Improving analysis tools.
- Adding tests that preserve byte-identical rebuilds.
- Documenting text, compression, font, or pointer formats.

Every change should keep `make <target>` working for any initialized target.
