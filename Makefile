RGBASM ?= rgbasm
RGBLINK ?= rgblink
RGBFIX ?= rgbfix
PYTHON ?= python3

TARGETS := sun moon comic

.PHONY: all clean init-sun init-moon init-comic sun moon comic compare-sun compare-moon compare-comic test

all: $(TARGETS)

build:
	mkdir -p build

sun: build asm/sun/main.asm
	$(RGBASM) -o build/sun.o asm/sun/main.asm
	$(RGBLINK) -o build/sun.gbc -m build/sun.map -n build/sun.sym build/sun.o
	$(RGBFIX) -v -p 0xFF build/sun.gbc

moon: build asm/moon/main.asm
	$(RGBASM) -o build/moon.o asm/moon/main.asm
	$(RGBLINK) -o build/moon.gbc -m build/moon.map -n build/moon.sym build/moon.o
	$(RGBFIX) -v -p 0xFF build/moon.gbc

comic: build asm/comic/main.asm
	$(RGBASM) -o build/comic.o asm/comic/main.asm
	$(RGBLINK) -o build/comic.gbc -m build/comic.map -n build/comic.sym build/comic.o
	$(RGBFIX) -v -p 0xFF build/comic.gbc

init-sun:
	$(PYTHON) tools/robopon.py init --target sun --rom baseroms/sun.gbc

init-moon:
	$(PYTHON) tools/robopon.py init --target moon --rom baseroms/moon.gbc

init-comic:
	$(PYTHON) tools/robopon.py init --target comic --rom baseroms/comic.gbc

compare-sun:
	$(PYTHON) tools/robopon.py compare --rom baseroms/sun.gbc --built build/sun.gbc

compare-moon:
	$(PYTHON) tools/robopon.py compare --rom baseroms/moon.gbc --built build/moon.gbc

compare-comic:
	$(PYTHON) tools/robopon.py compare --rom baseroms/comic.gbc --built build/comic.gbc

test:
	pytest -q

clean:
	rm -rf build
