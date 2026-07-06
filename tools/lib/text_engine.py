"""Robopon text engine research helpers.

This module implements the currently understood tree/Huffman text format used by
Robot Poncots / Robopon. It is intentionally conservative: it can decode streams,
re-encode token sequences against the same tree, and verify byte-level roundtrips.
It does not yet claim to solve expanded English insertion or text-engine patching.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
import csv
import json

BANK_SIZE = 0x4000
Tree = int | list[Any]

HIRA = 'をぁぃぅぇぉゃゅょっーあいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわんﾞﾟ'
KATA = 'ヲァィゥェォャュョッーアイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワンﾞﾟ'
ASCII = {i: chr(i) for i in range(0x20, 0x7F)}

SPECIAL = {
    0x00: '<END>',
    0x01: '<PLAYER>',
    0x02: '<RIVAL>',
    0x03: '<ROBOT>',
    0x04: '<NUM>',
    0x05: '<ITEM>',
    0x06: '<PAUSE>',
    0x07: '<PAGE>',
    0x08: '<WAIT>',
    0x09: '<TAB>',
    0x0A: '\\n',
    0x28: '<HIRAGANA>',
    0x29: '<KATAKANA>',
}
SPECIAL_REV = {v: k for k, v in SPECIAL.items() if v != '\\n'}

# These are verified for Moon from the current research. Sun/Comic are found by
# scanning and can be added to profiles as they are verified.
DEFAULT_STREAMS = {
    'moon': [
        {'name': 'dialogue', 'table': 0x38000, 'tree': 0x0016DA},
        {'name': 'descriptions', 'table': 0x48000, 'tree': 0x04B900},
    ],
    'sun': [
        {'name': 'dialogue', 'table': 0x38000, 'tree': 0x0016DA},
        {'name': 'descriptions', 'table': 0x48000, 'tree': 0x04B900},
    ],
    'comic': [
        {'name': 'dialogue', 'table': 0x38000, 'tree': 0x0016DA},
        {'name': 'descriptions', 'table': 0x48000, 'tree': 0x04B900},
    ],
}

@dataclass
class StreamSpec:
    name: str
    table: int
    tree: int


def bank_base(offset: int) -> int:
    return offset & ~(BANK_SIZE - 1)


def gb_addr_to_offset(bank: int, addr: int) -> int:
    return bank | (addr & 0x3FFF)


def rip_tree(data: bytes, pointer: int) -> Tree:
    """Rip the game's in-ROM decision tree routine into a Python tree.

    Tree nodes are encoded as tiny LR35902 code fragments. Known opcodes:
    3E nn = leaf token nn
    38 rr / DA aa aa = branch forms
    C3 aa aa = jump/end marker seen in tree routines
    """
    pos = pointer
    bank = bank_base(pointer)
    end = bank + BANK_SIZE
    raw: dict[int, int | tuple[int, int]] = {}
    while pos < end:
        op_start = pos
        op = data[pos]
        pos += 1
        if op not in (0x3E, 0x38, 0xDA, 0xC3, 0xCD):
            raise ValueError(f'invalid tree opcode 0x{op:02X} at 0x{op_start:06X}')
        if op > 0x40:
            addr = int.from_bytes(data[pos:pos+2], 'little')
            pos += 2
            target = gb_addr_to_offset(bank, addr)
            if op == 0xC3:
                end = target
        elif op == 0x38:
            rel = data[pos]
            pos += 1
            if rel >= 0x80:
                rel -= 0x100
            target = pos + rel
        else:
            raw[op_start] = data[pos]
            pos += 1
            target = -1
        if op in (0x38, 0xDA):
            raw[op_start - 3] = (pos, target)

    def build(node: int, depth: int = 0) -> Tree:
        if depth > 1024:
            raise ValueError('tree recursion too deep')
        v = raw[node]
        if isinstance(v, tuple):
            return [build(v[0], depth + 1), build(v[1], depth + 1)]
        return int(v)
    return build(pointer)


def iter_leaves(tree: Tree) -> Iterable[int]:
    if isinstance(tree, list):
        yield from iter_leaves(tree[0])
        yield from iter_leaves(tree[1])
    else:
        yield int(tree)


def code_map(tree: Tree) -> dict[int, str]:
    out: dict[int, str] = {}
    def walk(node: Tree, bits: str) -> None:
        if isinstance(node, list):
            walk(node[0], bits + '0')
            walk(node[1], bits + '1')
        else:
            out[int(node)] = bits
    walk(tree, '')
    return out


def raw_decode(data: bytes, tree: Tree, offset: int, bit_offset: int = 0, max_bits: int = 12000) -> tuple[list[int], int, bool]:
    out: list[int] = []
    node: Tree = tree
    for used in range(max_bits):
        absolute_bit = bit_offset + used
        byte_pos = offset + absolute_bit // 8
        if byte_pos >= len(data):
            return out, used, False
        bit = (data[byte_pos] >> (7 - (absolute_bit % 8))) & 1
        if not isinstance(node, list):
            node = tree
        node = node[bit]
        if not isinstance(node, list):
            token = int(node)
            out.append(token)
            if token == 0x00:
                return out, used + 1, True
            node = tree
    return out, max_bits, False


def encode_tokens(tokens: Iterable[int], tree: Tree) -> tuple[bytes, int]:
    cmap = code_map(tree)
    bits = ''.join(cmap[int(t)] for t in tokens)
    if not bits or not bits.endswith(cmap[0x00]):
        bits += cmap[0x00]
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b == '1':
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out), len(bits)


def kana_for(token: int, katakana: bool) -> str | None:
    if 0xA6 <= token <= 0xDF:
        return (KATA if katakana else HIRA)[token - 0xA6]
    return None


def render_tokens(tokens: Iterable[int]) -> str:
    katakana = False
    out: list[str] = []
    for token in tokens:
        t = int(token)
        if t == 0x00:
            break
        if t == 0x0A:
            out.append('\\n')
            continue
        if t == 0x28:
            katakana = False
            continue
        if t == 0x29:
            katakana = True
            continue
        k = kana_for(t, katakana)
        if k is not None:
            out.append(k)
        elif t in ASCII:
            out.append(ASCII[t])
        elif t in SPECIAL:
            out.append(SPECIAL[t])
        else:
            out.append(f'<{t:02X}>')
    return ''.join(out)




def render_tokens_with_charmap(tokens: Iterable[int], charmap: dict[str, list[int]]) -> str:
    """Render decoded engine tokens through a translator charmap.

    This is diagnostic only: it does not change ROM encoding.  It lets text-dump
    show English after the kana glyph slots have been repurposed.
    """
    seq = [int(t) for t in tokens]
    inv: dict[tuple[int, ...], str] = {}
    for ch, toks in charmap.items():
        if not toks:
            continue
        inv[tuple(int(x) for x in toks)] = ch
    max_len = max((len(k) for k in inv), default=1)
    out: list[str] = []
    i = 0
    while i < len(seq):
        t = seq[i]
        if t == 0x00:
            break
        if t == 0x0A:
            out.append('\\n'); i += 1; continue
        # Font/mode page controls are not printable.
        if t in (0x28, 0x29):
            i += 1; continue
        matched = False
        for n in range(min(max_len, len(seq)-i), 0, -1):
            key = tuple(seq[i:i+n])
            if key in inv:
                out.append(inv[key]); i += n; matched = True; break
        if matched:
            continue
        if t in SPECIAL and t not in (0x00, 0x0A, 0x28, 0x29):
            out.append(SPECIAL[t])
        else:
            out.append(f'<{t:02X}>')
        i += 1
    return ''.join(out)


def parse_token_hex(raw: str) -> list[int]:
    toks: list[int] = []
    for part in raw.replace(',', ' ').split():
        part = part.strip()
        if not part:
            continue
        if part.lower().startswith('0x'):
            toks.append(int(part, 16))
        else:
            toks.append(int(part, 16))
    return toks


def tokens_to_hex(tokens: Iterable[int]) -> str:
    return ' '.join(f'{int(t):02X}' for t in tokens)


def pointer_candidates(table: int, word: int) -> list[tuple[str, int, int]]:
    c = [
        ('byte14', table + (word & 0x3FFF), 0),
        ('byte13_bit3', table + (word & 0x1FFF), (word >> 13) & 7),
        ('byte13_bit0', table + (word & 0x1FFF), 0),
        ('window14', table + ((word >> 14) * BANK_SIZE) + (word & 0x3FFF), 0),
    ]
    seen: set[tuple[int, int]] = set()
    out: list[tuple[str, int, int]] = []
    for item in c:
        key = (item[1], item[2])
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def score_text(text: str) -> float:
    if len(text.strip()) < 2:
        return -999.0
    kana = sum(c in HIRA or c in KATA for c in text)
    ascii_good = sum(c.isascii() and (c.isalnum() or c in " .,!?'/-") for c in text)
    bad = text.count('<') + text.count('>')
    common = sum(text.count(w) for w in ['ロボポン', 'です', 'ます', 'から', '<PLAYER>'])
    return kana * 2 + ascii_good * .8 + len(text) * .04 + common * 2.5 - bad * 14


def decode_pointer(data: bytes, tree: Tree, table: int, index: int, word: int) -> dict[str, Any]:
    variants = []
    for kind, off, bo in pointer_candidates(table, word):
        toks, bits, ended = raw_decode(data, tree, off, bo)
        txt = render_tokens(toks)
        variants.append({
            'kind': kind, 'offset_int': off, 'offset': f'0x{off:06X}', 'bit_offset': bo,
            'bits': bits, 'bytes': (bits + bo + 7) // 8, 'ended': ended,
            'score': round(score_text(txt), 2), 'text': txt, 'raw_tokens': tokens_to_hex(toks),
        })
    best = max(variants, key=lambda v: (1 if v['ended'] else 0, float(v['score']) + (2 if v['kind'] == 'byte14' else 0)))
    return {
        'index': index,
        'pointer_word': f'0x{word:04X}',
        'pointer_kind': best['kind'],
        'offset': best['offset'],
        'offset_int': best['offset_int'],
        'bit_offset': best['bit_offset'],
        'bits': best['bits'],
        'bytes': best['bytes'],
        'ended': best['ended'],
        'score': best['score'],
        'text': best['text'],
        'raw_tokens': best['raw_tokens'],
        'variants': variants,
    }


def stream_specs_for_target(target: str) -> list[StreamSpec]:
    return [StreamSpec(**x) for x in DEFAULT_STREAMS.get(target, DEFAULT_STREAMS['moon'])]


def dump_stream(data: bytes, spec: StreamSpec) -> list[dict[str, Any]]:
    tree = rip_tree(data, spec.tree)
    first = int.from_bytes(data[spec.table:spec.table+2], 'little') & 0x3FFF
    count = first // 2
    rows = []
    for i in range(count):
        w = int.from_bytes(data[spec.table + 2*i:spec.table + 2*i + 2], 'little')
        r = decode_pointer(data, tree, spec.table, i, w)
        r.update({'stream': spec.name, 'table': f'0x{spec.table:06X}', 'tree': f'0x{spec.tree:06X}'})
        rows.append(r)
    return rows


def dump_all_text(data: bytes, target: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in stream_specs_for_target(target):
        rows.extend(dump_stream(data, spec))
    return rows


def write_text_outputs(rows: list[dict[str, Any]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    public = [{k: v for k, v in r.items() if k != 'offset_int'} for r in rows]
    (out_dir / 'text_dump.json').write_text(json.dumps(public, ensure_ascii=False, indent=2), encoding='utf-8')
    fields = ['stream', 'index', 'pointer_word', 'pointer_kind', 'offset', 'bit_offset', 'tree', 'bits', 'bytes', 'ended', 'score', 'text', 'raw_tokens']
    with (out_dir / 'text_dump.tsv').open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', extrasaction='ignore')
        w.writeheader()
        for r in public:
            rr = dict(r)
            rr['text'] = str(rr.get('text', '')).replace('\n', r'\n')
            w.writerow(rr)


def roundtrip_report(data: bytes, target: str) -> dict[str, Any]:
    streams = []
    total = 0
    ok = 0
    bad_examples = []
    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        rows = dump_stream(data, spec)
        stream_ok = 0
        for r in rows:
            total += 1
            toks = parse_token_hex(r['raw_tokens'])
            packed, bit_count = encode_tokens(toks, tree)
            original = data[int(r['offset'], 16):int(r['offset'], 16)+len(packed)]
            # Only compare the bits used. Last padding bits may differ, so decode packed back.
            rt_toks, _, rt_end = raw_decode(packed, tree, 0, 0, max_bits=bit_count + 16)
            same = toks == rt_toks and rt_end
            if same:
                ok += 1
                stream_ok += 1
            elif len(bad_examples) < 10:
                bad_examples.append({'stream': spec.name, 'index': r['index'], 'tokens': r['raw_tokens'], 'roundtrip': tokens_to_hex(rt_toks)})
        streams.append({'stream': spec.name, 'entries': len(rows), 'roundtrip_ok': stream_ok})
    return {'target': target, 'entries': total, 'roundtrip_ok': ok, 'streams': streams, 'bad_examples': bad_examples}


# ---------------------------------------------------------------------------
# Translation charmap helpers
# ---------------------------------------------------------------------------

# Default kana-slot Latin order.  This maps translator-visible English
# characters to the original Japanese text tokens whose font glyphs have been
# redrawn.  It intentionally uses only tokens that already exist in the game's
# Huffman trees; no text-engine patch is required.
DEFAULT_LATIN_KANA_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " .,!?\"'():;-+/&%#@[]<>*="
)


def default_latin_kana_charmap(start_token: int = 0xA6) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    tok = start_token
    for ch in DEFAULT_LATIN_KANA_CHARS:
        if ch in out:
            continue
        if tok > 0xFF:
            break
        out[ch] = [tok]
        tok += 1
    # Always provide control/newline aliases.
    out['\\n'] = [0x0A]
    return out


def write_charmap_tsv(path: Path, mapping: dict[str, list[int]], *, note: str = '') -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['char','tokens','note'], delimiter='\t')
        w.writeheader()
        for ch, toks in mapping.items():
            visible = '\\n' if ch == '\\n' else ch
            w.writerow({'char': visible, 'tokens': ' '.join(f'{t:02X}' for t in toks), 'note': note})


def _clean_charmap_char(raw: Any) -> str:
    ch = str(raw if raw is not None else '')
    # Preserve literal single-space entries; strip only CR/LF from spreadsheet exports.
    ch = ch.replace('\r', '').replace('\n', '')
    aliases = {
        '<SPACE>': ' ', '[SPACE]': ' ', 'SPACE': ' ', '\\s': ' ',
        '<TAB>': '\t', '[TAB]': '\t',
        '<NL>': '\\n', '<NEWLINE>': '\\n', '[NEWLINE]': '\\n',
    }
    return aliases.get(ch, ch)


def read_charmap(path: Path | None) -> dict[str, list[int]]:
    """Read an encoder charmap as character -> engine/Huffman tokens.

    Accepted TSV columns include:
      char + tokens       preferred
      char + token
      char + token_hex

    Deliberately *does not* treat tile_hex/code_hex as text tokens.  Tile IDs
    are for the font sheet; the text encoder needs engine tokens that exist in
    the Huffman tree.
    """
    if path is None:
        return default_latin_kana_charmap()
    rows: list[dict[str, Any]]
    if path.suffix.lower() == '.json':
        raw = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(raw, dict) and 'map' in raw:
            raw = raw['map']
        if isinstance(raw, dict):
            out: dict[str, list[int]] = {}
            for ch, toks in raw.items():
                key = _clean_charmap_char(ch)
                if key == '\\n':
                    key = '\\n'
                if isinstance(toks, str):
                    out[key] = parse_token_hex(toks)
                else:
                    out[key] = [int(x, 16) if isinstance(x, str) and x.lower().startswith('0x') else int(x) for x in toks]
            return out
        rows = raw
    else:
        with path.open('r', newline='', encoding='utf-8-sig') as f:
            rows = list(csv.DictReader(f, delimiter='\t'))
    out: dict[str, list[int]] = {}
    for r in rows:
        # Be tolerant of slightly different header names.
        ch_raw = r.get('char')
        if ch_raw is None:
            ch_raw = r.get('character') or r.get('glyph') or r.get('unicode')
        ch = _clean_charmap_char(ch_raw)
        if ch == '\\n':
            ch = '\\n'
        toks_raw = str(r.get('tokens') or r.get('token') or r.get('token_hex') or '').strip()
        if not ch or not toks_raw:
            continue
        out[ch] = parse_token_hex(toks_raw)
    return out

def text_to_tokens_with_charmap(text: str, charmap: dict[str, list[int]] | None = None) -> list[int]:
    """Convert translation text using an explicit translation character map.

    This is the path to use after redrawing Moon/Comic kana glyphs to English.
    Each visible English character maps to one or more original engine tokens.
    Raw tokens/control tags are still supported with <XX>, {XX}, <PLAYER>, etc.
    """
    if charmap is None:
        charmap = default_latin_kana_charmap()
    out: list[int] = []
    i = 0
    keys_by_len = sorted((k for k in charmap.keys() if k), key=len, reverse=True)
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text) and text[i+1] == 'n':
            out.extend(charmap.get('\\n', [0x0A])); i += 2; continue
        if ch == '\n':
            out.extend(charmap.get('\\n', [0x0A])); i += 1; continue
        if ch == '<':
            j = text.find('>', i+1)
            if j != -1:
                tag = text[i:j+1]
                inner = text[i+1:j]
                if tag in SPECIAL_REV:
                    out.append(SPECIAL_REV[tag]); i = j+1; continue
                if len(inner) == 2:
                    try:
                        out.append(int(inner, 16)); i = j+1; continue
                    except ValueError:
                        pass
        if ch == '{':
            j = text.find('}', i+1)
            if j != -1:
                inner = text[i+1:j]
                try:
                    out.append(int(inner, 16)); i = j+1; continue
                except ValueError:
                    pass
        matched = False
        for key in keys_by_len:
            if text.startswith(key, i):
                out.extend(charmap[key]); i += len(key); matched = True; break
        if matched:
            continue
        # In charmap mode, never silently fall back to ASCII ord().  If an
        # English character is missing here, the user's charmap needs a row for
        # it; otherwise ASCII bytes like 0x48 reach the Huffman encoder and fail.
        raise ValueError(f'character not in charmap at position {i}: {ch!r}')
    if not out or out[-1] != 0x00:
        out.append(0x00)
    return out


def charmap_coverage_report(data: bytes, target: str, mapping: dict[str, list[int]]) -> dict[str, Any]:
    reports = []
    errors = []
    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        cmap = code_map(tree)
        missing_rows = []
        for ch, toks in mapping.items():
            missing = [t for t in toks if t not in cmap]
            if missing:
                missing_rows.append({'char': ch, 'tokens': [f'0x{x:02X}' for x in toks], 'missing': [f'0x{x:02X}' for x in missing]})
        if missing_rows:
            errors.append({'stream': spec.name, 'missing_charmap_tokens': missing_rows[:50], 'missing_count': len(missing_rows)})
        reports.append({'stream': spec.name, 'chars': len(mapping), 'missing_chars': len(missing_rows), 'ok': not missing_rows})
    return {'target': target, 'streams': reports, 'errors': errors, 'ok': not errors}

# ---------------------------------------------------------------------------
# Translation workflow helpers
# ---------------------------------------------------------------------------

def text_to_tokens(text: str) -> list[int]:
    """Convert editable translation text to engine tokens.

    Supported syntax:
    - normal ASCII characters map to their byte values when present in the tree
    - Japanese kana map to the known kana token range
    - literal newlines or \\n map to token 0x0A
    - <END>, <PLAYER>, <PAGE>, etc. map to known special tokens
    - <XX> or {XX} inserts a raw hexadecimal token, e.g. <A6>
    """
    # Reverse kana maps. Prefer hiragana mode for HIRA, katakana mode for KATA.
    hira_rev = {ch: 0xA6 + i for i, ch in enumerate(HIRA)}
    kata_rev = {ch: 0xA6 + i for i, ch in enumerate(KATA)}
    out: list[int] = []
    katakana = False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and i + 1 < len(text) and text[i+1] == 'n':
            out.append(0x0A); i += 2; continue
        if ch == '\n':
            out.append(0x0A); i += 1; continue
        if ch == '<':
            j = text.find('>', i+1)
            if j != -1:
                tag = text[i:j+1]
                inner = text[i+1:j]
                if tag in SPECIAL_REV:
                    out.append(SPECIAL_REV[tag]); i = j+1; continue
                if len(inner) == 2:
                    try:
                        out.append(int(inner, 16)); i = j+1; continue
                    except ValueError:
                        pass
        if ch == '{':
            j = text.find('}', i+1)
            if j != -1:
                inner = text[i+1:j]
                try:
                    out.append(int(inner, 16)); i = j+1; continue
                except ValueError:
                    pass
        if ch in hira_rev:
            if katakana:
                out.append(0x28); katakana = False
            out.append(hira_rev[ch]); i += 1; continue
        if ch in kata_rev:
            if not katakana:
                out.append(0x29); katakana = True
            out.append(kata_rev[ch]); i += 1; continue
        if len(ch.encode('utf-8')) == 1 and 0x20 <= ord(ch) <= 0x7E:
            out.append(ord(ch)); i += 1; continue
        raise ValueError(f'unsupported character at position {i}: {ch!r}')
    if not out or out[-1] != 0x00:
        out.append(0x00)
    return out


def export_translation_files(data: bytes, target: str, out_dir: Path) -> list[dict[str, Any]]:
    rows = dump_all_text(data, target)
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = ['stream','index','source','translation','notes','raw_tokens','pointer_word','offset','bytes','bits']
    with (out_dir / 'translation.tsv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t')
        w.writeheader()
        for r in rows:
            w.writerow({
                'stream': r['stream'],
                'index': r['index'],
                'source': str(r['text']).replace('\n', r'\n'),
                'translation': '',
                'notes': '',
                'raw_tokens': r['raw_tokens'],
                'pointer_word': r['pointer_word'],
                'offset': r['offset'],
                'bytes': r['bytes'],
                'bits': r['bits'],
            })
    json_rows = []
    for r in rows:
        json_rows.append({
            'stream': r['stream'], 'index': r['index'], 'source': r['text'],
            'translation': '', 'notes': '', 'raw_tokens': r['raw_tokens'],
            'pointer_word': r['pointer_word'], 'offset': r['offset'], 'bytes': r['bytes'], 'bits': r['bits'],
        })
    (out_dir / 'translation.json').write_text(json.dumps(json_rows, ensure_ascii=False, indent=2), encoding='utf-8')
    return rows


def read_translation_file(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == '.json':
        return json.loads(path.read_text(encoding='utf-8'))
    rows: list[dict[str, Any]] = []
    with path.open('r', newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f, delimiter='\t'):
            rows.append(dict(r))
    return rows


def _mode_wrapped_translation_tokens(row: dict[str, Any], toks: list[int]) -> list[int]:
    """Preserve the original dialogue font-page/mode wrapper around edited text.

    In Robopon Moon/Comic, tokens 0x28 and 0x29 are not ordinary printable
    parentheses for dialogue: they select the kana/font page used by the renderer.
    When the kana glyphs are redrawn as English letters, edited strings still
    need the same leading/trailing mode tokens as the original string.  Without
    them, the game can render the right Huffman tokens through the wrong glyph
    page, which appears as garbled text.
    """
    try:
        raw = parse_token_hex(str(row.get('raw_tokens', '')))
    except Exception:
        raw = []
    if not raw:
        return toks

    prefix: list[int] = []
    suffix: list[int] = []

    # Preserve a leading font-page selector such as <HIRAGANA> / <KATAKANA>.
    if raw and raw[0] in (0x28, 0x29) and (not toks or toks[0] not in (0x28, 0x29)):
        prefix.append(raw[0])

    # Many strings end with the opposite selector immediately before END.
    # Preserve it unless the translated tokens already end with a selector.
    raw_body = raw[:-1] if raw and raw[-1] == 0x00 else raw
    if raw_body and raw_body[-1] in (0x28, 0x29) and (not toks or toks[-1] not in (0x28, 0x29)):
        suffix.append(raw_body[-1])

    return prefix + toks + suffix


def _translated_tokens(row: dict[str, Any], charmap: dict[str, list[int]] | None = None) -> tuple[list[int], bool, str | None]:
    text = str(row.get('translation', '') or '')
    if text.strip():
        try:
            if charmap is not None:
                toks = text_to_tokens_with_charmap(text, charmap)
            else:
                toks = text_to_tokens(text)
            return _mode_wrapped_translation_tokens(row, toks), True, None
        except Exception as e:
            return [], True, str(e)
    try:
        return parse_token_hex(str(row.get('raw_tokens', ''))), False, None
    except Exception as e:
        return [], False, f'bad raw_tokens: {e}'


def validate_translation(data: bytes, target: str, translation_path: Path, charmap_path: Path | None = None) -> dict[str, Any]:
    rows = read_translation_file(translation_path)
    charmap = read_charmap(charmap_path) if charmap_path is not None else None
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_stream.setdefault(str(r.get('stream')), []).append(r)
    report: dict[str, Any] = {'target': target, 'file': str(translation_path), 'streams': [], 'errors': [], 'warnings': []}
    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        cmap = code_map(tree)
        src = sorted(by_stream.get(spec.name, []), key=lambda r: int(r.get('index', 0)))
        if not src:
            report['warnings'].append(f'no rows for stream {spec.name}')
            continue
        capacity = BANK_SIZE - ((len(src) * 2) & (BANK_SIZE - 1))
        table_bytes = len(src) * 2
        used = 0
        unique_sequences: set[tuple[int, ...]] = set()
        changed = 0
        unsupported = 0
        for r in src:
            toks, did_change, err = _translated_tokens(r, charmap)
            idx = r.get('index')
            if did_change:
                changed += 1
            if err:
                unsupported += 1
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': err})
                continue
            missing = sorted({int(t) for t in toks if int(t) not in cmap})
            if missing:
                unsupported += 1
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': 'tokens not present in Huffman tree', 'tokens': [f'0x{x:02X}' for x in missing]})
                continue
            key = tuple(int(t) for t in toks)
            if key not in unique_sequences:
                packed, bits = encode_tokens(toks, tree)
                used += len(packed)
                unique_sequences.add(key)
        stream_report = {
            'stream': spec.name,
            'entries': len(src),
            'changed': changed,
            'table_offset': f'0x{spec.table:06X}',
            'tree_offset': f'0x{spec.tree:06X}',
            'pointer_table_bytes': table_bytes,
            'unique_packed_bytes': used,
            'unique_strings': len(unique_sequences),
            'capacity_bytes_after_pointer_table_in_bank': capacity,
            'bytes_left': capacity - used,
            'unsupported_rows': unsupported,
            'fits_original_bank': used <= capacity,
        }
        if used > capacity:
            report['errors'].append({'stream': spec.name, 'error': 'stream overflow', 'unique_packed_bytes': used, 'capacity': capacity})
        report['streams'].append(stream_report)
    report['ok'] = not report['errors']
    return report


def build_translation_rom(data: bytes, target: str, translation_path: Path, allow_partial: bool = False, charmap_path: Path | None = None) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    rows = read_translation_file(translation_path)
    charmap = read_charmap(charmap_path) if charmap_path is not None else None
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_stream.setdefault(str(r.get('stream')), []).append(r)
    rom = bytearray(data)
    report: dict[str, Any] = {'target': target, 'file': str(translation_path), 'streams': [], 'errors': [], 'warnings': []}
    skipped: list[dict[str, Any]] = []
    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        cmap = code_map(tree)
        src = sorted(by_stream.get(spec.name, []), key=lambda r: int(r.get('index', 0)))
        if not src:
            continue
        count = len(src)
        table_start = spec.table
        stream_bank_end = bank_base(spec.table) + BANK_SIZE
        data_start = table_start + count * 2
        pos = data_start
        ptr_words: list[int] = []
        encoded_offsets: dict[tuple[int, ...], int] = {}
        changed = 0
        written = 0
        for r in src:
            toks, did_change, err = _translated_tokens(r, charmap)
            if did_change:
                changed += 1
            idx = int(r.get('index', 0))
            if err:
                if allow_partial:
                    skipped.append({'stream': spec.name, 'index': idx, 'reason': err, 'translation': r.get('translation','')})
                    toks = parse_token_hex(str(r.get('raw_tokens', '')))
                else:
                    report['errors'].append({'stream': spec.name, 'index': idx, 'error': err}); continue
            missing = sorted({int(t) for t in toks if int(t) not in cmap})
            if missing:
                reason = 'tokens not present in Huffman tree: ' + ','.join(f'0x{x:02X}' for x in missing)
                if allow_partial:
                    skipped.append({'stream': spec.name, 'index': idx, 'reason': reason, 'translation': r.get('translation','')})
                    toks = parse_token_hex(str(r.get('raw_tokens', '')))
                else:
                    report['errors'].append({'stream': spec.name, 'index': idx, 'error': reason}); continue
            key = tuple(int(t) for t in toks)
            if key in encoded_offsets:
                ptr_words.append(encoded_offsets[key])
                written += 1
                continue
            packed, bits = encode_tokens(toks, tree)
            if pos + len(packed) > stream_bank_end:
                reason = f'not enough original-bank capacity for {len(packed)} bytes at stream offset 0x{pos:06X}'
                if allow_partial and str(r.get('translation','')).strip():
                    skipped.append({'stream': spec.name, 'index': idx, 'reason': reason, 'translation': r.get('translation','')})
                    toks = parse_token_hex(str(r.get('raw_tokens', '')))
                    key = tuple(int(t) for t in toks)
                    if key in encoded_offsets:
                        ptr_words.append(encoded_offsets[key])
                        written += 1
                        continue
                    packed, bits = encode_tokens(toks, tree)
                if pos + len(packed) > stream_bank_end:
                    report['errors'].append({'stream': spec.name, 'index': idx, 'error': reason}); break
            ptr = pos - table_start
            if not (0 <= ptr <= 0x3FFF):
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': f'pointer out of range 0x{ptr:04X}'}); break
            ptr_words.append(ptr)
            encoded_offsets[key] = ptr
            rom[pos:pos+len(packed)] = packed
            pos += len(packed)
            written += 1
        if len(ptr_words) == count:
            for i, ptr in enumerate(ptr_words):
                rom[table_start + 2*i: table_start + 2*i + 2] = int(ptr).to_bytes(2, 'little')
            # Clear unused tail of stream bank to make diffs readable. Avoid table area.
            for i in range(pos, stream_bank_end):
                rom[i] = 0xFF
        report['streams'].append({
            'stream': spec.name, 'entries': count, 'written': written, 'changed_requested': changed,
            'table_offset': f'0x{table_start:06X}', 'data_start': f'0x{data_start:06X}',
            'data_end': f'0x{pos:06X}', 'packed_bytes': max(0, pos - data_start),
            'capacity_bytes': stream_bank_end - data_start, 'bytes_left': stream_bank_end - pos, 'unique_strings': len(encoded_offsets),
        })
    report['ok'] = not report['errors']
    if report['errors'] and not allow_partial:
        raise ValueError(json.dumps(report, ensure_ascii=False, indent=2))
    return bytes(rom), report, skipped




# ---------------------------------------------------------------------------
# Expanded translation packing helpers
# ---------------------------------------------------------------------------

def _rom_size_code(size: int) -> int:
    # Game Boy header ROM size codes for common power-of-two ROM sizes.
    table = {
        0x8000: 0x00,      # 32 KiB
        0x10000: 0x01,     # 64 KiB
        0x20000: 0x02,     # 128 KiB
        0x40000: 0x03,     # 256 KiB
        0x80000: 0x04,     # 512 KiB
        0x100000: 0x05,    # 1 MiB
        0x200000: 0x06,    # 2 MiB
        0x400000: 0x07,    # 4 MiB
        0x800000: 0x08,    # 8 MiB
    }
    return table.get(size, 0x07 if size <= 0x400000 else 0x08)

def _fix_gb_checksums_text_engine(rom: bytearray) -> None:
    # Keep local copy so text_engine can produce bootable expanded ROMs without
    # importing robopon.py.
    x = 0
    for i in range(0x134, 0x14D):
        x = (x - rom[i] - 1) & 0xFF
    rom[0x14D] = x
    total = (sum(rom[:0x14E]) + sum(rom[0x150:])) & 0xFFFF
    rom[0x14E] = (total >> 8) & 0xFF
    rom[0x14F] = total & 0xFF

def _next_power_of_two_rom_size(n: int) -> int:
    size = 0x8000
    while size < n:
        size <<= 1
    return size


def _write_expanded_runtime_header(rom: bytearray, report: dict[str, Any], *, header_bank: int, header_offset: int, pointer_tables: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Write a compact runtime manifest for a future/installed ASM hook.

    This is intentionally simple and stable:
      RPEXT1\0
      stream_count:u8
      repeated stream records:
        name_len:u8, ascii name bytes
        count:u16
        table_offset:u24  (absolute ROM offset of 3-byte banked pointer table)
      pointer table entries:
        bank:u8, addr_lo:u8, addr_hi:u8

    A CPU hook can bank-switch to this header, locate the active stream's banked
    pointer table, read bank+address for the requested index, bank-switch, and
    call the normal Huffman decoder at that address.
    """
    pos = header_offset
    magic = b'RPEXT1\0'
    rom[pos:pos+len(magic)] = magic; pos += len(magic)
    rom[pos] = len(pointer_tables) & 0xFF; pos += 1
    table_payloads: list[tuple[str, int, bytes]] = []
    # Reserve descriptor space first; write pointer tables immediately after.
    desc_start = pos
    for name, entries in pointer_tables.items():
        name_b = name.encode('ascii', 'replace')[:31]
        pos += 1 + len(name_b) + 2 + 3
    table_start = pos
    for name, entries in pointer_tables.items():
        table_off = pos
        payload = bytearray()
        for e in entries:
            bank = int(str(e.get('bank','0')).replace('0x',''), 16)
            addr = int(str(e.get('gb_addr','0')).replace('0x',''), 16)
            payload.extend([bank & 0xFF, addr & 0xFF, (addr >> 8) & 0xFF])
        rom[pos:pos+len(payload)] = payload
        pos += len(payload)
        table_payloads.append((name, table_off, payload))
    # Fill descriptors.
    dpos = desc_start
    for name, table_off, payload in table_payloads:
        entries = pointer_tables[name]
        name_b = name.encode('ascii', 'replace')[:31]
        rom[dpos] = len(name_b); dpos += 1
        rom[dpos:dpos+len(name_b)] = name_b; dpos += len(name_b)
        count = len(entries)
        rom[dpos] = count & 0xFF; rom[dpos+1] = (count >> 8) & 0xFF; dpos += 2
        rom[dpos] = table_off & 0xFF; rom[dpos+1] = (table_off >> 8) & 0xFF; rom[dpos+2] = (table_off >> 16) & 0xFF; dpos += 3
    return {
        'magic': 'RPEXT1',
        'header_bank': f'0x{header_bank:02X}',
        'header_offset': f'0x{header_offset:06X}',
        'end_offset': f'0x{pos:06X}',
        'stream_tables': [
            {'stream': name, 'table_offset': f'0x{off:06X}', 'bytes': len(payload), 'entries': len(pointer_tables[name])}
            for name, off, payload in table_payloads
        ],
        'cpu_hook_status': 'runtime manifest installed; CPU trampoline must be connected to text decoder before game can use expanded banks automatically'
    }

def build_translation_rom_expanded(
    data: bytes,
    target: str,
    translation_path: Path,
    charmap_path: Path | None = None,
    *,
    start_bank: int = 0x40,
    max_size: int = 0x400000,
    fill_byte: int = 0xFF,
    install_hook: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    """Pack all translated text into expanded ROM banks.

    This command creates a *data-packed expanded ROM* plus a machine-readable
    manifest.  It intentionally does not pretend that the stock game can read
    these banks by itself: Robopon's original stream pointers are 16-bit and do
    not carry a bank number.  A text-engine hook/trampoline must consume the
    generated expanded_pointer_tables before the expanded data becomes active in
    game.

    The value of this function is that it solves the space/layout side: it
    encodes every string, stores it in unlimited appended banks, and records exact
    bank/offset/length information for the engine patch step.
    """
    rows = read_translation_file(translation_path)
    charmap = read_charmap(charmap_path) if charmap_path is not None else None
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_stream.setdefault(str(r.get('stream')), []).append(r)

    start_off = start_bank * BANK_SIZE
    required_min = max(len(data), start_off)
    rom_size = _next_power_of_two_rom_size(required_min + BANK_SIZE)
    if rom_size > max_size:
        raise ValueError(f'requested expanded ROM exceeds max size 0x{max_size:X}')
    rom = bytearray(data)
    if len(rom) < rom_size:
        rom.extend(bytes([fill_byte]) * (rom_size - len(rom)))

    pos = start_off
    report: dict[str, Any] = {
        'target': target,
        'file': str(translation_path),
        'mode': 'expanded-data-pack',
        'runtime_status': 'expanded text packed; runtime header installed when install_hook=True',
        'charmap': str(charmap_path) if charmap_path else None,
        'charmap_entries': len(charmap) if charmap else 0,
        'expanded_start_bank': f'0x{start_bank:02X}',
        'expanded_start_offset': f'0x{start_off:06X}',
        'streams': [],
        'errors': [],
        'warnings': [],
    }

    expanded_pointer_tables: dict[str, list[dict[str, Any]]] = {}

    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        huff_codes = code_map(tree)
        src = sorted(by_stream.get(spec.name, []), key=lambda r: int(r.get('index', 0)))
        if not src:
            report['warnings'].append(f'no rows for stream {spec.name}')
            continue

        stream_start = pos
        entries: list[dict[str, Any]] = []
        changed = 0
        unique: dict[tuple[int, ...], dict[str, Any]] = {}

        for r in src:
            idx = int(r.get('index', 0))
            tr = str(r.get('translation', '') or '')
            toks, did_change, err = _translated_tokens(r, charmap)
            if did_change:
                changed += 1
            if err:
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': str(err)})
                continue
            missing = sorted({int(t) for t in toks if int(t) not in huff_codes})
            if missing:
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': 'tokens not present in Huffman tree: ' + ','.join(f'0x{x:02X}' for x in missing)})
                continue
            key = tuple(int(t) for t in toks)
            if key in unique:
                ent = dict(unique[key])
                ent['index'] = idx
                ent['dedup_of'] = unique[key]['index']
                entries.append(ent)
                continue
            packed, bits = encode_tokens(toks, tree)
            # Grow to next power-of-two size as necessary, up to max_size.
            if pos + len(packed) > len(rom):
                new_size = _next_power_of_two_rom_size(pos + len(packed))
                if new_size > max_size:
                    report['errors'].append({'stream': spec.name, 'index': idx, 'error': f'expanded ROM overflow: need 0x{pos+len(packed):X}, max 0x{max_size:X}'})
                    continue
                rom.extend(bytes([fill_byte]) * (new_size - len(rom)))
            off = pos
            rom[off:off+len(packed)] = packed
            pos += len(packed)
            ent = {
                'index': idx,
                'offset': f'0x{off:06X}',
                'bank': f'0x{off // BANK_SIZE:02X}',
                'bank_offset': f'0x{off % BANK_SIZE:04X}',
                'gb_addr': f'0x{0x4000 + (off % BANK_SIZE):04X}' if off >= BANK_SIZE else f'0x{off:04X}',
                'packed_bytes': len(packed),
                'bits': bits,
                'changed': bool(did_change),
                'translation': tr,
            }
            unique[key] = dict(ent)
            entries.append(ent)

        expanded_pointer_tables[spec.name] = entries
        report['streams'].append({
            'stream': spec.name,
            'entries': len(src),
            'changed_requested': changed,
            'expanded_data_start': f'0x{stream_start:06X}',
            'expanded_data_end': f'0x{pos:06X}',
            'packed_bytes': pos - stream_start,
            'unique_strings': len(unique),
            'expanded_pointer_format': 'bank,gb_addr,packed_bytes per row; requires engine hook',
        })

    report['expanded_pointer_tables'] = expanded_pointer_tables
    if install_hook:
        # Place runtime header after packed text, aligned to 0x100.
        header_offset = (pos + 0xFF) & ~0xFF
        header_end_needed = header_offset + 0x100 + sum(len(v)*3 for v in expanded_pointer_tables.values())
        if header_end_needed > len(rom):
            new_size = _next_power_of_two_rom_size(header_end_needed)
            if new_size > max_size:
                report['errors'].append({'stream': 'runtime', 'index': -1, 'error': f'expanded hook header overflow: need 0x{header_end_needed:X}, max 0x{max_size:X}'})
            else:
                rom.extend(bytes([fill_byte]) * (new_size - len(rom)))
        if not report['errors']:
            hook_info = _write_expanded_runtime_header(rom, report, header_bank=header_offset//BANK_SIZE, header_offset=header_offset, pointer_tables=expanded_pointer_tables)
            report['expanded_runtime_header'] = hook_info
            pos = max(pos, int(hook_info['end_offset'], 16))
            report['runtime_status'] = 'expanded runtime header installed; CPU hook connection still target-specific'
    report['expanded_end_offset'] = f'0x{pos:06X}'
    final_size = _next_power_of_two_rom_size(max(pos, len(data)))
    final_size = max(final_size, len(data))
    if final_size < len(rom):
        rom = rom[:final_size]
    if len(rom) in (0x8000,0x10000,0x20000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000):
        rom[0x148] = _rom_size_code(len(rom))
    _fix_gb_checksums_text_engine(rom)
    report['rom_size'] = len(rom)
    report['rom_size_hex'] = f'0x{len(rom):X}'
    report['ok'] = not report['errors']
    if report['errors']:
        raise ValueError(json.dumps(report, ensure_ascii=False, indent=2))
    return bytes(rom), report

# ---------------------------------------------------------------------------
# Basic Game Boy 2bpp font helpers. These operate on explicitly supplied offsets.
# ---------------------------------------------------------------------------

def tile_to_pixels(tile: bytes) -> list[list[int]]:
    px: list[list[int]] = []
    for y in range(8):
        lo = tile[y*2]
        hi = tile[y*2+1]
        row = []
        for x in range(8):
            bit = 7 - x
            row.append(((hi >> bit) & 1) * 2 + ((lo >> bit) & 1))
        px.append(row)
    return px


def pixels_to_tile(px: list[list[int]]) -> bytes:
    out = bytearray(16)
    for y in range(8):
        lo = hi = 0
        for x in range(8):
            v = int(px[y][x]) & 3
            bit = 7 - x
            lo |= (v & 1) << bit
            hi |= ((v >> 1) & 1) << bit
        out[y*2] = lo; out[y*2+1] = hi
    return bytes(out)


def export_font_png(data: bytes, offset: int, tiles: int, out_png: Path, scale: int = 2, columns: int = 16) -> None:
    try:
        from PIL import Image
    except Exception as e:
        raise RuntimeError('Pillow is required for font PNG export/import: python3 -m pip install pillow') from e
    rows = (tiles + columns - 1) // columns
    img = Image.new('RGBA', (columns*8, rows*8), (255,255,255,0))
    palette = [(255,255,255,0), (170,170,170,255), (85,85,85,255), (0,0,0,255)]
    for t in range(tiles):
        tile = data[offset + t*16: offset + t*16 + 16]
        px = tile_to_pixels(tile.ljust(16, b'\0'))
        ox = (t % columns) * 8; oy = (t // columns) * 8
        for y in range(8):
            for x in range(8):
                img.putpixel((ox+x, oy+y), palette[px[y][x]])
    if scale != 1:
        img = img.resize((img.width*scale, img.height*scale), Image.Resampling.NEAREST)
    out_png.parent.mkdir(parents=True, exist_ok=True)
    img.save(out_png)


def import_font_png(data: bytes, offset: int, tiles: int, in_png: Path, scale: int = 2, columns: int = 16) -> bytes:
    try:
        from PIL import Image
    except Exception as e:
        raise RuntimeError('Pillow is required for font PNG export/import: python3 -m pip install pillow') from e
    img = Image.open(in_png).convert('RGBA')
    if scale != 1:
        img = img.resize((img.width//scale, img.height//scale), Image.Resampling.NEAREST)
    rom = bytearray(data)
    for t in range(tiles):
        ox = (t % columns) * 8; oy = (t // columns) * 8
        px: list[list[int]] = []
        for y in range(8):
            row = []
            for x in range(8):
                r,g,b,a = img.getpixel((ox+x, oy+y))
                if a < 64:
                    v = 0
                else:
                    lum = (r+g+b)//3
                    v = 3 if lum < 64 else 2 if lum < 128 else 1 if lum < 220 else 0
                row.append(v)
            px.append(row)
        rom[offset + t*16: offset + t*16 + 16] = pixels_to_tile(px)
    return bytes(rom)

# Override v6 translation validation/build with patch-oriented semantics:
# untranslated rows are left byte-for-byte untouched; only edited rows consume capacity.

def _free_runs_in_bank(data: bytes, bank_start: int, bank_end: int, protected_until: int, min_len: int = 4) -> list[tuple[int, int]]:
    runs: list[tuple[int, int]] = []
    i = max(bank_start, protected_until)
    while i < bank_end:
        if data[i] not in (0x00, 0xFF):
            i += 1; continue
        val = data[i]
        j = i + 1
        while j < bank_end and data[j] == val:
            j += 1
        if j - i >= min_len:
            runs.append((i, j - i))
        i = j
    return runs


def _free_runs_in_range(data: bytes, start: int, end: int, protected: list[tuple[int, int]] | None = None, min_len: int = 4) -> list[tuple[int, int]]:
    """Find 00/FF free runs in a ROM range, excluding protected intervals."""
    protected = sorted(protected or [])
    def is_protected(pos: int) -> int | None:
        for a, b in protected:
            if a <= pos < b:
                return b
        return None
    runs: list[tuple[int, int]] = []
    i = start
    while i < min(end, len(data)):
        skip_to = is_protected(i)
        if skip_to is not None:
            i = skip_to
            continue
        if data[i] not in (0x00, 0xFF):
            i += 1; continue
        val = data[i]
        j = i + 1
        while j < min(end, len(data)) and data[j] == val and is_protected(j) is None:
            j += 1
        if j - i >= min_len:
            runs.append((i, j - i))
        i = j
    return runs


def _encode_pointer_for_offset(table_start: int, offset: int, pointer_mode: str) -> int:
    """Encode a text pointer word for an absolute ROM offset.

    same-bank uses the low 14-bit byte offset from the pointer table.
    window14 uses the top two bits as a 16 KiB window index. Existing Robopon
    dialogue pointers have been observed decoding this way, allowing strings in
    the table bank and the next three banks without a code patch.
    """
    delta = offset - table_start
    if pointer_mode == 'same-bank':
        if not (0 <= delta <= 0x3FFF):
            raise ValueError(f'pointer out of same-bank range for offset 0x{offset:06X}')
        return delta
    if pointer_mode == 'window14':
        if not (0 <= delta <= 0xFFFF):
            raise ValueError(f'pointer out of window14 range for offset 0x{offset:06X}')
        window = delta // BANK_SIZE
        low = delta & 0x3FFF
        if not (0 <= window <= 3):
            raise ValueError(f'window14 window out of range for offset 0x{offset:06X}')
        return (window << 14) | low
    raise ValueError(f'unknown pointer_mode: {pointer_mode}')

def _allocation_runs_for_stream(data: bytes, target: str, spec: StreamSpec, count: int, pointer_mode: str) -> tuple[list[tuple[int,int]], str]:
    table_start = spec.table
    table_end = table_start + count * 2
    if pointer_mode == 'window14':
        start = table_end
        end = min(table_start + 0x10000, len(data))
        # Protect all known stream pointer tables so expanded dialogue cannot
        # overwrite description pointers or other text tables in the window.
        protected = []
        for other in stream_specs_for_target(target):
            # Use a conservative 0x1000 table protection if exact row count is not known.
            if table_start <= other.table < end:
                protected.append((other.table, min(other.table + 0x1000, end)))
        return _free_runs_in_range(data, start, end, protected=protected, min_len=8), f'0x{start:06X}-0x{end:06X}'
    bank_start = bank_base(table_start)
    bank_end = bank_start + BANK_SIZE
    return _free_runs_in_bank(data, bank_start, bank_end, table_end, min_len=8), f'0x{table_end:06X}-0x{bank_end:06X}'


def validate_translation(data: bytes, target: str, translation_path: Path, charmap_path: Path | None = None) -> dict[str, Any]:
    rows = read_translation_file(translation_path)
    charmap = read_charmap(charmap_path) if charmap_path is not None else None
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_stream.setdefault(str(r.get('stream')), []).append(r)
    report: dict[str, Any] = {'target': target, 'file': str(translation_path), 'mode': 'patch-edited-rows', 'charmap': str(charmap_path) if charmap_path else None, 'charmap_entries': len(charmap) if charmap else 0, 'streams': [], 'errors': [], 'warnings': []}
    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        cmap = code_map(tree)
        src = sorted(by_stream.get(spec.name, []), key=lambda r: int(r.get('index', 0)))
        if not src:
            report['warnings'].append(f'no rows for stream {spec.name}')
            continue
        table_start = spec.table
        bank_start = bank_base(table_start)
        bank_end = bank_start + BANK_SIZE
        protected_until = table_start + len(src) * 2
        free_runs = _free_runs_in_bank(data, bank_start, bank_end, protected_until)
        free_total = sum(n for _, n in free_runs)
        changed = 0; in_place = 0; needs_extra = 0; extra_bytes = 0; unsupported = 0
        for r in src:
            if not str(r.get('translation','') or '').strip():
                continue
            changed += 1
            toks, _, err = _translated_tokens(r, charmap)
            idx = r.get('index')
            if err:
                unsupported += 1; report['errors'].append({'stream': spec.name, 'index': idx, 'error': err}); continue
            missing = sorted({int(t) for t in toks if int(t) not in cmap})
            if missing:
                unsupported += 1; report['errors'].append({'stream': spec.name, 'index': idx, 'error': 'tokens not present in Huffman tree', 'tokens': [f'0x{x:02X}' for x in missing]}); continue
            packed, bits = encode_tokens(toks, tree)
            old_bytes = int(r.get('bytes') or 0)
            if len(packed) <= old_bytes:
                in_place += 1
            else:
                needs_extra += 1; extra_bytes += len(packed)
        if extra_bytes > free_total:
            report['errors'].append({'stream': spec.name, 'error': 'not enough same-bank free space for edited rows', 'extra_needed_bytes': extra_bytes, 'free_bytes': free_total})
        report['streams'].append({
            'stream': spec.name, 'entries': len(src), 'changed': changed,
            'in_place_possible': in_place, 'needs_pointer_rebuild': needs_extra,
            'extra_needed_bytes': extra_bytes, 'same_bank_free_bytes': free_total,
            'free_runs': [{'offset': f'0x{o:06X}', 'length': n} for o,n in free_runs[:20]],
            'unsupported_rows': unsupported,
            'fits_patch_mode': extra_bytes <= free_total,
        })
    report['ok'] = not report['errors']
    return report



def build_translation_rom(data: bytes, target: str, translation_path: Path, allow_partial: bool = False, charmap_path: Path | None = None, pointer_mode: str = 'same-bank') -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    """Build a translated ROM by patching only edited translation rows.

    This is the safe mode for the current Robopon text engine work:
    - Unedited rows remain byte-for-byte unchanged, so replacing the font does not
      require re-encoding the entire Japanese stream.
    - Edited rows are converted through charmap.tsv into existing Huffman tokens.
    - If the new encoded string fits in the original string's byte allocation, it
      is written in place and padded.
    - If it does not fit, the builder tries to place it in an existing 0x00/0xFF
      free run in the same text bank and updates that row's pointer.

    Full-script translation still needs either much shorter English, DTE/MTE, or
    an expanded text-engine patch. This command is intended for accurate testing
    and incremental translation without corrupting unchanged rows.
    """
    rows = read_translation_file(translation_path)
    charmap = read_charmap(charmap_path) if charmap_path is not None else None
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_stream.setdefault(str(r.get('stream')), []).append(r)

    rom = bytearray(data)
    report: dict[str, Any] = {
        'target': target,
        'file': str(translation_path),
        'mode': 'patch-edited-rows',
        'pointer_mode': pointer_mode,
        'charmap': str(charmap_path) if charmap_path else None,
        'charmap_entries': len(charmap) if charmap else 0,
        'streams': [],
        'errors': [],
        'warnings': [],
    }
    skipped: list[dict[str, Any]] = []

    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree)
        huff_codes = code_map(tree)
        src = sorted(by_stream.get(spec.name, []), key=lambda r: int(r.get('index', 0)))
        if not src:
            report['warnings'].append(f'no rows for stream {spec.name}')
            continue

        table_start = spec.table
        bank_start = bank_base(table_start)
        bank_end = bank_start + BANK_SIZE
        protected_until = table_start + len(src) * 2
        free_runs, allocation_range = _allocation_runs_for_stream(bytes(rom), target, spec, len(src), pointer_mode)
        free_i = 0
        changed = written = in_place = repointed = too_long = 0

        for r in src:
            tr = str(r.get('translation', '') or '')
            if not tr.strip():
                continue
            changed += 1
            idx = int(r.get('index', 0))
            toks, did_change, err = _translated_tokens(r, charmap)
            if err:
                if allow_partial:
                    skipped.append({'stream': spec.name, 'index': idx, 'reason': str(err), 'translation': tr})
                    continue
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': str(err)})
                continue
            missing = sorted({int(t) for t in toks if int(t) not in huff_codes})
            if missing:
                reason = 'tokens not present in Huffman tree: ' + ','.join(f'0x{x:02X}' for x in missing)
                if allow_partial:
                    skipped.append({'stream': spec.name, 'index': idx, 'reason': reason, 'translation': tr})
                    continue
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': reason})
                continue

            packed, bits = encode_tokens(toks, tree)
            try:
                old_off = int(str(r.get('offset', '')).strip(), 0)
                old_bytes = int(str(r.get('bytes', '')).strip() or '0')
            except Exception as e:
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': f'bad offset/bytes in translation row: {e}'})
                continue
            if not (bank_start <= old_off < bank_end):
                report['errors'].append({'stream': spec.name, 'index': idx, 'error': f'old offset 0x{old_off:06X} outside stream bank'})
                continue

            if len(packed) <= old_bytes:
                rom[old_off:old_off + len(packed)] = packed
                if old_bytes > len(packed):
                    rom[old_off + len(packed):old_off + old_bytes] = b'\xFF' * (old_bytes - len(packed))
                written += 1
                in_place += 1
                continue

            # Try repointing to same-bank free space.
            placed = False
            need = len(packed)
            while free_i < len(free_runs):
                run_off, run_len = free_runs[free_i]
                if run_len < need:
                    free_i += 1
                    continue
                rom[run_off:run_off + need] = packed
                if run_len > need:
                    free_runs[free_i] = (run_off + need, run_len - need)
                else:
                    free_i += 1
                try:
                    ptr = _encode_pointer_for_offset(table_start, run_off, pointer_mode)
                except ValueError as e:
                    report['errors'].append({'stream': spec.name, 'index': idx, 'error': str(e)})
                    placed = True
                    break
                rom[table_start + idx*2: table_start + idx*2 + 2] = int(ptr).to_bytes(2, 'little')
                written += 1
                repointed += 1
                placed = True
                break
            if not placed:
                too_long += 1
                reason = f'translation encoded to {need} bytes, original slot has {old_bytes} bytes, and no same-bank free run is large enough'
                if allow_partial:
                    skipped.append({'stream': spec.name, 'index': idx, 'reason': reason, 'translation': tr})
                else:
                    report['errors'].append({'stream': spec.name, 'index': idx, 'error': reason})

        report['streams'].append({
            'stream': spec.name,
            'entries': len(src),
            'changed_requested': changed,
            'written': written,
            'in_place': in_place,
            'repointed': repointed,
            'too_long': too_long,
            'table_offset': f'0x{table_start:06X}',
            'remaining_free_runs': len([r for r in free_runs[free_i:] if r[1] >= 8]),
            'allocation_range': allocation_range,
        })

    report['ok'] = not report['errors']
    if report['errors'] and not allow_partial:
        raise ValueError(json.dumps(report, ensure_ascii=False, indent=2))
    return bytes(rom), report, skipped

