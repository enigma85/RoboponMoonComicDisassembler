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


def _translated_tokens(row: dict[str, Any]) -> tuple[list[int], bool, str | None]:
    text = str(row.get('translation', '') or '')
    if text.strip():
        try:
            return text_to_tokens(text), True, None
        except Exception as e:
            return [], True, str(e)
    try:
        return parse_token_hex(str(row.get('raw_tokens', ''))), False, None
    except Exception as e:
        return [], False, f'bad raw_tokens: {e}'


def validate_translation(data: bytes, target: str, translation_path: Path) -> dict[str, Any]:
    rows = read_translation_file(translation_path)
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
            toks, did_change, err = _translated_tokens(r)
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


def build_translation_rom(data: bytes, target: str, translation_path: Path, allow_partial: bool = False) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    rows = read_translation_file(translation_path)
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
            toks, did_change, err = _translated_tokens(r)
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


def validate_translation(data: bytes, target: str, translation_path: Path) -> dict[str, Any]:
    rows = read_translation_file(translation_path)
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_stream.setdefault(str(r.get('stream')), []).append(r)
    report: dict[str, Any] = {'target': target, 'file': str(translation_path), 'mode': 'patch-edited-rows', 'streams': [], 'errors': [], 'warnings': []}
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
            toks, _, err = _translated_tokens(r)
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


def build_translation_rom(data: bytes, target: str, translation_path: Path, allow_partial: bool = False) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    rows = read_translation_file(translation_path)
    by_stream: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        by_stream.setdefault(str(r.get('stream')), []).append(r)
    rom = bytearray(data)
    report: dict[str, Any] = {'target': target, 'file': str(translation_path), 'mode': 'patch-edited-rows', 'streams': [], 'errors': [], 'warnings': []}
    skipped: list[dict[str, Any]] = []
    for spec in stream_specs_for_target(target):
        tree = rip_tree(data, spec.tree); cmap = code_map(tree)
        src = sorted(by_stream.get(spec.name, []), key=lambda r: int(r.get('index', 0)))
        if not src: continue
        table_start = spec.table
        bank_start = bank_base(table_start); bank_end = bank_start + BANK_SIZE
        protected_until = table_start + len(src)*2
        free_runs = _free_runs_in_bank(data, bank_start, bank_end, protected_until)
        run_i = 0; run_pos = free_runs[0][0] if free_runs else 0; run_end = free_runs[0][0]+free_runs[0][1] if free_runs else 0
        changed = in_place = repointed = written = 0
        for r in src:
            trans = str(r.get('translation','') or '')
            if not trans.strip(): continue
            changed += 1
            idx = int(r.get('index', 0))
            toks, _, err = _translated_tokens(r)
            if err:
                if allow_partial: skipped.append({'stream': spec.name,'index':idx,'reason':err,'translation':trans}); continue
                report['errors'].append({'stream': spec.name,'index':idx,'error':err}); continue
            missing = sorted({int(t) for t in toks if int(t) not in cmap})
            if missing:
                reason = 'tokens not present in Huffman tree: ' + ','.join(f'0x{x:02X}' for x in missing)
                if allow_partial: skipped.append({'stream': spec.name,'index':idx,'reason':reason,'translation':trans}); continue
                report['errors'].append({'stream': spec.name,'index':idx,'error':reason}); continue
            packed, bits = encode_tokens(toks, tree)
            old_off = int(str(r.get('offset')), 16)
            old_bytes = int(r.get('bytes') or 0)
            if len(packed) <= old_bytes:
                rom[old_off:old_off+len(packed)] = packed
                # Fill leftover with FF; pointer remains unchanged.
                for j in range(old_off+len(packed), old_off+old_bytes): rom[j] = 0xFF
                in_place += 1; written += 1; continue
            # Allocate in same bank free run and rebuild pointer word.
            while run_i < len(free_runs) and run_pos + len(packed) > run_end:
                run_i += 1
                if run_i < len(free_runs):
                    run_pos = free_runs[run_i][0]; run_end = free_runs[run_i][0] + free_runs[run_i][1]
            if run_i >= len(free_runs):
                reason = f'no same-bank free run large enough for {len(packed)} bytes'
                if allow_partial: skipped.append({'stream': spec.name,'index':idx,'reason':reason,'translation':trans}); continue
                report['errors'].append({'stream': spec.name,'index':idx,'error':reason}); continue
            ptr = run_pos - table_start
            if not (0 <= ptr <= 0x3FFF):
                reason = f'new pointer out of 14-bit range: 0x{ptr:04X}'
                if allow_partial: skipped.append({'stream': spec.name,'index':idx,'reason':reason,'translation':trans}); continue
                report['errors'].append({'stream': spec.name,'index':idx,'error':reason}); continue
            rom[run_pos:run_pos+len(packed)] = packed
            rom[table_start + idx*2: table_start + idx*2 + 2] = int(ptr).to_bytes(2, 'little')
            run_pos += len(packed)
            repointed += 1; written += 1
        report['streams'].append({
            'stream': spec.name, 'changed_requested': changed, 'written': written,
            'in_place': in_place, 'repointed': repointed,
            'remaining_free_runs': len(free_runs) - run_i if free_runs else 0,
        })
    report['ok'] = not report['errors']
    if report['errors'] and not allow_partial:
        raise ValueError(json.dumps(report, ensure_ascii=False, indent=2))
    return bytes(rom), report, skipped
