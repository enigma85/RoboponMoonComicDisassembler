from pathlib import Path
import importlib.util

ROOT = Path(__file__).resolve().parents[1]

def load_tool():
    spec = importlib.util.spec_from_file_location('robopon_tool', ROOT / 'tools' / 'robopon.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def test_sha1_known():
    mod = load_tool()
    assert mod.sha1(b'abc') == 'a9993e364706816aba3e25717850c26c9cd0d89d'

def test_header_shape():
    mod = load_tool()
    data = bytearray([0] * 0x150)
    data[0x134:0x138] = b'TEST'
    h = mod.rom_header(bytes(data))
    assert h['title_ascii_lossy'] == 'TEST'
