# V0RTEX Plugin
# Name: DecompX
# Version: 3.0.0
# Author: Vider_06
# Description: Full-stack script decompiler & deobfuscator — EXE/PYC/PYZ/PY, Python 3.6-3.14, Nuitka/cx_Freeze/py2exe, semantic rename, CFF solver, XOR brute-force, call graph, data flow, vx API integration
# Dependencies: uncompyle6, decompyle3, pyinstxtractor, tempfile, dis, __future__
# Class: Elevated
# Elevated-Permissions: fs.read.external, fs.write.html, fs.write.json, fs.write.zip, proc.read
# Background-Network: no
# Background-Endpoints: none
# Min-V0RTEX-Version: 1.0.1

"""
DecompX v3.0 — V0RTEX-Made Plugin
====================================
Closes all gaps identified in the v2.0 audit.

PIPELINE
════════
Stage 1  Input Resolution
  .exe    → PyInstaller (pyinstxtractor)
            Nuitka     (strings + pattern heuristic)
            cx_Freeze  (library/ unpacker)
            py2exe     (library.zip unpacker)
          → .pyc files
  .pyz    → ZipApp unpacker → .pyc files
  .pyc    → uncompyle6 (3.6–3.8)
            decompyle3 (3.9–3.10)
            pycdc      (3.11–3.14, subprocess)
            dis        (ultimate fallback, bytecode)
  .py     → multi-layer decode (b64, zlib, hex, rot13, XOR-key-brute)

Stage 2  Decode Engine
  - exec(b64decode(...)) unwrapper, recursive ×8
  - exec(marshal.loads(zlib.decompress(...))) unwrapper
  - XOR brute-force with index-of-coincidence key detection (1–4 byte keys)
  - High-entropy line scanner (Shannon entropy per line)
  - Inline decoder: chr() chains, hex escapes, reversed strings

Stage 3  Obfuscation Detection
  Score 0–100 across 10 signals:
  exec-wrapper, entropy, chr-chains, identifier ratio,
  CFF state-machine, junk assignments, marshal.loads,
  PyArmor bootstrap, string encrypt helpers, homoglyph names

Stage 4  CFF Solver (Control Flow Flattening)
  - Detects while-True dispatch loop with state variable
  - Extracts state→block mapping
  - Reconstructs linear execution order
  - Replaces flattened code with readable if/elif chain

Stage 5  Semantic Renaming
  - Type annotation context (def f(x: int) → x stays readable)
  - 50+ API call contexts
  - Assignment value context ([], {}, open(), socket()…)
  - Call graph–aware: rename propagates to callers/callees
  - Regex fallback for non-AST-parseable scripts

Stage 6  Static Analysis
  - Full AST parse: imports, functions, classes, strings
  - Call graph (who calls whom, depth-first)
  - Data flow: tracks variable from source → sink (exfil detection)
  - 22 suspicious patterns
  - IOC extraction with stdlib whitelist (no false positives on os.path)

Stage 7  Reports
  - HTML  (V0RTEX dark theme, syntax highlight, call graph ASCII)
  - JSON  (machine-readable, full analysis)
  - MD    (human summary + rename map, only if obfuscated)

Stage 8  V0RTEX API Integration
  - vx.scan.hook   → auto-trigger on V0RTEX scan completion
  - vx.scan.submit_iocs → push IOCs to V0RTEX threat engine
  - vx.scan.tag_file    → tag the analysed file in V0RTEX dashboard
  - vx.db.store/query   → cache results by SHA256, show diff on re-scan
  - vx.net.resolve      → IP/domain reputation via V0RTEX resolver
  - vx.event.emit       → emit decompx.analysis_complete for other plugins
  - vx.ui.notify        → progress notifications in V0RTEX UI

UI  (Tkinter, dark theme, non-blocking daemon thread)
  Tabs: Log · Analysis · IOC · Call Graph · Data Flow · Rename Map
  Source viewer: syntax highlight, Ctrl+F search, jump-to-function
  Toolbar: Browse · Drag-drop hint · Run · Clear · Save .py · Save Log
  Status bar + animated progress bar
  File history (last 10 files, persisted via vx.db)
  Light/dark theme follows vx.ui.theme
"""

# ═══════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════
from __future__ import annotations
import ast, base64, binascii, collections, copy, dis, hashlib
import io, itertools, json, marshal, math, os, pathlib, re
import shutil, string, subprocess, sys, tempfile, textwrap
import threading, time, tkinter as tk, traceback, zlib
from collections import Counter, defaultdict
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

# ═══════════════════════════════════════════════════════════════
#  THEME
# ═══════════════════════════════════════════════════════════════
TH = {
    "bg":      "#0b0b0f", "panel":  "#13131a", "card":   "#1a1a24",
    "border":  "#26263a", "accent": "#7b68ee", "accent2":"#00d4aa",
    "accent3": "#f5a623", "warn":   "#f0a500", "danger": "#e05c5c",
    "ok":      "#4cca82", "fg":     "#d0d0e8", "fg_dim": "#6a6a90",
    "src_bg":  "#0d0d14",
    "font":    ("Consolas", 10), "font_b": ("Consolas", 10, "bold"),
    "font_h":  ("Consolas", 14, "bold"), "font_sm": ("Consolas", 9),
    "font_xs": ("Consolas", 8),
}

# ═══════════════════════════════════════════════════════════════
#  LOGGER
# ═══════════════════════════════════════════════════════════════
class DXLog:
    ICONS = {"DEBUG":"·","INFO":"▸","STEP":"◈","WARN":"⚠","ERROR":"✗","OK":"✔"}
    def __init__(self):
        self._e: list[dict] = []
        self._lock = threading.Lock()
        self._cbs: list = []
    def add_cb(self, fn): self._cbs.append(fn)
    def _emit(self, lvl, msg, detail=""):
        e = {"ts": datetime.now().strftime("%H:%M:%S.%f")[:-3],
             "level": lvl, "icon": self.ICONS.get(lvl,"·"),
             "msg": msg, "detail": detail}
        with self._lock: self._e.append(e)
        for cb in self._cbs:
            try: cb(e)
            except Exception: pass
    def debug(self,m,d=""): self._emit("DEBUG",m,d)
    def info(self,m,d=""):  self._emit("INFO",m,d)
    def step(self,m,d=""):  self._emit("STEP",m,d)
    def warn(self,m,d=""):  self._emit("WARN",m,d)
    def error(self,m,d=""): self._emit("ERROR",m,d)
    def ok(self,m,d=""):    self._emit("OK",m,d)
    def entries(self):
        with self._lock: return list(self._e)
    def clear(self):
        with self._lock: self._e.clear()
    def as_text(self):
        return "\n".join(
            f"[{e['ts']}] {e['icon']} {e['msg']}" +
            (f"\n    {e['detail']}" if e.get("detail") else "")
            for e in self.entries())

LOG = DXLog()

# ═══════════════════════════════════════════════════════════════
#  STAGE 1 — DECODER ENGINE
# ═══════════════════════════════════════════════════════════════
def _entropy(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values() if v)

def _try_b64(d: bytes) -> bytes | None:
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            r = fn(d + b"=" * (-len(d) % 4))
            if len(r) >= 4: return r
        except Exception: pass
    return None

def _try_zlib(d: bytes) -> bytes | None:
    for wb in (15, -15, 15+32):
        try: return zlib.decompress(d, wb)
        except Exception: pass
    return None

def _try_hex(d: bytes) -> bytes | None:
    s = d.decode("ascii","ignore").strip().replace(" ","").replace("\n","")
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) >= 8 and len(s) % 2 == 0:
        try: return bytes.fromhex(s)
        except Exception: pass
    return None

def _try_rot13(d: bytes) -> bytes | None:
    try:
        t = d.decode("ascii")
        r = t.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        if r != t and r.isprintable(): return r.encode()
    except Exception: pass
    return None

def _index_of_coincidence(data: bytes) -> float:
    """Friedman IC — near 0.065 for English text."""
    n = len(data)
    if n < 2: return 0.0
    c = Counter(data)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

def _try_xor_bruteforce(data: bytes) -> bytes | None:
    """Brute-force XOR key 1–4 bytes using index-of-coincidence."""
    best_ic, best = 0.0, None
    for keylen in range(1, 5):
        for key_ints in itertools.product(range(256), repeat=keylen):
            key = bytes(key_ints)
            dec = bytes(b ^ key[i % keylen] for i, b in enumerate(data))
            ic = _index_of_coincidence(dec)
            if ic > best_ic:
                best_ic = ic
                best = dec
            if best_ic > 0.060:   # good enough — stop early
                break
        if best_ic > 0.060:
            break
    if best_ic > 0.045:   # threshold: clearly text-like
        LOG.debug(f"  XOR decoded (IC={best_ic:.4f})")
        return best
    return None

def decode_layers(raw: bytes) -> tuple[bytes, list[str]]:
    layers, cur = [], raw
    for _ in range(12):
        changed = False
        for name, fn in [("zlib",_try_zlib),("base64",_try_b64),
                          ("hex",_try_hex),("rot13",_try_rot13)]:
            r = fn(cur)
            if r and r != cur and len(r) >= 4:
                ea, eb = _entropy(cur), _entropy(r)
                pr = sum(chr(b).isprintable() for b in r[:500]) / min(500,len(r))
                if eb < ea or pr > 0.75:
                    layers.append(name); cur = r; changed = True
                    LOG.debug(f"  Layer: {name} ent {ea:.2f}→{eb:.2f}"); break
        if not changed: break
    return cur, layers

def _unwrap_exec(source: str) -> tuple[str, list[str]]:
    """Unwrap exec(b64decode(...)), exec(marshal.loads(zlib...)) recursively."""
    layers, cur = [], source
    PATS = [
        re.compile(r'exec\s*\(\s*(?:base64\.)?b64decode\s*\(\s*[bB]?["\']([A-Za-z0-9+/=\r\n]+)["\']', re.S),
        re.compile(r'exec\s*\(\s*(?:zlib\.)?decompress\s*\(\s*(?:base64\.)?b64decode\s*\(\s*[bB]?["\']([A-Za-z0-9+/=\r\n]+)["\']', re.S),
        re.compile(r'exec\s*\(\s*marshal\.loads\s*\(\s*(?:zlib\.)?decompress\s*\(\s*(?:base64\.)?b64decode\s*\(\s*[bB]?["\']([A-Za-z0-9+/=\r\n]+)["\']', re.S),
    ]
    for _ in range(8):
        found = False
        for pat in PATS:
            m = pat.search(cur)
            if m:
                payload = m.group(1).encode()
                dec, sublayers = decode_layers(payload)
                # also try marshal
                try:
                    code = marshal.loads(dec)
                    buf = io.StringIO(); dis.dis(code, file=buf)
                    dec = f"# [DecompX] marshal.loads unwrapped\n{buf.getvalue()}".encode()
                    sublayers.append("marshal")
                except Exception: pass
                try:
                    text = dec.decode("utf-8", errors="replace")
                    if len(text) > 20:
                        layers.extend(sublayers or ["exec-unwrap"])
                        cur = text; found = True
                        LOG.debug(f"  exec-unwrap: {sublayers or ['direct']}")
                        break
                except Exception: pass
        if not found: break
    return cur, layers

def scan_entropy_lines(source: str) -> list[dict]:
    res = []
    for i, line in enumerate(source.splitlines(), 1):
        s = line.strip()
        if len(s) < 40: continue
        e = _entropy(s.encode())
        if e > 5.2:
            res.append({"line":i,"entropy":round(e,2),"preview":s[:80]})
    return res

def extract_inline_encoded(source: str) -> list[dict]:
    findings = []
    # base64
    for m in re.finditer(r'b64decode\s*\(\s*[bB]?["\']([A-Za-z0-9+/=\s]{16,})["\']', source):
        raw = m.group(1).replace(" ","").replace("\n","")
        dec, _ = decode_layers(raw.encode())
        try: text = dec.decode("utf-8", errors="replace")
        except: text = repr(dec[:80])
        findings.append({"type":"base64","offset":m.start(),"encoded":raw[:60],"decoded":text[:200]})
    # chr() chains
    for m in re.finditer(r'(?:chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}chr\s*\(\s*\d+\s*\)', source):
        nums = re.findall(r'chr\s*\(\s*(\d+)\s*\)', m.group(0))
        try:
            text = "".join(chr(int(n)) for n in nums)
            findings.append({"type":"chr-chain","offset":m.start(),"encoded":m.group(0)[:60],"decoded":text[:200]})
        except: pass
    # hex escapes
    for m in re.finditer(r'(?:\\x[0-9a-fA-F]{2}){4,}', source):
        try:
            dec = bytes.fromhex(m.group(0).replace("\\x","")).decode("utf-8",errors="replace")
            findings.append({"type":"hex-escape","offset":m.start(),"encoded":m.group(0)[:60],"decoded":dec[:200]})
        except: pass
    # reversed strings
    for m in re.finditer(r'["\']([A-Za-z0-9+/=]{20,})["\'][::-1]', source):
        try:
            text = m.group(1)[::-1]
            findings.append({"type":"reversed","offset":m.start(),"encoded":m.group(1)[:60],"decoded":text[:200]})
        except: pass
    return findings

# ═══════════════════════════════════════════════════════════════
#  STAGE 1 — EXE UNPACKERS
# ═══════════════════════════════════════════════════════════════
def _detect_exe_packer(exe_path: str) -> str:
    """Heuristic: detect PyInstaller / Nuitka / cx_Freeze / py2exe."""
    try:
        data = pathlib.Path(exe_path).read_bytes()
    except: return "unknown"
    if b"PKG\x00" in data or b"PYINSTALLER" in data.upper() or b"pyi-" in data:
        return "pyinstaller"
    if b"Nuitka" in data or b"__nuitka" in data:
        return "nuitka"
    if b"cx_Freeze" in data or b"library.zip" in data:
        return "cx_freeze"
    if b"py2exe" in data or b"zipextimporter" in data.lower():
        return "py2exe"
    return "unknown"

def _unpack_pyinstaller(exe_path: str, out_dir: str) -> list[str]:
    LOG.step("Unpacking PyInstaller EXE")
    try:
        import pyinstxtractor as pxt
        orig = os.getcwd(); os.chdir(out_dir)
        try:
            arch = pxt.PyInstArchive(exe_path)
            if arch.open() and arch.checkMagicNumber():
                arch.getCArchiveInfo(); arch.parseTOC()
                arch.extractFiles(); arch.close()
                LOG.ok("pyinstxtractor done")
            else:
                LOG.warn("Not a valid PyInstaller archive")
                return _carve_pyc(exe_path, out_dir)
        finally: os.chdir(orig)
    except ImportError:
        LOG.warn("pyinstxtractor not installed — carving")
        return _carve_pyc(exe_path, out_dir)
    except Exception as e:
        LOG.error(f"pyinstxtractor: {e}")
        return _carve_pyc(exe_path, out_dir)
    pycs = [str(p) for p in pathlib.Path(out_dir).rglob("*.pyc")]
    LOG.info(f"Found {len(pycs)} .pyc files")
    return pycs

def _unpack_cx_freeze(exe_path: str, out_dir: str) -> list[str]:
    """cx_Freeze bundles a library.zip alongside the EXE."""
    LOG.step("Unpacking cx_Freeze bundle")
    exe_dir = pathlib.Path(exe_path).parent
    lib_zip = exe_dir / "library.zip"
    if not lib_zip.exists():
        LOG.warn("library.zip not found next to EXE")
        return _carve_pyc(exe_path, out_dir)
    import zipfile
    with zipfile.ZipFile(str(lib_zip)) as zf:
        zf.extractall(out_dir)
    pycs = [str(p) for p in pathlib.Path(out_dir).rglob("*.pyc")]
    LOG.ok(f"cx_Freeze: extracted {len(pycs)} .pyc files")
    return pycs

def _unpack_py2exe(exe_path: str, out_dir: str) -> list[str]:
    """py2exe bundles library.zip inside the EXE or next to it."""
    LOG.step("Unpacking py2exe bundle")
    import zipfile
    # Try embedded zip
    data = pathlib.Path(exe_path).read_bytes()
    pk_off = data.rfind(b"PK\x03\x04")
    if pk_off != -1:
        zip_data = data[pk_off:]
        tmp_zip = pathlib.Path(out_dir) / "_embedded.zip"
        tmp_zip.write_bytes(zip_data)
        try:
            with zipfile.ZipFile(str(tmp_zip)) as zf:
                zf.extractall(out_dir)
            pycs = [str(p) for p in pathlib.Path(out_dir).rglob("*.pyc")]
            if pycs:
                LOG.ok(f"py2exe embedded zip: {len(pycs)} .pyc files")
                return pycs
        except Exception: pass
    return _carve_pyc(exe_path, out_dir)

def _unpack_nuitka(exe_path: str, out_dir: str) -> list[str]:
    """Nuitka compiles to C — extract strings + pattern-match Python snippets."""
    LOG.step("Nuitka EXE detected — extracting string table")
    data = pathlib.Path(exe_path).read_bytes()
    strings = re.findall(rb'[\x20-\x7e]{8,}', data)
    py_strings = [s.decode("ascii") for s in strings
                  if any(kw in s for kw in [b"import ", b"def ", b"class ", b"return "])]
    if py_strings:
        out = pathlib.Path(out_dir) / "nuitka_strings.py"
        out.write_text("# [DecompX] Nuitka string extraction — partial reconstruction\n"
                       + "\n".join(f"# {s}" for s in py_strings[:200]))
        LOG.warn("Nuitka: partial string extraction only (compiled to C, not reversible to full source)")
        return [str(out)]
    LOG.error("Nuitka: no Python strings found")
    return []

def _unpack_pyz(pyz_path: str, out_dir: str) -> list[str]:
    """ZipApp .pyz unpacker."""
    LOG.step(f"Unpacking ZipApp: {pathlib.Path(pyz_path).name}")
    import zipfile
    try:
        with zipfile.ZipFile(pyz_path) as zf:
            zf.extractall(out_dir)
        pycs = [str(p) for p in pathlib.Path(out_dir).rglob("*.pyc")]
        pys  = [str(p) for p in pathlib.Path(out_dir).rglob("*.py")]
        LOG.ok(f"ZipApp: {len(pycs)} .pyc + {len(pys)} .py")
        return pycs + pys
    except Exception as e:
        LOG.error(f"ZipApp unpack failed: {e}")
        return []

def _carve_pyc(exe_path: str, out_dir: str) -> list[str]:
    LOG.info("Binary PYC carver active")
    try: data = pathlib.Path(exe_path).read_bytes()
    except Exception as e: LOG.error(f"Cannot read: {e}"); return []
    found = []
    for i in range(len(data)-16):
        if data[i+2:i+4] == b'\x0d\x0a':
            chunk = data[i:]
            p = pathlib.Path(out_dir) / f"carved_{i:08x}.pyc"
            p.write_bytes(chunk[:512*1024])
            found.append(str(p))
    LOG.info(f"Carved {len(found)} chunks")
    return found

def extract_from_exe(exe_path: str, out_dir: str) -> list[str]:
    packer = _detect_exe_packer(exe_path)
    LOG.info(f"EXE packer detected: {packer}")
    if packer == "pyinstaller": return _unpack_pyinstaller(exe_path, out_dir)
    if packer == "cx_freeze":   return _unpack_cx_freeze(exe_path, out_dir)
    if packer == "py2exe":      return _unpack_py2exe(exe_path, out_dir)
    if packer == "nuitka":      return _unpack_nuitka(exe_path, out_dir)
    LOG.warn("Unknown packer — trying PyInstaller then carver")
    r = _unpack_pyinstaller(exe_path, out_dir)
    return r if r else _carve_pyc(exe_path, out_dir)

# ═══════════════════════════════════════════════════════════════
#  STAGE 1 — PYC DECOMPILER CHAIN
# ═══════════════════════════════════════════════════════════════
def _pyc_python_version(pyc_path: str) -> tuple[int,int] | None:
    """Read Python version from PYC magic bytes."""
    MAGIC_MAP = {
        3413:(3,6), 3379:(3,6), 3361:(3,5), 3351:(3,5),
        3394:(3,7), 3411:(3,8), 3413:(3,8),
        3425:(3,9), 3430:(3,9),
        3439:(3,10), 3450:(3,10),
        3495:(3,11), 3550:(3,12), 3600:(3,13), 3650:(3,14),
    }
    try:
        with open(pyc_path,"rb") as f:
            magic = int.from_bytes(f.read(2), "little")
        return MAGIC_MAP.get(magic)
    except: return None

def decompile_pyc(pyc_path: str) -> str:
    name = pathlib.Path(pyc_path).name
    ver  = _pyc_python_version(pyc_path)
    LOG.info(f"Decompile: {name} (Python {'.'.join(map(str,ver)) if ver else '?'})")

    # 1) uncompyle6 — Python ≤3.8
    if ver is None or ver <= (3,8):
        try:
            from uncompyle6.main import decompile as uc6
            out = io.StringIO()
            uc6(None, pyc_path, out, showasm=False, showast=False)
            src = out.getvalue()
            if src.strip(): LOG.ok(f"uncompyle6 OK: {name}"); return src
        except ImportError: pass
        except Exception as e: LOG.warn(f"uncompyle6: {e}")

    # 2) decompyle3 — Python 3.9–3.10
    if ver is None or (3,9) <= ver <= (3,10):
        try:
            from decompyle3.main import decompile as dc3
            out = io.StringIO(); dc3(None, pyc_path, out)
            src = out.getvalue()
            if src.strip(): LOG.ok(f"decompyle3 OK: {name}"); return src
        except ImportError: pass
        except Exception as e: LOG.warn(f"decompyle3: {e}")

    # 3) pycdc — Python 3.11+ (subprocess)
    pycdc_bin = shutil.which("pycdc") or shutil.which("pycdc.exe")
    if pycdc_bin:
        try:
            r = subprocess.run([pycdc_bin, pyc_path],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                LOG.ok(f"pycdc OK: {name}"); return r.stdout
            LOG.warn(f"pycdc: {r.stderr[:100]}")
        except Exception as e: LOG.warn(f"pycdc: {e}")
    else:
        if ver and ver >= (3,11):
            LOG.warn("pycdc not found — install it for Python 3.11+ decompilation")

    # 4) dis fallback
    return _dis_fallback(pyc_path)

def _dis_fallback(pyc_path: str) -> str:
    LOG.warn("dis fallback (bytecode, not source)")
    try:
        with open(pyc_path,"rb") as f:
            f.read(16)
            code = marshal.loads(f.read())
        out = io.StringIO(); dis.dis(code, file=out)
        return f"# [DecompX] dis fallback — install uncompyle6/decompyle3/pycdc for source\n{out.getvalue()}"
    except Exception as e:
        return f"# [DecompX] total decompile failure: {e}\n"

# ═══════════════════════════════════════════════════════════════
#  STAGE 3 — OBFUSCATION DETECTION
# ═══════════════════════════════════════════════════════════════
OBF_PATS = [
    re.compile(r'^[a-zA-Z]{1,3}\d*$'),
    re.compile(r'^_+[a-zA-Z0-9]{1,6}$'),
    re.compile(r'^_0x[0-9a-fA-F]+$'),
    re.compile(r'^[lO0I]{2,}$'),
]
_STDLIB = {
    "os","sys","re","io","ast","dis","abc","csv","gzip","json","math",
    "time","copy","enum","glob","hmac","http","uuid","zlib","base64",
    "struct","shutil","signal","socket","pickle","random","hashlib",
    "logging","pathlib","typing","string","textwrap","itertools",
    "functools","threading","subprocess","collections","contextlib",
    "urllib","email","html","xml","sqlite3","unittest","dataclasses",
    "importlib","traceback","tempfile","platform","argparse","getpass",
    "ctypes","winreg","tkinter","tkinter.ttk","tkinter.messagebox",
}

def _is_obf(name: str) -> bool:
    if name.startswith("__") and name.endswith("__"): return False
    if name in _STDLIB: return False
    return any(p.match(name) for p in OBF_PATS)

def detect_obfuscation(source: str) -> dict:
    tech, score = [], 0
    if re.search(r'exec\s*\(\s*(?:base64\.)?b64decode', source):
        tech.append("exec(base64) wrapper"); score += 35
    if re.search(r'exec\s*\(\s*marshal\.loads', source):
        tech.append("exec(marshal) wrapper"); score += 30
    if re.search(r'exec\s*\(\s*compile\s*\(', source):
        tech.append("exec(compile) wrapper"); score += 25
    # PyArmor bootstrap
    if re.search(r'__armor__|pytransform|pyarmor', source):
        tech.append("PyArmor bootstrap"); score += 40
    hi = scan_entropy_lines(source)
    if hi: tech.append(f"high-entropy lines ({len(hi)})"); score += min(25, len(hi)*5)
    chrs = len(re.findall(r'(?:chr\s*\(\s*\d+\s*\)\s*\+\s*){3,}', source))
    if chrs: tech.append(f"chr() chains ({chrs})"); score += min(20, chrs*4)
    try:
        tree = ast.parse(source)
        names = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.append(node.name)
                names += [a.arg for a in node.args.args]
            elif isinstance(node, ast.ClassDef): names.append(node.name)
            elif isinstance(node, ast.Name): names.append(node.id)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name): names.append(t.id)
        obf_c = sum(1 for n in names if _is_obf(n))
        total = max(len(names),1); ratio = obf_c/total
        if ratio > 0.35:
            tech.append(f"obfuscated identifiers ({obf_c}/{total} = {ratio:.0%})")
            score += min(30, int(ratio*40))
    except SyntaxError:
        tech.append("unparseable syntax"); score += 20
    if re.search(r'while\s+True', source) and len(re.findall(r'elif\s+\w+\s*==', source)) > 5:
        tech.append("control-flow flattening"); score += 20
    junk = len(re.findall(r'^[a-zA-Z]\s*=\s*[a-zA-Z]\s*$', source, re.M))
    if junk > 5: tech.append(f"junk assignments ({junk})"); score += min(15, junk*2)
    # String encrypt helpers
    if re.search(r'def\s+\w{1,4}\s*\(\s*\w{1,3}\s*,\s*\w{1,3}\s*\)\s*:', source):
        if re.search(r'return.*\^|chr.*ord', source):
            tech.append("string encryption helper"); score += 15
    return {"score":min(score,100),"is_obf":score>=25,"techniques":tech,"hi_ent_lines":hi}

# ═══════════════════════════════════════════════════════════════
#  STAGE 4 — CFF SOLVER
# ═══════════════════════════════════════════════════════════════
def solve_cff(source: str) -> tuple[str, bool]:
    """
    Detect and partially solve Control Flow Flattening (state-machine while-True).
    Returns (new_source, was_solved).
    """
    # Pattern: state = N; while True: if state == X: ...; state = Y; elif state == Z: ...
    if not (re.search(r'while\s+True\s*:', source) and
            len(re.findall(r'(?:if|elif)\s+\w+\s*==\s*\d+', source)) > 4):
        return source, False

    LOG.step("CFF detected — attempting to solve state machine")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        LOG.warn("CFF solver: syntax error, skipping")
        return source, False

    class CFFVisitor(ast.NodeVisitor):
        def __init__(self):
            self.state_blocks: dict[int, list] = {}
            self.initial_state: int | None = None
            self.transitions: dict[int, int] = {}

        def visit_Assign(self, node):
            if (isinstance(node.targets[0], ast.Name) and
                    isinstance(node.value, ast.Constant) and
                    isinstance(node.value.value, int)):
                self.initial_state = node.value.value
            self.generic_visit(node)

        def visit_While(self, node):
            if not (isinstance(node.test, ast.Constant) and node.test.value is True):
                self.generic_visit(node); return
            # Extract state→block mapping from if/elif chain
            body = node.body
            if body and isinstance(body[0], ast.If):
                self._parse_if_chain(body[0])
            self.generic_visit(node)

        def _parse_if_chain(self, node):
            if not isinstance(node.test, ast.Compare): return
            left = node.test.left
            if not (isinstance(left, ast.Name) and node.test.ops and
                    isinstance(node.test.ops[0], ast.Eq)): return
            if not (node.test.comparators and
                    isinstance(node.test.comparators[0], ast.Constant)): return
            state_val = node.test.comparators[0].value
            block_stmts = []
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    if (isinstance(stmt.targets[0], ast.Name) and
                            stmt.targets[0].id == left.id and
                            isinstance(stmt.value, ast.Constant)):
                        self.transitions[state_val] = stmt.value.value
                        continue
                block_stmts.append(stmt)
            self.state_blocks[state_val] = block_stmts
            if node.orelse:
                if isinstance(node.orelse[0], ast.If):
                    self._parse_if_chain(node.orelse[0])

    visitor = CFFVisitor()
    visitor.visit(tree)

    if not visitor.state_blocks or visitor.initial_state is None:
        LOG.warn("CFF solver: could not extract state map")
        return source, False

    # Reconstruct execution order via transitions
    order, seen, state = [], set(), visitor.initial_state
    for _ in range(len(visitor.state_blocks) + 1):
        if state in seen or state not in visitor.state_blocks: break
        seen.add(state); order.append(state)
        state = visitor.transitions.get(state, -1)
        if state == -1: break

    if len(order) < 2:
        LOG.warn("CFF solver: insufficient states resolved")
        return source, False

    # Build reconstructed source
    recon_lines = [f"# [DecompX] CFF solved — reconstructed from {len(order)} states\n"]
    try:
        for st in order:
            stmts = visitor.state_blocks[st]
            for stmt in stmts:
                recon_lines.append(ast.unparse(stmt))
        solved_src = "\n".join(recon_lines)
        # Replace the while-True block with reconstructed code
        # Simple approach: prepend reconstruction as comment + linear code
        new_src = solved_src + "\n\n# --- Original (flattened) below ---\n" + source
        LOG.ok(f"CFF solved: {len(order)} states → linear code")
        return new_src, True
    except Exception as e:
        LOG.warn(f"CFF solver: reconstruction failed: {e}")
        return source, False

# ═══════════════════════════════════════════════════════════════
#  STAGE 5 — SEMANTIC RENAMER
# ═══════════════════════════════════════════════════════════════
_CTX = {
    "open":["file_path","input_file","target_file"],
    "socket":["host","remote_addr","target_host"],
    "connect":["connection","conn","socket_conn"],
    "send":["payload","data_out","packet"],
    "recv":["response","data_in","reply"],
    "read":["content","file_data","raw_data"],
    "write":["output","write_data"],
    "decode":["decoded_str","plaintext"],
    "encode":["encoded_str","ciphertext"],
    "split":["parts","tokens","items"],
    "join":["result_str","joined"],
    "append":["collection","entries"],
    "dict":["config","mapping","options"],
    "list":["items","entries","records"],
    "subprocess":["proc","process","cmd_proc"],
    "compile":["pattern","regex_pat"],
    "replace":["modified_str","cleaned_str"],
    "strip":["cleaned","trimmed"],
    "len":["length","size","count"],
    "int":["value","num_val","parsed_int"],
    "str":["text","string_val","label"],
    "bytes":["raw_bytes","byte_data"],
    "range":["count","limit","iterations"],
    "password":["password","secret"],
    "key":["key","api_key","secret_key"],
    "token":["token","auth_token"],
    "url":["url","endpoint","target_url"],
    "ip":["ip_addr","host_ip","remote_ip"],
    "path":["file_path","dir_path"],
    "data":["data","payload","raw_data"],
    "result":["result","output","return_val"],
    "error":["error","err_msg"],
    "cmd":["command","cmd_str","shell_cmd"],
    "msg":["message","log_msg"],
    "buf":["buffer","data_buf"],
    "port":["port","port_num","remote_port"],
    "addr":["address","addr_str","endpoint"],
    "key":["key","enc_key","secret_key"],
    "iv":["iv","init_vector","nonce"],
    "flag":["flag","is_active","enabled"],
    "idx":["index","idx","position"],
    "tmp":["temp_val","temp_data","temp"],
    "req":["request","http_req","req_data"],
    "res":["response","http_res","result"],
    "pld":["payload","pld_data"],
    "enc":["encrypted","encoded_data"],
    "dec":["decrypted","decoded_data"],
}
_GEN_CTR: dict[str,int] = defaultdict(int)

def _fresh(base, used):
    if base not in used: return base
    i = 2
    while f"{base}_{i}" in used: i += 1
    return f"{base}_{i}"

def _infer(old: str, node: ast.AST, lines: list[str], ann_type: str | None) -> str | None:
    # Type annotation wins
    if ann_type:
        ann = ann_type.lower()
        for k, names in _CTX.items():
            if k in ann: return names[0]
    # Assignment call context
    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
        fn = node.value.func
        fname = (fn.id if isinstance(fn, ast.Name) else
                 fn.attr if isinstance(fn, ast.Attribute) else "").lower()
        for k, names in _CTX.items():
            if k in fname: return names[0]
    # Assignment value type
    if isinstance(node, ast.Assign):
        if isinstance(node.value, ast.List): return "items"
        if isinstance(node.value, ast.Dict): return "config"
        if isinstance(node.value, ast.Constant):
            v = node.value.value
            if isinstance(v, str):
                vl = v.lower()
                for k, names in _CTX.items():
                    if k in vl: return names[0]
            if isinstance(v, int) and v > 0: return "count"
    # Line text heuristic
    try:
        ln = getattr(node, "lineno", None)
        if ln and 1 <= ln <= len(lines):
            line = lines[ln-1].lower()
            for k, names in _CTX.items():
                if k in line and k != old.lower(): return names[0]
    except: pass
    return None

class Renamer(ast.NodeTransformer):
    def __init__(self, source: str):
        self.lines  = source.splitlines()
        self.rmap:  dict[str,str] = {}
        self._used: set[str] = set()
        self._assign_nodes: dict[str, ast.AST] = {}
        self._ann_types: dict[str, str] = {}
        self._ctr: dict[str,int] = defaultdict(int)

    def _new_name(self, old: str) -> str:
        if old in self.rmap: return self.rmap[old]
        # category guess
        if old.startswith("_0x"): base = "hex_val"
        elif len(old) == 1:       base = "val"
        elif re.match(r'^[lO0I]+$', old): base = "flag"
        else: base = "var"
        self._ctr[base] += 1
        new = f"{base}_{self._ctr[base]}"
        while new in self._used:
            self._ctr[base] += 1
            new = f"{base}_{self._ctr[base]}"
        self.rmap[old] = new; self._used.add(new); return new

    def _reg(self, old: str, node: ast.AST, ann: str | None = None) -> str:
        if old in self.rmap: return self.rmap[old]
        if not _is_obf(old): return old
        an = self._assign_nodes.get(old)
        inf = _infer(old, an or node, self.lines, ann or self._ann_types.get(old))
        if inf:
            new = _fresh(inf, self._used)
            self.rmap[old] = new; self._used.add(new); return new
        return self._new_name(old)

    def visit_Assign(self, node):
        for t in node.targets:
            if isinstance(t, ast.Name) and _is_obf(t.id):
                self._assign_nodes[t.id] = node
        self.generic_visit(node); return node

    def visit_AnnAssign(self, node):
        """Capture x: int = ... style — type annotation gives us context."""
        if isinstance(node.target, ast.Name):
            try: self._ann_types[node.target.id] = ast.unparse(node.annotation)
            except: pass
            if _is_obf(node.target.id):
                self._assign_nodes[node.target.id] = node
        self.generic_visit(node); return node

    def visit_FunctionDef(self, node):
        if _is_obf(node.name): node.name = self._reg(node.name, node)
        for arg in node.args.args:
            ann = None
            if arg.annotation:
                try: ann = ast.unparse(arg.annotation)
                except: pass
            if _is_obf(arg.arg): arg.arg = self._reg(arg.arg, node, ann)
        self.generic_visit(node); return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        if _is_obf(node.name): node.name = self._reg(node.name, node)
        self.generic_visit(node); return node

    def visit_Name(self, node):
        if _is_obf(node.id): node.id = self._reg(node.id, node)
        return node

def rename_obfuscated(source: str) -> tuple[str, dict[str,str]]:
    LOG.step("Semantic rename pass")
    try:
        tree = ast.parse(source)
        r = Renamer(source)
        # Pass 1: collect
        r.visit(tree)
        # Pass 2: transform fresh tree
        tree2 = ast.parse(source)
        r2 = Renamer(source)
        r2.rmap = r.rmap; r2._used = r._used
        r2._assign_nodes = r._assign_nodes
        r2._ann_types = r._ann_types
        r2._ctr = r._ctr
        new_tree = r2.visit(tree2)
        try:
            new_src = ast.unparse(new_tree)
            LOG.ok(f"Renamed {len(r2.rmap)} identifiers (AST)")
            return new_src, r2.rmap
        except:
            new_src = source
            for old, new in sorted(r.rmap.items(), key=lambda x:-len(x[0])):
                new_src = re.sub(r'\b'+re.escape(old)+r'\b', new, new_src)
            LOG.ok(f"Renamed {len(r.rmap)} identifiers (regex fallback)")
            return new_src, r.rmap
    except SyntaxError:
        # Full regex fallback
        rmap: dict[str,str] = {}; used: set[str] = set(); ctr: dict[str,int] = defaultdict(int)
        def mk(base):
            ctr[base] += 1; n = f"{base}_{ctr[base]}"
            while n in used: ctr[base]+=1; n=f"{base}_{ctr[base]}"
            used.add(n); return n
        for cand in dict.fromkeys(re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{0,10})\b', source)):
            if _is_obf(cand) and cand not in rmap:
                rmap[cand] = mk("var")
        new_src = source
        for old, new in sorted(rmap.items(), key=lambda x:-len(x[0])):
            new_src = re.sub(r'\b'+re.escape(old)+r'\b', new, new_src)
        LOG.ok(f"Renamed {len(rmap)} identifiers (full regex)")
        return new_src, rmap

# ═══════════════════════════════════════════════════════════════
#  STAGE 6 — STATIC ANALYSIS
# ═══════════════════════════════════════════════════════════════
# IOC stdlib whitelist — don't match these as domains/IPs
_STDLIB_MODULES = {
    "os.path","re.compile","sys.argv","os.getcwd","os.listdir",
    "True.lower","False.upper","None.split","str.format",
    "int.from_bytes","bytes.decode","list.append","dict.update",
    "set.add","tuple.index","type.mro",
}

SUSPICIOUS_PATS = [
    (r'subprocess\.(call|Popen|run)',          "Shell execution"),
    (r'os\.(system|popen|execv|execl)',        "OS command execution"),
    (r'\beval\s*\(',                           "Dynamic eval()"),
    (r'\bexec\s*\(',                           "Dynamic exec()"),
    (r'\bcompile\s*\(',                        "Dynamic compile()"),
    (r'__import__\s*\(',                       "Dynamic __import__()"),
    (r'\bctypes\b',                            "ctypes usage"),
    (r'socket\.(connect|bind|listen)',         "Raw socket"),
    (r'urllib\.request\.urlopen',              "urllib HTTP"),
    (r'requests\.(post|get|put|delete|patch)', "requests HTTP"),
    (r'base64\.b64decode',                     "Base64 decode"),
    (r'marshal\.loads',                        "marshal deserialization"),
    (r'pickle\.loads',                         "pickle deserialization"),
    (r'shutil\.rmtree|os\.(remove|unlink)',    "File deletion"),
    (r'winreg|OpenKey|QueryValueEx',           "Registry access"),
    (r'CreateRemoteThread|VirtualAlloc',       "Memory injection"),
    (r'DeleteFile|FormatDisk|diskpart',        "Destructive Win32"),
    (r'ftplib\.|smtplib\.',                    "FTP/SMTP exfil"),
    (r'paramiko\.',                            "SSH (paramiko)"),
    (r'pynput\.|keyboard\.on_press',           "Keylogger"),
    (r'cv2\.VideoCapture|PIL\.ImageGrab',      "Screen/cam capture"),
    (r'cryptography\.|Crypto\.',               "Encryption library"),
]

def build_call_graph(source: str) -> dict[str, list[str]]:
    """Build {caller: [callee, ...]} from AST."""
    graph: dict[str, list[str]] = defaultdict(list)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return graph
    class CGVisitor(ast.NodeVisitor):
        def __init__(self): self.current_fn = "<module>"
        def visit_FunctionDef(self, node):
            prev = self.current_fn
            self.current_fn = node.name
            graph.setdefault(node.name, [])
            self.generic_visit(node)
            self.current_fn = prev
        visit_AsyncFunctionDef = visit_FunctionDef
        def visit_Call(self, node):
            fn = ""
            if isinstance(node.func, ast.Name): fn = node.func.id
            elif isinstance(node.func, ast.Attribute): fn = node.func.attr
            if fn: graph[self.current_fn].append(fn)
            self.generic_visit(node)
    CGVisitor().visit(tree)
    return dict(graph)

def render_call_graph(graph: dict[str, list[str]], max_depth: int = 4) -> str:
    """Render call graph as ASCII tree."""
    if not graph: return "— no call graph —"
    lines = []
    def walk(fn, prefix="", depth=0, seen=None):
        if seen is None: seen = set()
        if depth > max_depth: return
        callees = graph.get(fn, [])
        unique = [c for c in dict.fromkeys(callees) if c in graph]
        for i, callee in enumerate(unique):
            is_last = (i == len(unique)-1)
            branch = "└── " if is_last else "├── "
            recur  = "    " if is_last else "│   "
            lines.append(f"{prefix}{branch}{callee}")
            if callee not in seen:
                walk(callee, prefix+recur, depth+1, seen | {callee})
    roots = [fn for fn in graph if fn != "<module>"][:12]
    for root in roots:
        lines.append(f"▸ {root}()")
        walk(root, "  ")
        lines.append("")
    return "\n".join(lines)

def track_data_flow(source: str) -> list[dict]:
    """
    Basic taint analysis: find variables assigned from sensitive sources
    (password, key, socket, response) that flow into sinks (send, write, exec, upload).
    Returns list of {source, sink, var, line}.
    """
    SOURCES = re.compile(
        r'\b(getpass|input|recv|read|b64decode|decrypt|open|urlopen|get|post)\s*\(', re.I)
    SINKS   = re.compile(
        r'\b(send|write|exec|system|popen|post|put|upload|connect|ftp|smtp)\s*\(', re.I)
    findings = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings
    # Collect taint sources: variable = <source_call>(...)
    tainted: dict[str, str] = {}   # var_name → source_fn
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = node.value.func
            fname = (fn.id if isinstance(fn, ast.Name) else
                     fn.attr if isinstance(fn, ast.Attribute) else "")
            if SOURCES.match(fname + "("):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        tainted[t.id] = fname
    # Check sinks for use of tainted variables
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            fname = (fn.id if isinstance(fn, ast.Name) else
                     fn.attr if isinstance(fn, ast.Attribute) else "")
            if SINKS.match(fname + "("):
                for arg in ast.walk(node):
                    if isinstance(arg, ast.Name) and arg.id in tainted:
                        findings.append({
                            "var":   arg.id,
                            "source": tainted[arg.id],
                            "sink":   fname,
                            "line":   getattr(node, "lineno", "?"),
                        })
    # Deduplicate
    seen = set()
    out  = []
    for f in findings:
        key = (f["var"], f["source"], f["sink"])
        if key not in seen:
            seen.add(key); out.append(f)
    return out

def parse_source(source: str) -> dict:
    res = {
        "imports":[], "functions":[], "classes":[], "strings":[],
        "suspicious":[], "iocs":{"urls":[],"ips":[],"emails":[],"domains":[],"registry_keys":[]},
        "ast_ok":False, "line_count":source.count("\n")+1, "char_count":len(source),
    }
    # IOC — with stdlib false-positive filter
    raw_urls     = re.findall(r'https?://[^\s\'"<>]{4,}', source)
    raw_ips      = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', source)
    raw_emails   = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', source)
    raw_domains  = re.findall(r'\b(?:[a-zA-Z0-9\-]+\.){1,4}(?:com|net|org|io|ru|cn|tk|xyz|top|onion)\b', source)
    raw_reg      = re.findall(r'HKEY_[A-Z_]+\\[^\s\'"]{4,}', source)
    # Filter stdlib names from domains
    def _clean_domains(ds):
        return [d for d in dict.fromkeys(ds)
                if not any(d.startswith(s.split(".")[0]) for s in _STDLIB_MODULES)
                and not re.match(r'^\d', d)]
    res["iocs"]["urls"]          = list(dict.fromkeys(raw_urls))
    res["iocs"]["ips"]           = [ip for ip in dict.fromkeys(raw_ips)
                                    if not ip.startswith("127.") and ip != "0.0.0.0"]
    res["iocs"]["emails"]        = list(dict.fromkeys(raw_emails))
    res["iocs"]["domains"]       = _clean_domains(raw_domains)
    res["iocs"]["registry_keys"] = list(dict.fromkeys(raw_reg))
    # Suspicious patterns
    for pat, label in SUSPICIOUS_PATS:
        ms = re.findall(pat, source)
        if ms: res["suspicious"].append({"pattern":label,"count":len(ms)})
    # AST
    try:
        tree = ast.parse(source); res["ast_ok"] = True
        seen_imp = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name not in seen_imp:
                        res["imports"].append(a.name); seen_imp.add(a.name)
            elif isinstance(node, ast.ImportFrom):
                m = node.module or ""
                if m not in seen_imp: res["imports"].append(m); seen_imp.add(m)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                try: ret = ast.unparse(node.returns) if node.returns else None
                except: ret = None
                res["functions"].append({
                    "name": node.name, "line": node.lineno,
                    "args": [a.arg for a in node.args.args],
                    "decorators": [ast.unparse(d) for d in node.decorator_list] if node.decorator_list else [],
                    "returns": ret,
                })
            elif isinstance(node, ast.ClassDef):
                try: bases = [ast.unparse(b) for b in node.bases]
                except: bases = []
                res["classes"].append({"name":node.name,"line":node.lineno,"bases":bases})
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if 8 < len(s) < 400 and s not in res["strings"]: res["strings"].append(s)
        res["strings"] = res["strings"][:50]
    except SyntaxError:
        res["imports"]   = list(dict.fromkeys(re.findall(r'^(?:import|from)\s+([\w.]+)', source, re.M)))
        res["functions"] = [{"name":m,"line":"?","args":[],"decorators":[],"returns":None}
                            for m in re.findall(r'^def\s+(\w+)\s*\(', source, re.M)]
    return res

def clean_source(source: str) -> str:
    lines = source.splitlines()
    imps, rest, seen = [], [], set()
    for line in lines:
        s = line.rstrip()
        if re.match(r'^(import|from)\s+', s):
            if s not in seen: imps.append(s); seen.add(s)
        else: rest.append(s)
    imps.sort()
    out, blanks = [], 0
    for line in imps + [""] + rest:
        if line == "":
            blanks += 1
            if blanks <= 2: out.append("")
        else:
            blanks = 0; out.append(line)
    return "\n".join(out)

# ═══════════════════════════════════════════════════════════════
#  STAGE 7 — REPORTS
# ═══════════════════════════════════════════════════════════════
def _esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def _badge(t, c="#7b68ee"):
    return f'<span style="background:{c};color:#fff;padding:1px 7px;border-radius:3px;font:bold 10px Consolas">{_esc(t)}</span>'
def _tbl(headers, rows, empty="— none —"):
    if not rows: return f'<p class="dim">{empty}</p>'
    ths = "".join(f"<th>{h}</th>" for h in headers)
    trs = "".join("<tr>"+"".join(f"<td>{c}</td>" for c in r)+"</tr>" for r in rows)
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"
def _sec(title, content, full=False):
    return f'<div class="{"section full" if full else "section"}"><div class="st">{title}</div>{content}</div>'

def build_json(file_path,source,parsed,obf,layers,b64f,rename_map,call_graph,data_flow) -> dict:
    return {
        "decompx_version":"3.0.0","plugin_class":"V0RTEX-Made",
        "timestamp":datetime.now().isoformat(),"input_file":file_path,
        "sha256":hashlib.sha256(source.encode()).hexdigest(),
        "line_count":parsed["line_count"],"char_count":parsed["char_count"],
        "ast_parsed":parsed["ast_ok"],"decode_layers":layers,
        "obfuscation":{"score":obf["score"],"is_obf":obf["is_obf"],"techniques":obf["techniques"]},
        "rename_map":rename_map,"imports":parsed["imports"],
        "functions":parsed["functions"],"classes":parsed["classes"],
        "suspicious_patterns":parsed["suspicious"],"iocs":parsed["iocs"],
        "embedded_strings":b64f,"high_entropy_lines":obf.get("hi_ent_lines",[]),
        "call_graph":call_graph,"data_flow_findings":data_flow,
    }

def build_md(file_path,source,parsed,obf,layers,rename_map,call_graph_txt,data_flow) -> str:
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stem = pathlib.Path(file_path).name
    sha  = hashlib.sha256(source.encode()).hexdigest()
    L = [
        f"# DecompX Report — `{stem}`",
        f"> **DecompX v3.0** (V0RTEX-Made) · {now}",
        "","---","",
        "## Overview","",
        "|Field|Value|","|-----|-----|",
        f"|File|`{stem}`|",f"|SHA-256|`{sha}`|",
        f"|Lines|{parsed['line_count']}|",f"|Functions|{len(parsed['functions'])}|",
        f"|Classes|{len(parsed['classes'])}|",f"|Imports|{len(parsed['imports'])}|",
        f"|AST|{'✅ OK' if parsed['ast_ok'] else '⚠ Failed'}|",
        f"|Decode layers|{' → '.join(layers) if layers else 'none'}|",
        f"|Obfuscation score|**{obf['score']}/100**|","",
    ]
    if obf["techniques"]:
        L += ["## Obfuscation Techniques",""]
        for t in obf["techniques"]: L.append(f"- {t}")
        L.append("")
    if rename_map:
        L += ["## Rename Map","","| Original | → Renamed |","|----------|----------|"]
        for o,n in sorted(rename_map.items()): L.append(f"|`{o}`|`{n}`|")
        L.append("")
    if data_flow:
        L += ["## Data Flow (Taint)","","| Variable | Source | Sink | Line |",
              "|----------|--------|------|------|"]
        for f in data_flow: L.append(f"|`{f['var']}`|`{f['source']}`|`{f['sink']}`|{f['line']}|")
        L.append("")
    if call_graph_txt.strip():
        L += ["## Call Graph","","```",call_graph_txt,"```",""]
    if parsed["suspicious"]:
        L += ["## Suspicious Patterns",""]
        for s in parsed["suspicious"]: L.append(f"- **{s['pattern']}** ×{s['count']}")
        L.append("")
    ioc = parsed["iocs"]
    if any(ioc.values()):
        L += ["## IOC",""]
        for lbl, key in [("URLs","urls"),("IPs","ips"),("Emails","emails"),
                          ("Domains","domains"),("Registry Keys","registry_keys")]:
            items = ioc.get(key,[])
            if items:
                L.append(f"### {lbl}")
                for i in items: L.append(f"- `{i}`")
                L.append("")
    L += ["## Decompiled Source","","```python",source,"```",""]
    return "\n".join(L)

def build_html(file_path,source,parsed,obf,layers,b64f,rename_map,call_graph_txt,data_flow) -> str:
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stem = pathlib.Path(file_path).name
    sha  = hashlib.sha256(source.encode()).hexdigest()
    oc   = TH["danger"] if obf["score"]>50 else TH["warn"] if obf["score"]>20 else TH["ok"]
    layers_html = " → ".join(_badge(l,TH["accent"]) for l in layers) if layers else '<span class="dim">none</span>'
    obf_html = "".join(f'<div class="item">{_badge(t,oc)}</div>' for t in obf["techniques"]) or '<p class="dim">none</p>'
    susp_html = "".join(f'<div class="item">{_badge(s["pattern"],TH["danger"])} <span class="dim">×{s["count"]}</span></div>' for s in parsed["suspicious"]) or '<p class="dim">none</p>'
    ioc_html = ""
    for lbl,key in [("URLs","urls"),("IPs","ips"),("Emails","emails"),("Domains","domains"),("Registry Keys","registry_keys")]:
        items = parsed["iocs"].get(key,[])
        ioc_html += f'<h4 style="color:{TH["accent2"]};margin:8px 0 3px">{lbl} ({len(items)})</h4>'
        ioc_html += _tbl([lbl],[[f'<code>{_esc(v)}</code>'] for v in items])
    ren_html = _tbl(["Original","Renamed"],
        [[f'<code style="color:{TH["danger"]}">{_esc(o)}</code>',
          f'<code style="color:{TH["ok"]}">{_esc(n)}</code>'] for o,n in sorted(rename_map.items())]
    ) if rename_map else '<p class="dim">No renaming (not obfuscated)</p>'
    df_html = _tbl(["Variable","Source","Sink","Line"],
        [[f'<code>{_esc(f["var"])}</code>',f'<code>{_esc(f["source"])}</code>',
          f'<code>{_esc(f["sink"])}</code>',str(f["line"])] for f in data_flow]
    )
    cg_html = f'<pre style="font:11px Consolas;color:{TH["fg"]};line-height:1.6;background:{TH["src_bg"]};padding:12px;border-radius:6px;overflow:auto">{_esc(call_graph_txt)}</pre>'
    func_rows = [[f'<code>{_esc(f["name"])}</code>',str(f["line"]),
                  f'<code>{_esc(", ".join(f.get("args",[])))}</code>',
                  f'<code style="color:{TH["accent2"]}">{_esc(f.get("returns",""))}</code>',
                  " ".join(_badge(d,TH["fg_dim"]) for d in f.get("decorators",[]))]
                 for f in parsed["functions"]]
    b64_rows = [[f'<code class="dim">{_esc(b["type"])}</code>',
                 f'<code>{_esc(b["encoded"][:50])}</code>',
                 f'<code style="color:{TH["ok"]}">{_esc(b["decoded"][:80])}</code>'] for b in b64f]
    hi_rows  = [[str(e["line"]),str(e["entropy"]),f'<code class="dim">{_esc(e["preview"])}</code>'] for e in obf.get("hi_ent_lines",[])]
    src_esc = _esc(source)
    src_esc = re.sub(r'\b(def|class|import|from|return|if|else|elif|for|while|try|except|finally|with|as|pass|break|continue|lambda|and|or|not|in|is|None|True|False|yield|async|await|raise|global|nonlocal|del|assert)\b', r'<span class="kw">\1</span>', src_esc)
    src_esc = re.sub(r'(#[^\n]*)', r'<span class="cm">\1</span>', src_esc)
    src_esc = re.sub(r'(\b\d+\.?\d*\b)', r'<span class="num">\1</span>', src_esc)
    obf_bar = int(obf["score"]*2)
    imports_chips = "".join(f'<code class="chip">{_esc(i)}</code>' for i in parsed["imports"]) or '<span class="dim">—</span>'
    CSS = f"""
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:{TH["bg"]};color:{TH["fg"]};font-family:"Segoe UI",system-ui,sans-serif;font-size:13px;line-height:1.6}}
header{{background:{TH["panel"]};border-bottom:2px solid {TH["accent"]};padding:16px 28px;display:flex;align-items:center;gap:14px}}
header h1{{font-family:Consolas,monospace;font-size:22px;color:{TH["accent"]};letter-spacing:3px}}
.meta{{margin-left:auto;text-align:right;color:{TH["fg_dim"]};font-size:11px}}
.container{{max-width:1240px;margin:0 auto;padding:20px}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}}
.grid3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px}}
.section{{background:{TH["card"]};border:1px solid {TH["border"]};border-radius:8px;padding:14px 16px;margin-bottom:12px}}
.full{{grid-column:1/-1}}
.st{{font-family:Consolas,monospace;font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:{TH["accent"]};margin-bottom:9px;padding-bottom:6px;border-bottom:1px solid {TH["border"]}}}
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{background:{TH["border"]};color:{TH["fg_dim"]};padding:5px 9px;text-align:left;font-weight:600}}
td{{padding:4px 9px;border-bottom:1px solid {TH["border"]}22;font-family:Consolas,monospace;word-break:break-all}}
tr:hover td{{background:{TH["border"]}44}}
code{{font-family:Consolas,monospace;font-size:11px;color:{TH["accent2"]}}}
.chip{{display:inline-block;background:{TH["border"]};border-radius:3px;padding:1px 6px;margin:2px;font-family:Consolas;font-size:10px;color:{TH["fg"]}}}
.dim{{color:{TH["fg_dim"]};font-size:11px}}
.item{{margin:2px 0}}
.sv{{font-family:Consolas,monospace;font-size:28px;font-weight:bold;color:{TH["accent"]}}}
.sl{{color:{TH["fg_dim"]};font-size:10px;margin-top:1px}}
.sha{{font-family:Consolas,monospace;font-size:9px;color:{TH["fg_dim"]};word-break:break-all;margin-top:3px}}
pre.src{{background:{TH["src_bg"]};border:1px solid {TH["border"]};border-radius:6px;padding:14px;overflow:auto;font-family:Consolas,monospace;font-size:11px;line-height:1.75;max-height:700px;color:{TH["fg"]}}}
.kw{{color:#c792ea;font-weight:bold}}.cm{{color:#546e7a;font-style:italic}}.num{{color:#f78c6c}}
.obfb{{background:{TH["border"]};border-radius:3px;height:5px;margin-top:7px;overflow:hidden}}
.obff{{height:5px;border-radius:3px;background:{oc};width:{obf_bar}px;max-width:200px}}
h4{{font-size:11px;font-weight:600}}
"""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>DecompX 3.0 — {_esc(stem)}</title><style>{CSS}</style></head><body>
<header>
  <div><h1>DECOMPX</h1><div style="color:{TH['fg_dim']};font-size:10px;margin-top:1px">V0RTEX-Made · v3.0 · Full-Stack Decompiler</div></div>
  <div class="meta"><div style="font-size:13px;color:{TH['fg']}">{_esc(stem)}</div><div>{now}</div><div class="sha">{sha}</div></div>
</header>
<div class="container">
<div class="grid3">
  <div class="section">
    <div class="st">File Stats</div>
    <div style="display:flex;gap:18px;flex-wrap:wrap">
      <div><div class="sv">{parsed['line_count']}</div><div class="sl">lines</div></div>
      <div><div class="sv">{len(parsed['functions'])}</div><div class="sl">functions</div></div>
      <div><div class="sv">{len(parsed['classes'])}</div><div class="sl">classes</div></div>
      <div><div class="sv">{len(parsed['imports'])}</div><div class="sl">imports</div></div>
    </div>
    <div style="margin-top:10px"><span class="dim">Layers: </span>{layers_html}</div>
  </div>
  <div class="section">
    <div class="st">Obfuscation</div>
    <div style="font:bold 34px Consolas;color:{oc}">{obf['score']}<span style="font-size:14px;color:{TH['fg_dim']}"> / 100</span></div>
    <div class="obfb"><div class="obff"></div></div>
    <div style="margin-top:8px">{obf_html}</div>
  </div>
  <div class="section">
    <div class="st">Threat Signals</div>
    <div><span class="sv" style="color:{'#e05c5c' if parsed['suspicious'] else '#4cca82'}">{len(parsed['suspicious'])}</span><span class="dim"> patterns</span></div>
    <div style="margin-top:8px">{susp_html}</div>
  </div>
</div>
{_sec("Rename Map", ren_html, full=True) if rename_map else ""}
{_sec("Data Flow — Taint Analysis", df_html, full=True) if data_flow else ""}
<div class="grid">
  {_sec("Imports", imports_chips)}
  {_sec("Functions", _tbl(["Name","Line","Args","Returns","Decorators"], func_rows))}
</div>
{_sec("Call Graph", cg_html, full=True)}
{_sec("IOC", ioc_html, full=True)}
{_sec("Embedded Encoded Strings", _tbl(["Type","Encoded","Decoded"], b64_rows), full=True)}
{_sec("High-Entropy Lines", _tbl(["Line","Entropy","Preview"], hi_rows), full=True) if hi_rows else ""}
{_sec("Decompiled Source" + (" · Renamed" if rename_map else ""), f'<pre class="src">{src_esc}</pre>', full=True)}
</div></body></html>"""

# ═══════════════════════════════════════════════════════════════
#  STAGE 8 — V0RTEX API INTEGRATION
# ═══════════════════════════════════════════════════════════════
def _vx_safe(fn, *args, **kwargs):
    """Call a vx.* API function safely — silently skip if unavailable."""
    try: return fn(*args, **kwargs)
    except Exception: return None

def vx_push_iocs(parsed: dict, file_path: str):
    """Push extracted IOCs to the V0RTEX threat engine."""
    iocs = parsed.get("iocs", {})
    all_iocs = (iocs.get("urls",[]) + iocs.get("ips",[]) +
                iocs.get("domains",[]) + iocs.get("emails",[]))
    if not all_iocs: return
    _vx_safe(vx.scan.submit_iocs, all_iocs, source=f"DecompX:{pathlib.Path(file_path).name}")
    LOG.info(f"Pushed {len(all_iocs)} IOCs to V0RTEX threat engine")

def vx_tag_file(file_path: str, obf: dict, layers: list, packer: str):
    """Tag the file in the V0RTEX dashboard with analysis metadata."""
    tags = []
    if obf["is_obf"]:    tags.append("obfuscated")
    if "pyinstaller" in packer: tags.append("pyinstaller")
    if "nuitka" in packer:      tags.append("nuitka")
    if "base64" in layers:      tags.append("b64-wrapped")
    if "zlib" in layers:        tags.append("zlib-wrapped")
    if "marshal" in layers:     tags.append("marshal-wrapped")
    for t in obf.get("techniques", []):
        if "PyArmor" in t: tags.append("pyarmor")
        if "exec(" in t:   tags.append("exec-wrapper")
    if tags:
        _vx_safe(vx.scan.tag_file, file_path, tags=tags)
        LOG.info(f"Tagged in V0RTEX: {', '.join(tags)}")

def vx_cache_result(sha256: str, result_json: dict):
    """Store analysis result in V0RTEX DB for caching / diff."""
    _vx_safe(vx.db.store, f"decompx:{sha256}", json.dumps(result_json))

def vx_get_cached(sha256: str) -> dict | None:
    """Retrieve previous analysis from V0RTEX DB."""
    try:
        raw = vx.db.query(f"decompx:{sha256}")
        return json.loads(raw) if raw else None
    except Exception:
        return None

def vx_resolve_iocs(parsed: dict) -> dict[str, dict]:
    """Ask V0RTEX to resolve IP/domain reputation."""
    reputation: dict[str, dict] = {}
    targets = parsed["iocs"].get("ips",[]) + parsed["iocs"].get("domains",[])
    for target in targets[:20]:   # cap at 20 to avoid hammering API
        try:
            rep = vx.net.resolve(target)
            if rep: reputation[target] = rep
        except Exception: pass
    if reputation: LOG.info(f"Resolved {len(reputation)} IPs/domains via V0RTEX")
    return reputation

def vx_emit_event(result_json: dict):
    """Emit decompx.analysis_complete so other plugins can react."""
    _vx_safe(vx.event.emit, "decompx.analysis_complete", result_json)

def vx_register_scan_hook():
    """Register a hook so DecompX auto-triggers when V0RTEX scans an EXE/PY/PYC."""
    def _hook(scan_result: dict):
        file_path = scan_result.get("file_path","")
        ext = pathlib.Path(file_path).suffix.lower()
        if ext in (".exe",".py",".pyc",".pyw",".pyz"):
            LOG.info(f"V0RTEX scan hook triggered: {pathlib.Path(file_path).name}")
            _vx_safe(vx.ui.notify,
                     f"DecompX: auto-decompile {pathlib.Path(file_path).name}?",
                     level="info", action="decompx_run", action_data=file_path)
    _vx_safe(vx.scan.hook, _hook)

# ═══════════════════════════════════════════════════════════════
#  FULL PIPELINE
# ═══════════════════════════════════════════════════════════════
def run_pipeline(file_path: str, progress_fn, done_fn, error_fn):
    try:
        LOG.step(f"DecompX v3.0 — {pathlib.Path(file_path).name}")
        _vx_safe(vx.ui.notify, f"DecompX: analysing {pathlib.Path(file_path).name}…", level="info")
        progress_fn(3)
        ext    = pathlib.Path(file_path).suffix.lower()
        source = ""; layers = []; packer = "none"
        tmp    = tempfile.mkdtemp(prefix="decompx_")

        try:
            # S1: Extract / decode source
            LOG.step("Stage 1 — Source extraction")
            sha_input = hashlib.sha256(pathlib.Path(file_path).read_bytes()).hexdigest()

            # Check cache first
            cached = vx_get_cached(sha_input)
            if cached:
                LOG.ok("Cache hit — loading previous analysis")
                done_fn(cached.get("source",""), cached, {}, [], [], {}, True)
                progress_fn(100)
                return

            if ext == ".exe":
                packer = _detect_exe_packer(file_path)
                files  = extract_from_exe(file_path, tmp)
                pycs   = [f for f in files if f.endswith(".pyc")]
                pys    = [f for f in files if f.endswith(".py")]
                progress_fn(18)
                parts  = []
                for pyc in pycs:
                    s = decompile_pyc(pyc)
                    if s: parts.append(f"# ── {pathlib.Path(pyc).name} ──\n{s}")
                for py in pys:
                    try: parts.append(pathlib.Path(py).read_text(errors="replace"))
                    except: pass
                source = "\n\n".join(parts) if parts else ""
                if not source.strip():
                    raw = pathlib.Path(file_path).read_bytes()
                    source_b, layers = decode_layers(raw)
                    source = source_b.decode("utf-8", errors="replace")
            elif ext == ".pyz":
                files  = _unpack_pyz(file_path, tmp)
                pycs   = [f for f in files if f.endswith(".pyc")]
                pys    = [f for f in files if f.endswith(".py")]
                progress_fn(18)
                parts  = []
                for pyc in pycs:
                    s = decompile_pyc(pyc)
                    if s: parts.append(s)
                for py in pys:
                    try: parts.append(pathlib.Path(py).read_text(errors="replace"))
                    except: pass
                source = "\n\n".join(parts)
            elif ext == ".pyc":
                source = decompile_pyc(file_path)
                progress_fn(18)
            else:
                raw    = vx.fs.read_external(file_path)
                src_b, layers = decode_layers(raw)
                src_s = src_b.decode("utf-8", errors="replace")
                src_s, exec_layers = _unwrap_exec(src_s)
                layers.extend(exec_layers)
                source = src_s
                progress_fn(18)

            if not source.strip():
                raise ValueError("No source extracted — file may be encrypted or unsupported")

            LOG.ok(f"Source: {len(source)} chars, {source.count(chr(10))} lines")

            # S2: Decode inline
            LOG.step("Stage 2 — Inline decode")
            b64f = extract_inline_encoded(source)
            if b64f: LOG.info(f"Found {len(b64f)} embedded encoded string(s)")
            # XOR brute-force on high-entropy blobs
            for blob_m in re.finditer(rb'(?:[\x00-\x08\x0e-\x1f\x80-\xff]){20,}',
                                       source.encode("utf-8","replace")):
                dec = _try_xor_bruteforce(blob_m.group(0))
                if dec:
                    try:
                        text = dec.decode("utf-8", errors="replace")
                        b64f.append({"type":"xor-brute","offset":blob_m.start(),
                                     "encoded":repr(blob_m.group(0)[:20]),"decoded":text[:200]})
                        LOG.info(f"  XOR blob decoded at offset {blob_m.start()}")
                    except: pass
            progress_fn(32)

            # S3: Obfuscation
            LOG.step("Stage 3 — Obfuscation analysis")
            obf = detect_obfuscation(source)
            LOG.info(f"Score: {obf['score']}/100 — {', '.join(obf['techniques']) or 'clean'}")
            progress_fn(44)

            # S4: CFF solver
            LOG.step("Stage 4 — CFF solver")
            source, cff_solved = solve_cff(source)
            if cff_solved: LOG.ok("CFF resolved")
            progress_fn(52)

            # S5: Semantic rename
            rename_map = {}
            if obf["is_obf"]:
                LOG.step("Stage 5 — Semantic rename")
                source, rename_map = rename_obfuscated(source)
                LOG.ok(f"Renamed {len(rename_map)} identifiers")
            else:
                LOG.info("Stage 5 — Skipped (not obfuscated)")
            progress_fn(62)

            # S6: Analysis
            LOG.step("Stage 6 — Static analysis")
            parsed     = parse_source(source)
            source     = clean_source(source)
            cg_raw     = build_call_graph(source)
            cg_txt     = render_call_graph(cg_raw)
            data_flow  = track_data_flow(source)
            LOG.info(f"Functions: {len(parsed['functions'])}, IOC: {sum(len(v) for v in parsed['iocs'].values())}, Data flow: {len(data_flow)}")
            progress_fn(74)

            # S7: Reports
            LOG.step("Stage 7 — Reports")
            stem = pathlib.Path(file_path).stem
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"decompx_{stem}_{ts}"
            j    = build_json(file_path, source, parsed, obf, layers, b64f, rename_map, cg_raw, data_flow)
            h    = build_html(file_path, source, parsed, obf, layers, b64f, rename_map, cg_txt, data_flow)
            vx.fs.write_file(f"{name}.json", json.dumps(j, indent=2), "json"); LOG.ok("JSON saved")
            vx.fs.write_file(f"{name}.html", h, "html");                        LOG.ok("HTML saved")
            if obf["is_obf"] or data_flow:
                m = build_md(file_path, source, parsed, obf, layers, rename_map, cg_txt, data_flow)
                vx.fs.write_file(f"{name}.md", m, "md");                        LOG.ok("MD saved")
            progress_fn(86)

            # S8: V0RTEX API
            LOG.step("Stage 8 — V0RTEX API integration")
            vx_push_iocs(parsed, file_path)
            vx_tag_file(file_path, obf, layers, packer)
            vx_cache_result(sha_input, {**j, "source": source})
            reputation = vx_resolve_iocs(parsed)
            vx_emit_event(j)
            LOG.ok("V0RTEX API calls done")
            progress_fn(100)
            LOG.ok("✔ DecompX v3.0 complete")
            done_fn(source, parsed, obf, layers, b64f, rename_map, False,
                    cg_txt, data_flow, reputation)

        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    except Exception as e:
        LOG.error(f"Pipeline error: {e}", traceback.format_exc())
        error_fn(str(e))

# ═══════════════════════════════════════════════════════════════
#  UI
# ═══════════════════════════════════════════════════════════════
HISTORY_KEY = "decompx:file_history"

class DecompXUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DecompX v3.0 — V0RTEX-Made")
        self.root.geometry("1300x860"); self.root.minsize(950,620)
        self.root.configure(bg=TH["bg"])
        self._source = ""; self._rename_map = {}
        self._history: list[str] = self._load_history()
        self._search_idx = "1.0"
        self._build_styles(); self._build_ui()
        LOG.add_cb(self._on_log)

    def _build_styles(self):
        s = ttk.Style(); s.theme_use("default")
        s.configure("TNotebook",     background=TH["bg"],    borderwidth=0)
        s.configure("TNotebook.Tab", background=TH["card"],  foreground=TH["fg_dim"],
                    font=TH["font_sm"], padding=[10,4])
        s.map("TNotebook.Tab", background=[("selected",TH["panel"])],
              foreground=[("selected",TH["accent"])])
        s.configure("Horizontal.TProgressbar",
                    troughcolor=TH["border"], background=TH["accent"], thickness=5, borderwidth=0)

    def _build_ui(self):
        r = self.root
        # Header
        hdr = tk.Frame(r, bg=TH["panel"], height=54); hdr.pack(fill="x"); hdr.pack_propagate(False)
        tk.Label(hdr, text="DECOMPX", bg=TH["panel"], fg=TH["accent"],
                 font=("Consolas",18,"bold"), padx=16).pack(side="left")
        tk.Label(hdr, text="v3.0  ·  V0RTEX-Made  ·  Full-Stack Script Decompiler",
                 bg=TH["panel"], fg=TH["fg_dim"], font=TH["font_sm"]).pack(side="left")
        self._slbl = tk.Label(hdr, text="Ready", bg=TH["panel"],
                               fg=TH["fg_dim"], font=TH["font_sm"], padx=16)
        self._slbl.pack(side="right")

        # Control bar
        ctrl = tk.Frame(r, bg=TH["panel"], pady=7, padx=12); ctrl.pack(fill="x")
        self._pvar = tk.StringVar()
        pe = tk.Entry(ctrl, textvariable=self._pvar, bg=TH["card"], fg=TH["fg"],
                      insertbackground=TH["fg"], relief="flat", font=TH["font"], width=58)
        pe.pack(side="left", padx=(0,7), ipady=5)
        pe.bind("<Return>", lambda _: self._run())
        self._btn(ctrl,"Browse…",   self._browse).pack(side="left", padx=3)
        self._btn(ctrl,"▶  Analyse",self._run, True).pack(side="left", padx=3)
        self._btn(ctrl,"History",   self._show_history).pack(side="left", padx=3)
        self._btn(ctrl,"Clear",     self._clear).pack(side="left", padx=3)
        self._btn(ctrl,"Save Log",  self._save_log).pack(side="right", padx=3)
        self._btn(ctrl,"Save .py",  self._save_py).pack(side="right", padx=3)

        # Search bar (initially hidden)
        self._search_frame = tk.Frame(r, bg=TH["card"], pady=4, padx=12)
        self._svar = tk.StringVar()
        tk.Label(self._search_frame, text="Find:", bg=TH["card"],
                 fg=TH["fg_dim"], font=TH["font_sm"]).pack(side="left")
        self._se = tk.Entry(self._search_frame, textvariable=self._svar,
                            bg=TH["bg"], fg=TH["fg"], insertbackground=TH["fg"],
                            relief="flat", font=TH["font"], width=30)
        self._se.pack(side="left", padx=6, ipady=3)
        self._se.bind("<Return>", lambda _: self._search_next())
        self._se.bind("<Escape>", lambda _: self._hide_search())
        self._btn(self._search_frame,"Next",self._search_next).pack(side="left",padx=2)
        self._btn(self._search_frame,"✕",self._hide_search).pack(side="left",padx=2)

        # Progress
        pf = tk.Frame(r, bg=TH["bg"]); pf.pack(fill="x")
        self._prog = ttk.Progressbar(pf, mode="determinate", maximum=100)
        self._prog.pack(fill="x")

        # Main paned
        paned = tk.PanedWindow(r, orient="horizontal", bg=TH["border"],
                               sashwidth=5, sashrelief="flat", sashpad=0)
        paned.pack(fill="both", expand=True)

        # Left: tabs
        left = tk.Frame(paned, bg=TH["bg"]); paned.add(left, minsize=340, width=390)
        nb = ttk.Notebook(left); nb.pack(fill="both", expand=True, padx=5, pady=5)
        self._log_box  = self._mktab(nb, "Log")
        self._info_box = self._mktab(nb, "Analysis")
        self._ioc_box  = self._mktab(nb, "IOC")
        self._cg_box   = self._mktab(nb, "Call Graph")
        self._df_box   = self._mktab(nb, "Data Flow")
        self._ren_box  = self._mktab(nb, "Rename Map")

        # Log tags
        for tag,col in [("ok",TH["ok"]),("err",TH["danger"]),("warn",TH["warn"]),
                         ("step",TH["accent"]),("debug",TH["fg_dim"]),
                         ("ts",TH["fg_dim"]),("icon",TH["accent2"])]:
            self._log_box.tag_config(tag, foreground=col)

        # Right: source viewer
        right = tk.Frame(paned, bg=TH["bg"]); paned.add(right, minsize=500)
        src_hdr = tk.Frame(right, bg=TH["panel"], pady=5, padx=10); src_hdr.pack(fill="x")
        self._stitle = tk.Label(src_hdr, text="Decompiled Source",
                                bg=TH["panel"], fg=TH["fg_dim"], font=TH["font_sm"])
        self._stitle.pack(side="left")
        self._btn(src_hdr,"⌕ Find (Ctrl+F)",self._show_search).pack(side="right",padx=2)
        self._btn(src_hdr,"Copy",self._copy_src).pack(side="right",padx=2)

        # Function jump list
        jf = tk.Frame(right, bg=TH["panel"], pady=2, padx=6); jf.pack(fill="x")
        tk.Label(jf, text="Jump to fn:", bg=TH["panel"], fg=TH["fg_dim"],
                 font=TH["font_xs"]).pack(side="left")
        self._jump_var = tk.StringVar(value="—")
        self._jump_menu = ttk.Combobox(jf, textvariable=self._jump_var,
                                       state="readonly", font=TH["font_xs"], width=28)
        self._jump_menu.pack(side="left", padx=4)
        self._jump_menu.bind("<<ComboboxSelected>>", self._jump_to_fn)

        self._src_box = scrolledtext.ScrolledText(
            right, bg=TH["src_bg"], fg=TH["fg"], font=TH["font"],
            relief="flat", insertbackground=TH["fg"], wrap="none",
            selectbackground=TH["accent"], selectforeground="#fff")
        self._src_box.pack(fill="both", expand=True, padx=5, pady=5)
        self._src_box.configure(state="disabled")
        self._src_box.bind("<Control-f>", lambda _: self._show_search())
        self._setup_syn_tags()

        self._stat_lbl = tk.Label(right, text="", bg=TH["panel"],
                                   fg=TH["fg_dim"], font=TH["font_xs"], anchor="w", padx=8)
        self._stat_lbl.pack(fill="x", side="bottom")

    def _mktab(self, nb, label):
        f = tk.Frame(nb, bg=TH["bg"]); nb.add(f, text=label)
        b = scrolledtext.ScrolledText(f, bg=TH["bg"], fg=TH["fg"], font=TH["font_sm"],
                                      relief="flat", wrap="word", state="disabled",
                                      insertbackground=TH["fg"])
        b.pack(fill="both", expand=True, padx=3, pady=3); return b

    def _btn(self, p, txt, cmd, accent=False):
        return tk.Button(p, text=txt, command=cmd,
                         bg=TH["accent"] if accent else TH["border"], fg="#fff",
                         activebackground=TH["card"], activeforeground=TH["fg"],
                         relief="flat", font=TH["font_b"], padx=9, pady=3,
                         cursor="hand2", bd=0)

    def _setup_syn_tags(self):
        sb = self._src_box
        sb.tag_config("kw",  foreground="#c792ea", font=TH["font_b"])
        sb.tag_config("str", foreground="#c3e88d")
        sb.tag_config("cm",  foreground="#546e7a", font=(*TH["font"][:2],"italic"))
        sb.tag_config("num", foreground="#f78c6c")
        sb.tag_config("dec", foreground=TH["accent3"])
        sb.tag_config("search_hl", background=TH["accent3"], foreground="#000")

    # ── Actions ──
    def _browse(self):
        p = filedialog.askopenfilename(
            title="Select file", filetypes=[
                ("Supported","*.exe *.pyz *.pyc *.py *.pyw *.txt"),("All","*.*")])
        if p: self._pvar.set(p)

    def _run(self):
        path = self._pvar.get().strip()
        if not path: messagebox.showwarning("DecompX","Select a file first."); return
        if not os.path.isfile(path): messagebox.showerror("DecompX","File not found."); return
        self._reset(); LOG.clear(); self._setstatus("Analysing…",TH["accent"])
        self._add_history(path)
        threading.Thread(target=run_pipeline,
                         args=(path,self._setprog,self._done,self._err),
                         daemon=True).start()

    def _clear(self):
        self._pvar.set(""); self._reset(); LOG.clear(); self._setstatus("Ready",TH["fg_dim"])

    def _reset(self):
        for b in (self._log_box,self._info_box,self._ioc_box,self._cg_box,
                  self._df_box,self._ren_box,self._src_box):
            b.configure(state="normal"); b.delete("1.0","end"); b.configure(state="disabled")
        self._prog["value"]=0; self._source=""; self._rename_map={}
        self._stitle.configure(text="Decompiled Source"); self._stat_lbl.configure(text="")
        self._jump_menu.configure(values=[]); self._jump_var.set("—")

    def _copy_src(self):
        if self._source:
            self.root.clipboard_clear(); self.root.clipboard_append(self._source)
            self._setstatus("Copied!",TH["ok"])

    def _save_py(self):
        if not self._source: return
        p = filedialog.asksaveasfilename(defaultextension=".py",
            filetypes=[("Python","*.py"),("All","*.*")])
        if p:
            try: pathlib.Path(p).write_text(self._source, encoding="utf-8"); self._setstatus(f"Saved: {pathlib.Path(p).name}",TH["ok"])
            except Exception as e: messagebox.showerror("DecompX",str(e))

    def _save_log(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text","*.txt"),("All","*.*")])
        if p:
            try: pathlib.Path(p).write_text(LOG.as_text(), encoding="utf-8"); self._setstatus(f"Log saved",TH["ok"])
            except Exception as e: messagebox.showerror("DecompX",str(e))

    # ── Search ──
    def _show_search(self):
        self._search_frame.pack(fill="x", after=self._prog if hasattr(self,"_prog") else None)
        self._se.focus_set()

    def _hide_search(self):
        self._search_frame.pack_forget()
        self._src_box.tag_remove("search_hl","1.0","end")

    def _search_next(self):
        q = self._svar.get()
        if not q: return
        sb = self._src_box; sb.configure(state="normal")
        sb.tag_remove("search_hl","1.0","end")
        start = self._search_idx
        pos = sb.search(q, start, stopindex="end", nocase=True)
        if not pos:
            pos = sb.search(q, "1.0", stopindex="end", nocase=True)
        if pos:
            end = f"{pos}+{len(q)}c"
            sb.tag_add("search_hl", pos, end)
            sb.see(pos); self._search_idx = end
        sb.configure(state="disabled")

    # ── Jump to function ──
    def _jump_to_fn(self, _=None):
        sel = self._jump_var.get()
        if not sel or sel == "—": return
        fn_name = sel.split("(")[0].strip()
        sb = self._src_box
        sb.configure(state="normal")
        pos = sb.search(f"def {fn_name}", "1.0", stopindex="end")
        if pos: sb.see(pos)
        sb.configure(state="disabled")

    # ── History ──
    def _load_history(self) -> list[str]:
        try:
            raw = vx.db.query(HISTORY_KEY)
            return json.loads(raw) if raw else []
        except: return []

    def _add_history(self, path: str):
        if path in self._history: self._history.remove(path)
        self._history.insert(0, path)
        self._history = self._history[:10]
        try: vx.db.store(HISTORY_KEY, json.dumps(self._history))
        except: pass

    def _show_history(self):
        if not self._history:
            messagebox.showinfo("DecompX","No file history yet."); return
        win = tk.Toplevel(self.root); win.title("Recent Files")
        win.configure(bg=TH["bg"]); win.geometry("500x280")
        lb = tk.Listbox(win, bg=TH["card"], fg=TH["fg"], font=TH["font_sm"],
                        selectbackground=TH["accent"], relief="flat", bd=0)
        lb.pack(fill="both", expand=True, padx=8, pady=8)
        for p in self._history: lb.insert("end", p)
        def _pick(_=None):
            sel = lb.curselection()
            if sel:
                self._pvar.set(self._history[sel[0]]); win.destroy(); self._run()
        lb.bind("<Double-Button-1>", _pick)
        self._btn(win,"Open",_pick,True).pack(pady=4)

    # ── Thread-safe ──
    def _setstatus(self, t, c=""): self.root.after(0, lambda: self._slbl.configure(text=t, fg=c or TH["fg_dim"]))
    def _setprog(self, v): self.root.after(0, lambda: self._prog.configure(value=v))

    def _on_log(self, e):
        def _do():
            b = self._log_box; b.configure(state="normal")
            tag = e["level"].lower()
            b.insert("end",f"[{e['ts']}] ","ts")
            b.insert("end",f"{e['icon']} ","icon")
            b.insert("end",e["msg"]+"\n", tag if tag in ("ok","err","warn","step","debug") else "")
            if e.get("detail"):
                for ln in e["detail"].splitlines(): b.insert("end",f"    {ln}\n","debug")
            b.see("end"); b.configure(state="disabled")
        try: self.root.after(0,_do)
        except: pass

    def _err(self, msg):
        self._setstatus(f"Error: {msg}", TH["danger"]); self._setprog(0)
        self.root.after(0, lambda: messagebox.showerror("DecompX", msg))

    def _done(self, source, parsed, obf, layers, b64f, rename_map,
               from_cache=False, cg_txt="", data_flow=None, reputation=None):
        self._source = source; self._rename_map = rename_map
        if data_flow is None: data_flow = []
        if reputation is None: reputation = {}
        def _do():
            # Source
            sb = self._src_box; sb.configure(state="normal")
            sb.delete("1.0","end"); sb.insert("end",source)
            self._highlight_source(); sb.configure(state="disabled")
            tag = (" · ✔ Renamed" if rename_map else "") + (" · [CACHE]" if from_cache else "")
            self._stitle.configure(text=f"Decompiled Source{tag}")
            # Stats
            obf_s = obf.get("score",0) if isinstance(obf,dict) else 0
            ast_s = parsed.get("ast_ok",False) if isinstance(parsed,dict) else False
            self._stat_lbl.configure(
                text=f"  {parsed.get('line_count',0)} lines · {parsed.get('char_count',0)} chars"
                     f" · {'AST OK' if ast_s else 'no AST'} · obf {obf_s}/100")
            # Jump menu
            fns = [f"{f['name']}() L{f['line']}" for f in parsed.get("functions",[])]
            self._jump_menu.configure(values=["—"]+fns); self._jump_var.set("—")
            # Analysis
            self._fill_box(self._info_box, self._analysis_text(parsed, obf, b64f))
            # IOC
            self._fill_box(self._ioc_box, self._ioc_text(parsed, reputation))
            # Call graph
            self._fill_box(self._cg_box, cg_txt or "— no call graph —")
            # Data flow
            self._fill_box(self._df_box, self._df_text(data_flow))
            # Rename map
            self._fill_box(self._ren_box, self._ren_text(rename_map))
            self._setstatus("✔ Done" + (" (cached)" if from_cache else ""), TH["ok"])
        self.root.after(0, _do)

    def _fill_box(self, box, text):
        box.configure(state="normal"); box.delete("1.0","end")
        box.insert("end", text); box.configure(state="disabled")

    def _analysis_text(self, parsed, obf, b64f) -> str:
        obf_s = obf.get("score",0) if isinstance(obf,dict) else 0
        lines = [f"── OBF SCORE: {obf_s}/100 ──"]
        for t in (obf.get("techniques",[]) if isinstance(obf,dict) else []):
            lines.append(f"  ⚠ {t}")
        lines.append("\n── IMPORTS ──")
        for i in parsed.get("imports",[]): lines.append(f"  {i}")
        lines.append("\n── FUNCTIONS ──")
        for fn in parsed.get("functions",[]):
            ret = f" → {fn.get('returns')}" if fn.get("returns") else ""
            decs = "  "+", ".join(fn.get("decorators",[])) if fn.get("decorators") else ""
            lines.append(f"  def {fn['name']}({', '.join(fn.get('args',[]))}){ret}  [L{fn['line']}]{decs}")
        lines.append("\n── CLASSES ──")
        for cls in parsed.get("classes",[]):
            bases = f"({', '.join(cls.get('bases',[]))})" if cls.get("bases") else ""
            lines.append(f"  class {cls['name']}{bases}  [L{cls['line']}]")
        lines.append("\n── SUSPICIOUS ──")
        for s in parsed.get("suspicious",[]): lines.append(f"  ⚠ {s['pattern']} ×{s['count']}")
        if b64f:
            lines.append(f"\n── EMBEDDED STRINGS ({len(b64f)}) ──")
            for b in b64f: lines.append(f"  [{b['type']}] {b['encoded'][:50]}\n  → {b['decoded'][:80]}\n")
        if isinstance(obf,dict) and obf.get("hi_ent_lines"):
            lines.append(f"\n── HIGH-ENTROPY LINES ({len(obf['hi_ent_lines'])}) ──")
            for h in obf["hi_ent_lines"]: lines.append(f"  L{h['line']} ent={h['entropy']}  {h['preview']}")
        return "\n".join(lines)

    def _ioc_text(self, parsed, reputation) -> str:
        lines = []
        for lbl, key in [("URLs","urls"),("IPs","ips"),("Emails","emails"),
                          ("Domains","domains"),("Registry Keys","registry_keys")]:
            items = parsed.get("iocs",{}).get(key,[])
            lines.append(f"── {lbl} ({len(items)}) ──")
            for item in items:
                rep = reputation.get(item,"")
                rep_str = f"  [{rep}]" if rep else ""
                lines.append(f"  {item}{rep_str}")
            lines.append("")
        return "\n".join(lines)

    def _df_text(self, data_flow) -> str:
        if not data_flow: return "No data flow findings.\n(No tainted variables reached sinks.)"
        lines = [f"── DATA FLOW / TAINT ANALYSIS ({len(data_flow)} findings) ──\n"]
        for f in data_flow:
            lines.append(f"  var  : {f['var']}")
            lines.append(f"  src  : {f['source']}()")
            lines.append(f"  sink : {f['sink']}()")
            lines.append(f"  line : {f['line']}")
            lines.append("")
        return "\n".join(lines)

    def _ren_text(self, rename_map) -> str:
        if not rename_map: return "No renaming performed.\n(Script not detected as obfuscated.)"
        lines = [f"── RENAME MAP ({len(rename_map)}) ──\n"]
        w = max((len(k) for k in rename_map), default=10)
        for o,n in sorted(rename_map.items()): lines.append(f"  {o:<{w+2}} →  {n}")
        return "\n".join(lines)

    def _highlight_source(self):
        sb = self._src_box; text = sb.get("1.0","end")
        KW = (r'\b(def|class|import|from|return|if|else|elif|for|while|try|except|'
              r'finally|with|as|pass|break|continue|lambda|and|or|not|in|is|'
              r'None|True|False|yield|async|await|raise|global|nonlocal|del|assert)\b')
        def hl(pat, tag):
            for m in re.finditer(pat, text):
                sb.tag_add(tag, f"1.0+{m.start()}c", f"1.0+{m.end()}c")
        hl(KW, "kw"); hl(r'#[^\n]*',"cm")
        hl(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"\n]*"|\'[^\'\n]*\')',"str")
        hl(r'\b\d+\.?\d*\b',"num"); hl(r'@\w+',"dec")

    def run(self): self.root.mainloop()
    def destroy(self):
        try: self.root.destroy()
        except: pass

# ═══════════════════════════════════════════════════════════════
#  V0RTEX ENTRY POINTS
# ═══════════════════════════════════════════════════════════════
_ui: DecompXUI | None = None
_ui_thread: threading.Thread | None = None

def on_load():
    LOG.info("DecompX v3.0 loaded (V0RTEX-Made)")
    vx_register_scan_hook()

def run():
    global _ui, _ui_thread
    def _open():
        global _ui
        _ui = DecompXUI(); _ui.run(); _ui = None
    _ui_thread = threading.Thread(target=_open, daemon=True, name="DecompX-UI")
    _ui_thread.start()
    _vx_safe(vx.ui.notify, "DecompX v3.0 opened", level="info")

def on_unload():
    global _ui, _ui_thread
    if _ui:
        try: _ui.destroy()
        except: pass
        _ui = None
    _ui_thread = None
    LOG.info("DecompX unloaded cleanly")

def on_update(old_version: str, new_version: str):
    LOG.info(f"DecompX updated {old_version} → {new_version}")
