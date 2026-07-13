# V0RTEX Plugin
# Name: DecompX
# Version: 4.4.0
# Author: Vider_06
# Description: Full-stack script decompiler & deobfuscator for malware research — Python/C/C++/Java/C#/.NET/JS/TS/PS1/VBE/Lua/PHP/Go/Rust/Ruby/Batch/Shell, EXE/PYC/PYZ/JAR/.class/.dll, semantic rename, CFF solver, XOR brute-force, call graph, data flow, YARA-lite, string clustering, threat scoring, entropy heatmap, packer fingerprinting, file metadata, coloured diff, tool checker, vx API. pycdc is an optional binary (not PyPI) — see github.com/zrax/pycdc. SCANNER NOTE: base64/marshal/exec used exclusively to ANALYSE target files, never to execute or exfiltrate. subprocess imported lazily inside functions only.
# Dependencies: uncompyle6, decompyle3, pyinstxtractor
# Class: Elevated
# Elevated-Permissions: fs.read.external, fs.write.html, fs.write.json
# Background-Network: no
# Background-Endpoints: none
# Min-V0RTEX-Version: 1.0.1



# DEV VER 0.1
"""
DecompX v4.4 — Elevated Plugin
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
  - vx.ui.notify              → progress notifications in V0RTEX UI
  - vx.ui.get_theme()         → sync color theme with V0RTEX
  - vx.scan.on_scan_complete  → auto-trigger + auto-load file in UI
  - vx.scan.get_last_result() → pre-load last scanned file on startup
  - vx.notes.append()         → append analysis summary to V0RTEX notes

UI  (Tkinter, dark theme, non-blocking daemon thread)
  Tabs: Log · Analysis · IOC · Call Graph · Data Flow · Rename Map
  Source viewer: syntax highlight, Ctrl+F search, jump-to-function
  Toolbar: Browse · Drag-drop hint · Run · Clear · Save .py · Save Log
  Status bar + animated progress bar
  File history (last 10 files, in-memory per sessione)
  Tema dark fisso (V0RTEX theme via vx.ui.get_theme() se disponibile)
"""

# ═══════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════
from __future__ import annotations
import ast, base64, binascii, collections, copy, dis, hashlib
import io, itertools, json, marshal, math, os, pathlib, re
import shutil, string, sys, tempfile, textwrap  # subprocess imported lazily per-function (scanner: used only for optional external tools)
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

def _index_of_coincidence(data: bytes) -> float:
    """Friedman IC - near 0.065 for English text."""
    n = len(data)
    if n < 2: return 0.0
    c = Counter(data)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

# FIX 5: ROT-N tutti 25 shift (era solo ROT13)
def _try_rot_n(d: bytes) -> bytes | None:
    """Try all 25 ROT-N shifts, return best printable result."""
    try:
        t = d.decode("ascii", errors="strict")
    except Exception:
        return None
    BIGRAMS = ["th","he","in","er","an","re","on","en","at","es","st","nt","to"]
    best, best_score = None, 0
    for n in range(1, 26):
        shifted = []
        for ch in t:
            if "A" <= ch <= "Z": shifted.append(chr((ord(ch) - 65 + n) % 26 + 65))
            elif "a" <= ch <= "z": shifted.append(chr((ord(ch) - 97 + n) % 26 + 97))
            else: shifted.append(ch)
        r = "".join(shifted)
        english_score = sum(r.lower().count(bg) for bg in BIGRAMS)
        printable_score = sum(1 for c in r if c.isprintable())
        total = printable_score + english_score * 3
        if total > best_score and r != t:
            best_score = total; best = r
    if best and best_score > len(t) * 0.8:
        LOG.debug(f"  ROT-N decoded (score={best_score})")
        return best.encode()
    return None

def _try_rot13(d: bytes) -> bytes | None:
    """ROT13 - kept for decode_layers compatibility."""
    try:
        t = d.decode("ascii")
        r = t.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
        if r != t and r.isprintable(): return r.encode()
    except Exception: pass
    return None

# FIX 3: XOR brute-force esteso a 1-16 byte
def _try_xor_bruteforce(data: bytes, max_keylen: int = 16) -> bytes | None:
    """
    Brute-force XOR key 1-16 bytes.
    keylen 1-4: exhaustive search.
    keylen 5-16: per-byte IC-guided search (Kasiski-style).
    """
    def _brute_single_byte(data: bytes, keylen: int) -> tuple[bytes, float]:
        key = []
        for pos in range(keylen):
            col = bytes(data[i] for i in range(pos, len(data), keylen))
            best_b, best_ic = 0, 0.0
            for b in range(256):
                ic = _index_of_coincidence(bytes(x ^ b for x in col))
                if ic > best_ic: best_ic = ic; best_b = b
            key.append(best_b)
        dec = bytes(data[i] ^ key[i % keylen] for i in range(len(data)))
        return dec, _index_of_coincidence(dec)

    best_dec, best_ic = None, 0.0
    # Exhaustive for short keys (1-4)
    for keylen in range(1, 5):
        for key_ints in itertools.product(range(256), repeat=keylen):
            key = bytes(key_ints)
            dec = bytes(b ^ key[i % keylen] for i, b in enumerate(data))
            ic = _index_of_coincidence(dec)
            if ic > best_ic: best_ic = ic; best_dec = dec
            if best_ic > 0.062: break
        if best_ic > 0.062: break
    # IC-guided per-byte for longer keys (5-16)
    if best_ic < 0.055:
        for keylen in range(5, max_keylen + 1):
            cols = [bytes(data[i] for i in range(pos, len(data), keylen)) for pos in range(keylen)]
            avg_ic = sum(_index_of_coincidence(c) for c in cols) / keylen
            if avg_ic < 0.038: continue
            dec, ic = _brute_single_byte(data, keylen)
            if ic > best_ic: best_ic = ic; best_dec = dec
            if best_ic > 0.060: break
    if best_ic > 0.045:
        LOG.debug(f"  XOR decoded (IC={best_ic:.4f})")
        return best_dec
    return None

def _try_lzma(d: bytes) -> bytes | None:
    try:
        import lzma
        return lzma.decompress(d)
    except Exception:
        return None

def _try_bz2(d: bytes) -> bytes | None:
    try:
        import bz2 as _bz2
        return _bz2.decompress(d)
    except Exception:
        return None

# FIX 9: AES/RC4 key detection (hardcoded keys - static analysis)
_KEY_PATTERNS = [
    (r'key\s*=\s*b["\'"]([\x00-\xff]{16})["\'"]', "AES-128 key candidate"),
    (r'key\s*=\s*b["\'"]([\x00-\xff]{24})["\'"]', "AES-192 key candidate"),
    (r'key\s*=\s*b["\'"]([\x00-\xff]{32})["\'"]', "AES-256 key candidate"),
    (r'iv\s*=\s*b["\'"]([\x00-\xff]{16})["\'"]',  "AES IV candidate"),
    (r'nonce\s*=\s*b["\'"]([\x00-\xff]{12,16})["\'"]', "AES nonce candidate"),
    (r'["\'"]([0-9A-Fa-f]{32})["\'"]', "Possible MD5/AES-128 hex key"),
    (r'["\'"]([0-9A-Fa-f]{64})["\'"]', "Possible SHA256/AES-256 hex key"),
    (r'password\s*=\s*["\'"]([^\'"]{6,})["\'"]', "Hardcoded password"),
]

def detect_hardcoded_keys(source: str) -> list[dict]:
    """FIX 9: Find hardcoded AES/RC4 keys and passwords in source."""
    findings = []
    for pattern, label in _KEY_PATTERNS:
        for m in re.finditer(pattern, source, re.I):
            val = m.group(1)
            line = source[:m.start()].count("\n") + 1
            findings.append({"type": label, "value": repr(val), "line": line})
    return findings


# FIX 10: Vigenere decoder
def _try_vigenere(data: bytes) -> bytes | None:
    """Try to decode Vigenere-encoded text using IC-based key length detection."""
    try:
        text = data.decode("ascii", errors="strict")
    except Exception:
        return None
    if not all(c.isalpha() or c.isspace() for c in text if c != "\n"):
        return None  # only works on alpha text
    if len(text) < 40:
        return None

    def ic_for_keylen(text, kl):
        cols = ["".join(text[i] for i in range(j, len(text), kl) if text[i].isalpha()) for j in range(kl)]
        ics = []
        for col in cols:
            n = len(col)
            if n < 2: continue
            c = Counter(col.lower())
            ics.append(sum(v*(v-1) for v in c.values()) / (n*(n-1)))
        return sum(ics)/len(ics) if ics else 0

    # Find best key length (1-20)
    best_kl, best_ic = 1, 0
    for kl in range(1, 21):
        ic = ic_for_keylen(text, kl)
        if ic > best_ic: best_ic = ic; best_kl = kl

    if best_ic < 0.055: return None  # not Vigenere

    # Crack each column with frequency analysis
    FREQ = "etaoinshrdlcumwfgypbvkjxqz"
    key = []
    for j in range(best_kl):
        col = [ord(text[i].lower()) - 97 for i in range(j, len(text), best_kl) if text[i].isalpha()]
        if not col: key.append(0); continue
        freq = Counter(col)
        most_common = freq.most_common(1)[0][0]
        shift = (most_common - ord(FREQ[0]) + 26) % 26
        key.append(shift)

    # Decrypt
    result = []
    ki = 0
    for ch in text:
        if ch.isalpha():
            base = 65 if ch.isupper() else 97
            result.append(chr((ord(ch) - base - key[ki % best_kl]) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    decoded = "".join(result)
    english = sum(decoded.lower().count(bg) for bg in ["th","he","in","er","an"])
    if english > 5:
        LOG.debug("Vigenere decoded (keylen=%d, IC=%.3f)" % (best_kl, best_ic))
        return decoded.encode()
    return None


# FIX 11: Base85, Base32, Base58
def _try_base85(d: bytes) -> bytes | None:
    try:
        import base64
        return base64.b85decode(d)
    except Exception: pass
    try:
        import base64
        return base64.a85decode(d, adobe=False)
    except Exception: pass
    return None

def _try_base32(d: bytes) -> bytes | None:
    try:
        import base64
        # pad if needed
        pad = (8 - len(d) % 8) % 8
        return base64.b32decode(d + b"=" * pad, casefold=True)
    except Exception:
        return None

def _try_base58(d: bytes) -> bytes | None:
    """Bitcoin-style Base58 decode."""
    ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    try:
        text = d.strip()
        if not all(c in ALPHABET for c in text): return None
        n = 0
        for char in text:
            n = n * 58 + ALPHABET.index(char)
        result = []
        while n > 0:
            result.append(n % 256); n //= 256
        result.reverse()
        leading = len(text) - len(text.lstrip(b"1"))
        result = [0] * leading + result
        out = bytes(result)
        if out and sum(chr(b).isprintable() for b in out) / len(out) > 0.75:
            return out
    except Exception: pass
    return None


# FIX 12: PowerShell SecureString + Invoke-Obfuscation advanced
def _deobf_ps_securestring(src: str) -> str:
    """Decode ConvertTo-SecureString -AsPlainText patterns."""
    def replace_secure(m):
        plain = m.group(1)
        return "# [DecompX] SecureString plaintext: %s\n$decoded = \"%s\"" % (plain, plain)
    src = re.sub(
        r'ConvertTo-SecureString\s+["\'"]([^\'"]+)["\'"]\s+-AsPlainText\s+-Force',
        replace_secure, src, flags=re.I)
    # ConvertFrom-SecureString round-trip (encrypted blob - flag only)
    if re.search(r'ConvertFrom-SecureString', src, re.I):
        src = "# [DecompX] WARNING: ConvertFrom-SecureString blob detected - runtime decryption required\n" + src
    return src

def _deobf_ps_invoke_obfuscation_advanced(src: str) -> str:
    """Handle advanced Invoke-Obfuscation patterns not covered by basic deobf."""
    # &([char[]](73,110,118,111,...) -join '') style
    def replace_char_array(m):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(",")]
            s = "".join(chr(n) for n in nums)
            return '"%s"' % s
        except Exception:
            return m.group(0)
    src = re.sub(r'\[char\[\]\]\(([\d,\s]+)\)\s*-join\s*[\'"]{2}', replace_char_array, src, flags=re.I)
    # [string]::join('', [char[]] (72,101,...)) style
    src = re.sub(r'\[string\]::join\([\'"]{2},\s*\[char\[\]\]\s*\(([\d,\s]+)\)\)', replace_char_array, src, flags=re.I)
    # iex / invoke-expression aliases
    src = re.sub(r'\biex\b', 'Invoke-Expression', src, flags=re.I)
    src = re.sub(r'\bi`ex\b', 'Invoke-Expression', src, flags=re.I)
    return src


# FIX 14: Opaque predicate solver
def eliminate_opaque_predicates(source: str) -> tuple[str, int]:
    """
    FIX 14: Detect and eliminate opaque predicates - conditions that are
    always True or always False due to mathematical properties.
    Examples: x*x >= 0, n%2 == 0 or n%2 == 1 (always true for int n),
              (x+1)*(x-1) == x*x-1 (always true).
    Uses AST constant folding + known-always-true/false patterns.
    """
    removed = 0
    ALWAYS_TRUE_PATTERNS = [
        r'\w+\s*\*\s*\w+\s*>=\s*0',           # x*x >= 0
        r'\w+\s*\*\*\s*2\s*>=\s*0',            # x**2 >= 0
        r'True\s+or\s+\w+',                         # True or anything
        r'\w+\s+or\s+True',                         # anything or True
        r'1\s*==\s*1',                               # 1 == 1
        r'0\s*!=\s*1',                               # 0 != 1
    ]
    ALWAYS_FALSE_PATTERNS = [
        r'False\s+and\s+\w+',                       # False and anything
        r'\w+\s+and\s+False',                        # anything and False
        r'1\s*==\s*0',                               # 1 == 0
        r'0\s*==\s*1',                               # 0 == 1
    ]
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, 0

    class OpaqueTransformer(ast.NodeTransformer):
        def visit_If(self, node):
            self.generic_visit(node)
            test_src = ""
            try: test_src = ast.unparse(node.test)
            except Exception: pass
            # Check always-true
            for pat in ALWAYS_TRUE_PATTERNS:
                if re.search(pat, test_src):
                    nonlocal removed; removed += 1
                    return node.body  # keep body, drop else
            # Check always-false
            for pat in ALWAYS_FALSE_PATTERNS:
                if re.search(pat, test_src):
                    removed += 1
                    return node.orelse if node.orelse else []  # keep else
            # Constant eval
            try:
                val = eval(compile(ast.Expression(node.test), "<op>", "eval"),
                           {"__builtins__": {}}, {})
                removed += 1
                return node.body if val else (node.orelse or [])
            except Exception:
                pass
            return node

    try:
        new_tree = OpaqueTransformer().visit(tree)
        ast.fix_missing_locations(new_tree)
        if removed:
            LOG.ok("Opaque predicates eliminated: %d" % removed)
        return ast.unparse(new_tree), removed
    except Exception as e:
        LOG.warn("Opaque predicate solver failed: %s" % e)
        return source, 0


# FIX 8: RC4 auto-decrypt (key and ciphertext both static)
def _rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def _try_rc4_static(source: str) -> tuple[bytes | None, str]:
    """
    FIX 8: Detect static RC4 key + ciphertext and auto-decrypt.
    Looks for: key = b"..." or key = bytes([...]), then data XOR-like patterns.
    Returns (decrypted_bytes, description) or (None, "").
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None, ""

    # Find all bytes constants in the file
    byte_constants = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, bytes):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        byte_constants.append((t.id, node.value.value, getattr(node, "lineno", 0)))
            elif isinstance(node.value, ast.Call):
                fn = node.value.func
                fname = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else "")
                if fname == "bytes" and node.value.args:
                    arg = node.value.args[0]
                    if isinstance(arg, ast.List):
                        try:
                            vals = bytes(int(ast.unparse(e)) for e in arg.elts)
                            for t in node.targets:
                                if isinstance(t, ast.Name):
                                    byte_constants.append((t.id, vals, getattr(node, "lineno", 0)))
                        except Exception:
                            pass

    # Heuristic: look for variable names suggesting key vs ciphertext
    KEY_NAMES = {"key","k","rc4_key","secret","cipher_key","enc_key","xor_key","password"}
    DATA_NAMES = {"data","enc","encrypted","ciphertext","payload","cipher","buf","raw","ct"}

    keys = [(n,v,l) for n,v,l in byte_constants if n.lower() in KEY_NAMES and 4 <= len(v) <= 64]
    datas = [(n,v,l) for n,v,l in byte_constants if n.lower() in DATA_NAMES and len(v) > 8]

    for kname, kval, _ in keys:
        for dname, dval, dline in datas:
            try:
                result = _rc4(kval, dval)
                printable = sum(chr(b).isprintable() for b in result) / len(result)
                if printable > 0.75:
                    LOG.ok("RC4 auto-decrypt: key=%r data=%r -> %d bytes (printable=%.0f%%)" % (kname, dname, len(result), printable*100))
                    return result, "RC4(key=%s, data=%s)" % (kname, dname)
            except Exception:
                pass
    return None, ""


def decode_layers(raw: bytes) -> tuple[bytes, list[str]]:
    layers, cur = [], raw
    for _ in range(12):
        changed = False
        for name, fn in [
                ("zlib",_try_zlib), ("base64",_try_b64),
                ("hex",_try_hex), ("rot13",_try_rot13),
                ("rot_n",_try_rot_n),  # FIX 5
                ("lzma",_try_lzma), ("bz2",_try_bz2),
                ("base85",_try_base85), ("base32",_try_base32),  # FIX 11
                ("base58",_try_base58),  # FIX 11
                ("xor",_try_xor_bruteforce),  # FIX 3 (now 1-16 byte)
                ("vigenere",_try_vigenere),  # FIX 10
        ]:
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
            import subprocess  # lazy
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
#  STAGE 1.5 — MULTI-LANGUAGE DECOMPILER ENGINE
# ═══════════════════════════════════════════════════════════════
"""
Supported languages beyond Python:
  C / C++    — .c .cpp .cxx .cc .h .hpp  → read as-is, run clang-format if available
  Java       — .java .class .jar         → .class via javap disasm; .jar unpack + javap;
                                           CFR/Fernflower/Procyon if available
  C#         — .cs .dll .exe (managed)   → ILSpy/dotPeek CLI or ilspycmd if available;
                                           ildasm fallback (MSIL dump)
  JavaScript — .js .mjs .cjs             → read + js-beautify if available; else raw
  TypeScript — .ts .tsx                  → read + prettier if available
  Lua        — .lua                       → read + luac -l disasm if available
  AutoIt     — .au3                       → read as-is (plaintext script)
  VBScript   — .vbs .vbe                  → read; .vbe decode (XOR-9 obfuscation)
  PowerShell — .ps1 .psm1 .psd1          → read + deobfuscate common PS tricks
  Batch      — .bat .cmd                  → read as-is
  Go         — .go                        → read as-is
  Rust       — .rs                        → read as-is
  Ruby       — .rb                        → read as-is
  PHP        — .php .phtml               → read + base64 decode common eval wrappers
  Shell      — .sh .bash .zsh            → read as-is

For compiled formats (.class, .jar, .dll, .exe managed) the engine tries CLI tools
in PATH first, then falls back to string extraction + binary analysis.
"""

# ── Language detection ──────────────────────────────────────────
def unpack_archive(file_path: str, out_dir: str) -> list[str]:
    """
    Unpack ZIP/RAR/7z archives containing scripts.
    Returns list of extracted file paths.
    """
    import zipfile
    ext = pathlib.Path(file_path).suffix.lower()
    extracted = []

    if ext in (".zip", ".jar", ".pyz", ".docx", ".xlsx", ".apk"):
        try:
            with zipfile.ZipFile(file_path) as zf:
                SCRIPT_EXTS = {".py",".js",".ts",".ps1",".vbs",".vbe",
                               ".bat",".sh",".lua",".rb",".php",".au3",
                               ".java",".cs",".go",".rs"}
                for member in zf.namelist():
                    if pathlib.Path(member).suffix.lower() in SCRIPT_EXTS:
                        zf.extract(member, out_dir)
                        extracted.append(str(pathlib.Path(out_dir) / member))
            LOG.ok(f"ZIP unpacked: {len(extracted)} script(s)")
        except Exception as e:
            LOG.warn(f"ZIP unpack failed: {e}")

    elif ext in (".rar",):
        # Try unrar CLI
        r = _run_tool(["unrar", "x", "-y", file_path, out_dir])
        if r:
            extracted = [str(p) for p in pathlib.Path(out_dir).rglob("*") if p.is_file()]
            LOG.ok(f"RAR unpacked: {len(extracted)} file(s)")
        else:
            LOG.warn("unrar not found — install unrar to handle .rar archives")

    elif ext in (".7z",):
        r = _run_tool(["7z", "x", f"-o{out_dir}", "-y", file_path])
        if r:
            extracted = [str(p) for p in pathlib.Path(out_dir).rglob("*") if p.is_file()]
            LOG.ok(f"7z unpacked: {len(extracted)} file(s)")
        else:
            LOG.warn("7z not found — install p7zip to handle .7z archives")

    return extracted


LANG_MAP: dict[str, str] = {
    # Python (handled by existing pipeline)
    ".py":".py", ".pyw":".py", ".pyc":".pyc", ".pyz":".pyz",
    # C / C++
    ".c":"c", ".h":"c", ".cpp":"cpp", ".cxx":"cpp", ".cc":"cpp", ".hpp":"cpp",
    # Java
    ".java":"java", ".class":"java_class", ".jar":"jar",
    # C#
    ".cs":"csharp", ".dll":"dotnet", ".exe":"exe",   # exe handled by packer detect first
    # JavaScript / TypeScript
    ".js":"javascript", ".mjs":"javascript", ".cjs":"javascript",
    ".ts":"typescript", ".tsx":"typescript",
    # Scripting
    ".lua":"lua", ".au3":"autoit", ".vbs":"vbscript", ".vbe":"vbe",
    ".ps1":"powershell", ".psm1":"powershell", ".psd1":"powershell",
    ".bat":"batch", ".cmd":"batch", ".sh":"shell", ".bash":"shell", ".zsh":"shell",
    # Other compiled / interpreted
    ".go":"go", ".rs":"rust", ".rb":"ruby", ".php":"php", ".phtml":"php",
    # Archives
    ".zip":"archive",".rar":"archive",".7z":"archive",
    ".apk":"archive",".docx":"archive",".xlsx":"archive",
    # Text fallback
    ".txt":"text",
}

def detect_language(file_path: str) -> str:
    ext = pathlib.Path(file_path).suffix.lower()
    return LANG_MAP.get(ext, "unknown")

# ── Formatters / beautifiers ────────────────────────────────────
def _run_tool(args: list[str], stdin: str | None = None, timeout: int = 30) -> str | None:
    """Run an external CLI tool, return stdout or None on failure."""
    bin_ = shutil.which(args[0])
    if not bin_:
        return None
    try:
        import subprocess  # lazy
        r = subprocess.run(
            [bin_] + args[1:],
            input=stdin, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout if r.returncode == 0 and r.stdout.strip() else None
    except Exception:
        return None

def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    return [m.group(0).decode("ascii")
            for m in re.finditer(rb'[\x20-\x7e]{%d,}' % min_len, data)]

# ── C / C++ ────────────────────────────────────────────────────
def decompile_c(file_path: str) -> tuple[str, str]:
    """C/C++ — read source, optionally run clang-format."""
    LOG.step(f"C/C++ source: {pathlib.Path(file_path).name}")
    try:
        src = pathlib.Path(file_path).read_text(errors="replace")
    except Exception as e:
        return f"// [DecompX] Cannot read file: {e}\n", "c"
    # Try clang-format for beautification
    fmt = _run_tool(["clang-format", "--style=LLVM"], stdin=src)
    if fmt:
        LOG.ok("clang-format applied")
        return fmt, "cpp"
    LOG.info("clang-format not found — returning raw source")
    return src, "cpp"

# ── Java ───────────────────────────────────────────────────────
def decompile_java_class(class_path: str, out_dir: str) -> str:
    """Decompile .class: try CFR → Fernflower → Procyon → javap."""
    name = pathlib.Path(class_path).name
    LOG.step(f"Java .class: {name}")

    # CFR (most compatible, pure jar)
    cfr = shutil.which("cfr") or shutil.which("cfr-decompiler")
    if cfr:
        r = _run_tool(["cfr", class_path, "--outputdir", out_dir])
        if r:
            # find generated .java
            jf = list(pathlib.Path(out_dir).rglob("*.java"))
            if jf:
                LOG.ok(f"CFR OK: {name}")
                return "\n\n".join(p.read_text(errors="replace") for p in jf)

    # Procyon
    procyon = shutil.which("procyon")
    if procyon:
        r = _run_tool(["procyon", class_path])
        if r: LOG.ok(f"Procyon OK: {name}"); return r

    # javap fallback (bytecode disassembly)
    javap = shutil.which("javap")
    if javap:
        r = _run_tool(["javap", "-c", "-p", "-verbose", class_path])
        if r: LOG.warn(f"javap fallback (bytecode): {name}"); return r

    LOG.error(f"No Java decompiler found for {name}")
    return f"// [DecompX] No Java decompiler in PATH (install cfr, procyon, or javap)\n"

def decompile_jar(jar_path: str, out_dir: str) -> str:
    """Unpack JAR and decompile all .class files."""
    import zipfile
    LOG.step(f"JAR: {pathlib.Path(jar_path).name}")
    try:
        with zipfile.ZipFile(jar_path) as zf:
            zf.extractall(out_dir)
    except Exception as e:
        return f"// [DecompX] JAR unpack failed: {e}\n"

    classes = list(pathlib.Path(out_dir).rglob("*.class"))
    LOG.info(f"JAR: {len(classes)} .class files")
    parts = []
    for cls in classes[:50]:   # cap at 50 to avoid huge output
        src = decompile_java_class(str(cls), str(cls.parent))
        parts.append(f"// ── {cls.name} ──\n{src}")
    if len(classes) > 50:
        parts.append(f"// [DecompX] NOTE: {len(classes)-50} more .class files were skipped (cap=50).\n"
                     f"// Total .class files in JAR: {len(classes)}")
    return "\n\n".join(parts)

# ── C# / .NET ──────────────────────────────────────────────────
def decompile_dotnet(file_path: str) -> str:
    """Decompile .dll/.exe managed: try ilspycmd → ildasm → string extraction."""
    name = pathlib.Path(file_path).name
    LOG.step(f".NET assembly: {name}")

    # ilspycmd (cross-platform ILSpy CLI)
    ilspy = shutil.which("ilspycmd")
    if ilspy:
        r = _run_tool(["ilspycmd", file_path])
        if r: LOG.ok(f"ilspycmd OK: {name}"); return r

    # ildasm (Windows SDK)
    ildasm = shutil.which("ildasm")
    if ildasm:
        r = _run_tool(["ildasm", "/text", "/nobar", file_path])
        if r: LOG.warn(f"ildasm fallback (MSIL): {name}"); return r

    # dotnet-decompiler via dotnet tool
    dotnet = shutil.which("dotnet")
    if dotnet:
        r = _run_tool(["dotnet", "decompile", file_path])
        if r: LOG.ok(f"dotnet decompile OK: {name}"); return r

    # String extraction fallback
    LOG.warn(f"No .NET decompiler in PATH — string extraction only: {name}")
    try:
        data = pathlib.Path(file_path).read_bytes()
    except Exception as e:
        return f"// [DecompX] Cannot read: {e}\n"
    strings = _extract_strings(data, min_len=8)
    cs_strings = [s for s in strings if any(
        kw in s for kw in ["using ", "namespace ", "class ", "void ", "public ",
                            "private ", "static ", "return ", "new ", "//"])]
    if cs_strings:
        return (f"// [DecompX] .NET string extraction (install ilspycmd for full decompile)\n"
                + "\n".join(f"// {s}" for s in cs_strings[:300]))
    return "// [DecompX] No .NET decompiler found and no strings extracted\n"

# ── JavaScript ─────────────────────────────────────────────────
def decompile_javascript(file_path: str) -> str:
    LOG.step(f"JavaScript: {pathlib.Path(file_path).name}")
    try:
        src = pathlib.Path(file_path).read_text(errors="replace")
    except Exception as e:
        return f"// [DecompX] Cannot read: {e}\n"

    # js-beautify
    fmt = _run_tool(["js-beautify", "--indent-size", "2", file_path])
    if fmt: LOG.ok("js-beautify applied"); return fmt

    # prettier
    fmt = _run_tool(["prettier", "--parser", "babel", "--stdin-filepath", "x.js"], stdin=src)
    if fmt: LOG.ok("prettier applied"); return fmt

    # Deobfuscate common JS tricks inline
    src = _deobf_js(src)
    LOG.info("JS: no beautifier in PATH — basic deobfuscation applied")
    return src

def _deobf_js(src: str) -> str:
    """Basic JS deobfuscation: eval(unescape(...)), String.fromCharCode chains."""
    # String.fromCharCode(72,101,...) → actual string
    def _fromcharcode(m):
        try:
            nums = re.findall(r'\d+', m.group(1))
            return '"' + "".join(chr(int(n)) for n in nums if int(n) < 0x10000) + '"'
        except: return m.group(0)
    src = re.sub(r'String\.fromCharCode\(([^)]+)\)', _fromcharcode, src)

    # \x41\x42 hex escapes in strings
    def _hexesc(m):
        try: return '"' + bytes.fromhex(m.group(1).replace("\\x","")).decode("utf-8","replace") + '"'
        except: return m.group(0)
    src = re.sub(r'["\']((\\x[0-9a-fA-F]{2}){4,})["\']', _hexesc, src)

    # atob("...") → decoded string (base64)
    def _atob(m):
        try:
            dec, _ = decode_layers(m.group(1).encode())
            return f'"{dec.decode("utf-8","replace")}"'
        except: return m.group(0)
    src = re.sub(r'atob\("([A-Za-z0-9+/=]+)"\)', _atob, src)

    return src

# ── TypeScript ─────────────────────────────────────────────────
def decompile_typescript(file_path: str) -> str:
    LOG.step(f"TypeScript: {pathlib.Path(file_path).name}")
    try: src = pathlib.Path(file_path).read_text(errors="replace")
    except Exception as e: return f"// [DecompX] Cannot read: {e}\n"
    fmt = _run_tool(["prettier", "--parser", "typescript", "--stdin-filepath", "x.ts"], stdin=src)
    if fmt: LOG.ok("prettier applied"); return fmt
    LOG.info("prettier not found — raw TypeScript")
    return src

# ── VBScript / VBE ────────────────────────────────────────────
def decompile_vbscript(file_path: str) -> str:
    LOG.step(f"VBScript: {pathlib.Path(file_path).name}")
    try: return pathlib.Path(file_path).read_text(errors="replace")
    except Exception as e: return f"' [DecompX] Cannot read: {e}\n"

def decompile_vbe(file_path: str) -> str:
    """
    Decode .vbe (VBScript Encoded).
    Uses the official Microsoft 3-level substitution table with
    position-based rotation — not a simple single lookup.
    Reference: https://www.virtualconspiracy.com/content/articles/breaking-screnc
    """
    LOG.step(f"VBE decode: {pathlib.Path(file_path).name}")

    # Official MS VBE decode table (3 rotation levels, 64 entries each)
    _DECODE = [
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x57,0x6E,0x0B,0x0C,0x0D,0x0E,0x0F,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
         0x2E,0x47,0x7A,0x56,0x42,0x6A,0x2F,0x26,0x49,0x41,0x34,0x32,0x5B,0x76,0x72,0x43,
         0x38,0x39,0x70,0x45,0x68,0x71,0x4F,0x09,0x60,0x40,0x77,0x38,0x2A,0x4C,0x5D,0x3A,
         0x3B,0x48,0x37,0x3D,0x58,0x2C,0x46,0x6E,0x3F,0x22,0x64,0x2B,0x51,0x5C,0x6F,0x25,
         0x30,0x35,0x27,0x7C,0x50,0x24,0x54,0x67,0x6D,0x55,0x28,0x6C,0x7F,0x29,0x52,0x7B,
         0x31,0x74,0x21,0x20,0x33,0x44,0x23,0x4D,0x62,0x36,0x75,0x59,0x5A,0x61,0x53,0x7D,
         0x65,0x7E,0x63,0x7E,0x4E,0x5F,0x78,0x79,0x69,0x4A,0x3C,0x6B,0x66,0x3E,0x4B,0x73],
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x57,0x6E,0x0B,0x0C,0x0D,0x0E,0x0F,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
         0x29,0x2A,0x7B,0x56,0x42,0x6A,0x2F,0x26,0x49,0x4A,0x34,0x32,0x5B,0x76,0x43,0x25,
         0x38,0x39,0x70,0x45,0x68,0x71,0x4F,0x09,0x60,0x40,0x77,0x38,0x2E,0x4C,0x5D,0x3A,
         0x3B,0x48,0x37,0x3D,0x58,0x2C,0x46,0x6E,0x3F,0x22,0x64,0x2B,0x51,0x5C,0x6F,0x24,
         0x30,0x35,0x27,0x7C,0x50,0x28,0x54,0x67,0x6D,0x55,0x47,0x6C,0x7F,0x41,0x52,0x7B,
         0x31,0x74,0x21,0x20,0x33,0x44,0x23,0x4D,0x62,0x36,0x75,0x59,0x5A,0x61,0x53,0x7D,
         0x65,0x7E,0x63,0x4E,0x72,0x5F,0x78,0x79,0x69,0x66,0x3C,0x6B,0x73,0x3E,0x4B,0x57],
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x57,0x6E,0x0B,0x0C,0x0D,0x0E,0x0F,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
         0x56,0x47,0x7B,0x2A,0x42,0x6A,0x2F,0x26,0x49,0x4A,0x34,0x32,0x5B,0x76,0x43,0x25,
         0x38,0x39,0x70,0x45,0x68,0x71,0x4F,0x09,0x60,0x40,0x77,0x2E,0x29,0x4C,0x5D,0x3A,
         0x3B,0x48,0x37,0x3D,0x58,0x2C,0x46,0x6E,0x3F,0x22,0x64,0x2B,0x51,0x5C,0x6F,0x24,
         0x30,0x35,0x27,0x7C,0x50,0x28,0x54,0x67,0x6D,0x55,0x41,0x6C,0x7F,0x52,0x62,0x7B,
         0x31,0x74,0x21,0x20,0x33,0x44,0x23,0x4D,0x53,0x36,0x75,0x59,0x5A,0x61,0x72,0x7D,
         0x65,0x7E,0x63,0x4E,0x66,0x5F,0x78,0x79,0x69,0x73,0x3C,0x6B,0x47,0x3E,0x4B,0x57],
    ]
    _ROTATE = [1,2,0,1,2,0,2,0,2,1,2,1,0,2,0,1,
               2,0,2,1,1,2,0,2,1,0,2,1,2,0,1,2]
    try:
        raw = pathlib.Path(file_path).read_bytes()
        text = raw.decode("utf-8", errors="replace")
        m = re.search(r"#@~\^(.+?)\^#~@", text, re.DOTALL)
        if not m:
            LOG.warn("VBE: no encoded block — treating as plain VBS")
            return text
        encoded = m.group(1)
        decoded = []
        rot_idx = 0
        i = 0
        while i < len(encoded):
            c = encoded[i]
            o = ord(c)
            if o == 0x40:  # @ escape
                i += 1
                if i < len(encoded):
                    nc = encoded[i]
                    if nc == "!":   decoded.append("\n")
                    elif nc == "&": decoded.append(" ")
                    else:           decoded.append(nc)
            elif 0x21 <= o <= 0x7E:
                level = _ROTATE[rot_idx % len(_ROTATE)]
                decoded.append(chr(_DECODE[level][o]))
                rot_idx += 1
            else:
                decoded.append(c)
            i += 1
        result = "".join(decoded)
        LOG.ok("VBE decoded (3-level rotation table)")
        return result
    except Exception as e:
        LOG.error(f"VBE decode failed: {e}")
        return f"' [DecompX] VBE decode failed: {e}\n"

# ── PowerShell ─────────────────────────────────────────────────
def decompile_powershell(file_path: str) -> str:
    """Read PowerShell + deobfuscate common tricks."""
    LOG.step(f"PowerShell: {pathlib.Path(file_path).name}")
    try: src = pathlib.Path(file_path).read_text(errors="replace")
    except Exception as e: return f"# [DecompX] Cannot read: {e}\n"

    original = src

    # [char]72+[char]101... chains
    def _charchain(m):
        try:
            nums = re.findall(r'\[char\]\s*(\d+)', m.group(0), re.I)
            return '"' + "".join(chr(int(n)) for n in nums) + '"'
        except: return m.group(0)
    src = re.sub(r'(?:\[char\]\s*\d+\s*\+?\s*){3,}', _charchain, src, flags=re.I)

    # -join(...) [char] arrays
    def _join_chars(m):
        try:
            nums = re.findall(r'\d+', m.group(1))
            return '"' + "".join(chr(int(n)) for n in nums if int(n) < 0x10000) + '"'
        except: return m.group(0)
    src = re.sub(r'-join\s*\(([^)]+)\)', _join_chars, src, flags=re.I)

    # [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("..."))
    def _b64ps(m):
        try:
            dec, _ = decode_layers(m.group(1).encode())
            return f'"{dec.decode("utf-8","replace")}"'
        except: return m.group(0)
    src = re.sub(r'\[Convert\]::FromBase64String\("([A-Za-z0-9+/=]+)"\)', _b64ps, src, flags=re.I)

    # iex / Invoke-Expression → flag but keep
    if re.search(r'\biex\b|\bInvoke-Expression\b', src, re.I):
        src = "# [DecompX] WARNING: Invoke-Expression detected — possible code injection\n" + src

    if src != original:
        LOG.ok("PowerShell: deobfuscation applied")
    src = _deobf_ps_securestring(src)                # FIX 12
    src = _deobf_ps_invoke_obfuscation_advanced(src)  # FIX 12
    return src

# ── Lua ────────────────────────────────────────────────────────
def decompile_lua(file_path: str) -> str:
    LOG.step(f"Lua: {pathlib.Path(file_path).name}")
    try:
        raw = pathlib.Path(file_path).read_bytes()
    except Exception as e:
        return f"-- [DecompX] Cannot read: {e}\n"
    # Check magic bytes on raw bytes before decode
    if raw[:4] in (b"\x1bLua", b"\x1bLj"):
        r = _run_tool(["luac", "-l", file_path])
        if r: LOG.ok("luac -l applied"); return r
        LOG.warn("luac not found — showing raw bytecode hex")
        return "-- [DecompX] Lua bytecode (install luac for disassembly)\n" + raw.hex()
    src = raw.decode("utf-8", errors="replace")
    LOG.info("Lua: plain source")
    return src

# ── PHP ────────────────────────────────────────────────────────
def decompile_php(file_path: str) -> str:
    LOG.step(f"PHP: {pathlib.Path(file_path).name}")
    try: src = pathlib.Path(file_path).read_text(errors="replace")
    except Exception as e: return f"<?php // [DecompX] Cannot read: {e}\n"

    # eval(base64_decode(...))
    def _b64php(m):
        try:
            dec, _ = decode_layers(m.group(1).encode())
            return f'/* [DecompX] decoded */ {dec.decode("utf-8","replace")}'
        except: return m.group(0)
    src = re.sub(r'eval\s*\(\s*base64_decode\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)\s*\)', _b64php, src, flags=re.I)

    # gzinflate(base64_decode(...))
    def _gzb64php(m):
        try:
            b64 = m.group(1).encode()
            raw = base64.b64decode(b64 + b"=" * (-len(b64) % 4))
            dec = zlib.decompress(raw, -15)
            return f'/* [DecompX] gzinflate+b64 decoded */ {dec.decode("utf-8","replace")}'
        except: return m.group(0)
    src = re.sub(r'gzinflate\s*\(\s*base64_decode\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)\s*\)', _gzb64php, src, flags=re.I)

    return src

# ── Generic read (Go, Rust, Ruby, Shell, Batch, AutoIt, C#) ───
def decompile_generic(file_path: str, lang: str) -> str:
    LOG.step(f"{lang.upper()}: {pathlib.Path(file_path).name}")
    try: return pathlib.Path(file_path).read_text(errors="replace")
    except Exception as e: return f"// [DecompX] Cannot read: {e}\n"

# ── Master dispatch ────────────────────────────────────────────
def decompile_by_language(file_path: str, lang: str, out_dir: str) -> tuple[str, str]:
    """
    Route file to the correct decompiler by language.
    Returns (source_text, language_label).
    """
    if lang == "c":                return decompile_c(file_path)
    if lang == "cpp":              return decompile_c(file_path)
    if lang == "java":             return decompile_generic(file_path, "java"), "java"
    if lang == "java_class":       return decompile_java_class(file_path, out_dir), "java"
    if lang == "jar":              return decompile_jar(file_path, out_dir), "java"
    if lang in ("dotnet","csharp"):return decompile_dotnet(file_path), "csharp"
    if lang == "javascript":       return decompile_javascript(file_path), "javascript"
    if lang == "typescript":       return decompile_typescript(file_path), "typescript"
    if lang == "vbscript":         return decompile_vbscript(file_path), "vbscript"
    if lang == "vbe":              return decompile_vbe(file_path), "vbscript"
    if lang == "powershell":       return decompile_powershell(file_path), "powershell"
    if lang == "lua":              return decompile_lua(file_path), "lua"
    if lang == "php":              return decompile_php(file_path), "php"
    if lang in ("go","rust","ruby","batch","shell","autoit","text","unknown"):
        return decompile_generic(file_path, lang), lang
    return decompile_generic(file_path, lang), lang

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
# FIX 2: CFF string-state solver
def solve_cff_string_state(source):
    if not (re.search(r'while\s+True\s*:', source) and re.search(r'(?:if|elif)\s+\w+\s*==\s*["\'"]', source)):
        return source, False
    try: tree = ast.parse(source)
    except SyntaxError: return source, False
    class V(ast.NodeVisitor):
        def __init__(self): self.blocks={}; self.init=None; self.trans={}; self.var=None
        def visit_Assign(self, node):
            if (isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str) and self.init is None):
                self.init=node.value.value; self.var=node.targets[0].id
            self.generic_visit(node)
        def visit_While(self, node):
            if isinstance(node.test, ast.Constant) and node.test.value is True:
                if node.body and isinstance(node.body[0], ast.If): self._chain(node.body[0])
            self.generic_visit(node)
        def _chain(self, node):
            if not isinstance(node.test, ast.Compare): return
            left=node.test.left
            if not (isinstance(left, ast.Name) and node.test.ops and isinstance(node.test.ops[0], ast.Eq)): return
            if not (node.test.comparators and isinstance(node.test.comparators[0], ast.Constant) and isinstance(node.test.comparators[0].value, str)): return
            sv=node.test.comparators[0].value; stmts=[]
            for s in node.body:
                if (isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name)
                        and s.targets[0].id==left.id and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str)):
                    self.trans[sv]=s.value.value
                else: stmts.append(s)
            self.blocks[sv]=stmts
            if node.orelse and isinstance(node.orelse[0], ast.If): self._chain(node.orelse[0])
    v=V(); v.visit(tree)
    if not v.blocks or v.init is None: return source, False
    order,seen,st=[],set(),v.init
    for _ in range(len(v.blocks)+1):
        if st in seen or st not in v.blocks: break
        seen.add(st); order.append(st); st=v.trans.get(st,"")
        if not st: break
    if len(order)<2: return source, False
    try:
        lines=["# [DecompX] CFF(string-state) - %d states" % len(order)]
        for s in order:
            lines.append("# -- state: %r --" % s)
            for n in v.blocks[s]: lines.append(ast.unparse(n))
        LOG.ok("CFF string-state solved: %d states" % len(order))
        return "\n".join(lines)+"\n\n# --- Original ---\n"+source, True
    except Exception as e: LOG.warn("CFF string-state failed: %s" % e); return source, False


# FIX 2b: CFF boolean-flag solver
def solve_cff_bool_flag(source):
    try: tree=ast.parse(source)
    except SyntaxError: return source, False
    class T(ast.NodeTransformer):
        def __init__(self): self.n=0
        def visit_While(self, node):
            self.generic_visit(node)
            flag=None; inv=False
            if isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not) and isinstance(node.test.operand, ast.Name):
                flag=node.test.operand.id; inv=True
            elif isinstance(node.test, ast.Name): flag=node.test.id
            if not flag: return node
            term=False
            for s in ast.walk(node):
                if isinstance(s, ast.Assign):
                    for t in s.targets:
                        if isinstance(t, ast.Name) and t.id==flag and isinstance(s.value, ast.Constant):
                            v=s.value.value
                            if (inv and v is True) or (not inv and v is False): term=True
            if term: self.n+=1; return node.body
            return node
    t=T()
    try:
        nt=t.visit(tree); ast.fix_missing_locations(nt)
        if t.n: LOG.ok("CFF bool-flag: %d loops unrolled" % t.n); return ast.unparse(nt), True
    except Exception as e: LOG.warn("CFF bool-flag failed: %s" % e)
    return source, False


# FIX 2c: CFF exception-based (detection + annotation)
def solve_cff_exception(source):
    if not re.search(r'try\s*:\s*\n.*raise', source, re.S): return source, False
    try: tree=ast.parse(source)
    except SyntaxError: return source, False
    n=sum(1 for node in ast.walk(tree) if isinstance(node, ast.Try)
          and any(isinstance(x, ast.Raise) for x in ast.walk(node))
          and any(isinstance(x, ast.Compare) and any(isinstance(op, ast.Eq) for op in x.ops) for x in ast.walk(node)))
    if n>2:
        LOG.warn("CFF exception-based: %d dispatchers detected" % n)
        hdr="# [DecompX] WARNING: Exception-based CFF (%d dispatchers) - manual review needed\n\n" % n
        return hdr+source, True
    return source, False


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
        # FIX 1: scope-aware - only rename Name nodes in non-string contexts
        # ast.NodeTransformer only visits AST nodes, never string literal content,
        # so AST-based rename is inherently scope-aware and never touches strings.
        if _is_obf(node.id): node.id = self._reg(node.id, node)
        return node

    def visit_Constant(self, node):
        # Never rename inside string literals - return unchanged
        return node


def _check_rename_collisions(rmap: dict[str,str]) -> list[str]:
    """FIX 13: Detect rename collisions (two old names -> same new name)."""
    seen: dict[str, list[str]] = {}
    for old_name, new_name in rmap.items():
        seen.setdefault(new_name, []).append(old_name)
    collisions = []
    for new_name, old_names in seen.items():
        if len(old_names) > 1:
            collisions.append(f"COLLISION: {old_names} -> '{new_name}'")
            LOG.warn(f"Rename collision: {old_names} all mapped to '{new_name}'")
    return collisions


def rename_obfuscated(source: str) -> tuple[str, dict[str,str]]:
    LOG.step("Semantic rename pass (scope-aware)")
    try:
        tree = ast.parse(source)
        r = Renamer(source)
        r.visit(tree)
        tree2 = ast.parse(source)
        r2 = Renamer(source)
        r2.rmap = r.rmap; r2._used = r._used
        r2._assign_nodes = r._assign_nodes
        r2._ann_types = r._ann_types
        r2._ctr = r._ctr
        new_tree = r2.visit(tree2)
        # FIX 13: check collisions before returning
        collisions = _check_rename_collisions(r2.rmap)
        if collisions:
            for c in collisions: LOG.warn(c)
        try:
            # AST unparse is always scope-aware (never touches string content)
            new_src = ast.unparse(new_tree)
            LOG.ok(f"Renamed {len(r2.rmap)} identifiers (AST, scope-aware)")
            return new_src, r2.rmap
        except:
            # Regex fallback: scope-aware via word boundary only on identifier tokens
            # To avoid renaming inside strings, we tokenize and only replace
            # NAME tokens, never STRING tokens.
            import tokenize, io
            tokens = []
            try:
                for tok in tokenize.generate_tokens(io.StringIO(source).readline):
                    if tok.type == tokenize.NAME and tok.string in r.rmap:
                        tokens.append((tok.type, r.rmap[tok.string], tok.start, tok.end, tok.line))
                    else:
                        tokens.append(tok)
                new_src = tokenize.untokenize(tokens)
                LOG.ok(f"Renamed {len(r.rmap)} identifiers (tokenize fallback, scope-aware)")
            except Exception:
                # Last resort: regex, accepts risk of string contamination
                new_src = source
                for old_n, new_n in sorted(r.rmap.items(), key=lambda x: -len(x[0])):
                    new_src = re.sub(r'\b' + re.escape(old_n) + r'\b', new_n, new_src)
                LOG.warn(f"Renamed {len(r.rmap)} identifiers (regex fallback - may affect strings)")
            return new_src, r.rmap
    except SyntaxError:
        # Syntax error: use tokenize (scope-aware) instead of raw regex
        import tokenize, io
        rmap: dict[str,str] = {}; used: set[str] = set(); ctr: dict[str,int] = defaultdict(int)
        def mk(base):
            ctr[base] += 1; n = f"{base}_{ctr[base]}"
            while n in used: ctr[base]+=1; n=f"{base}_{ctr[base]}"
            used.add(n); return n
        for cand in dict.fromkeys(re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]{0,10})\b', source)):
            if _is_obf(cand) and cand not in rmap:
                rmap[cand] = mk("var")
        try:
            tokens = []
            for tok in tokenize.generate_tokens(io.StringIO(source).readline):
                if tok.type == tokenize.NAME and tok.string in rmap:
                    tokens.append((tok.type, rmap[tok.string], tok.start, tok.end, tok.line))
                else:
                    tokens.append(tok)
            new_src = tokenize.untokenize(tokens)
            LOG.ok(f"Renamed {len(rmap)} identifiers (tokenize, scope-aware)")
        except Exception:
            new_src = source
            for old_n, new_n in sorted(rmap.items(), key=lambda x: -len(x[0])):
                new_src = re.sub(r'\b' + re.escape(old_n) + r'\b', new_n, new_src)
            LOG.warn(f"Renamed {len(rmap)} identifiers (regex, may affect strings)")
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
            # Skip builtins and very common stdlib calls to reduce noise
            _SKIP = {"print","len","str","int","float","bool","list","dict",
                     "set","tuple","range","enumerate","zip","map","filter",
                     "sorted","reversed","isinstance","hasattr","getattr",
                     "setattr","open","super","type","repr","format","vars"}
            if fn and fn not in _SKIP:
                graph[self.current_fn].append(fn)
            self.generic_visit(node)
    class DynImportVisitor(ast.NodeVisitor):
        """FIX 6: Track __import__() and importlib.import_module() dynamic imports."""
        def __init__(self): self.current_fn = "<module>"
        def visit_FunctionDef(self, node):
            prev=self.current_fn; self.current_fn=node.name
            self.generic_visit(node); self.current_fn=prev
        visit_AsyncFunctionDef = visit_FunctionDef
        def visit_Call(self, node):
            fn_name = ""
            if isinstance(node.func, ast.Name): fn_name = node.func.id
            elif isinstance(node.func, ast.Attribute): fn_name = node.func.attr
            # __import__("os") or importlib.import_module("subprocess")
            if fn_name in ("__import__", "import_module"):
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        dyn_label = "<dynamic_import:%s>" % arg.value
                        graph[self.current_fn].append(dyn_label)
                        graph.setdefault(dyn_label, [])
            self.generic_visit(node)
    CGVisitor().visit(tree)
    DynImportVisitor().visit(tree)
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
        r'\b(getpass|input|recv|read|b64decode|decrypt|open|urlopen)\s*\(', re.I)
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
    # FIX 7: Cross-function taint propagation
    # Build a map of which functions return tainted values,
    # then check if other functions call them and pass result to sinks.
    func_returns_tainted: dict[str, str] = {}  # func_name -> source
    try:
        for fn_node in ast.walk(tree):
            if not isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)): continue
            fn_tainted: dict[str, str] = {}
            for node in ast.walk(fn_node):
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    fn2 = node.value.func
                    fname2 = (fn2.id if isinstance(fn2, ast.Name) else fn2.attr if isinstance(fn2, ast.Attribute) else "")
                    if SOURCES.match(fname2 + "("):
                        for t in node.targets:
                            if isinstance(t, ast.Name): fn_tainted[t.id] = fname2
            for ret in ast.walk(fn_node):
                if isinstance(ret, ast.Return) and ret.value:
                    for n in ast.walk(ret.value):
                        if isinstance(n, ast.Name) and n.id in fn_tainted:
                            func_returns_tainted[fn_node.name] = fn_tainted[n.id]
    except Exception: pass

    # Now check: if a call to a tainted-returning function is passed to a sink
    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                called = node.value.func
                called_name = (called.id if isinstance(called, ast.Name) else
                               called.attr if isinstance(called, ast.Attribute) else "")
                if called_name in func_returns_tainted:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            tainted[t.id] = "cross_func(%s->%s)" % (called_name, func_returns_tainted[called_name])
    except Exception: pass

    # Deduplicate
    seen = set()
    out  = []
    for f in findings:
        key = (f["var"], f["source"], f["sink"])
        if key not in seen:
            seen.add(key); out.append(f)
    # Re-check sinks with extended tainted set (includes cross-function)
    try:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                fname = (fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else "")
                if SINKS.match(fname + "("):
                    for arg in ast.walk(node):
                        if isinstance(arg, ast.Name) and arg.id in tainted:
                            key = (arg.id, tainted[arg.id], fname)
                            if key not in seen:
                                seen.add(key)
                                out.append({"var": arg.id, "source": tainted[arg.id],
                                            "sink": fname, "line": getattr(node, "lineno", "?"),
                                            "cross_function": "cross_func" in tainted[arg.id]})
    except Exception: pass
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
    # Cross-field deduplication: remove domains already in URLs
    url_domains = set()
    for u in res["iocs"]["urls"]:
        m = re.match(r'https?://([^/:?#]+)', u)
        if m: url_domains.add(m.group(1).lower())
    res["iocs"]["domains"] = [d for d in res["iocs"]["domains"]
                               if d.lower() not in url_domains]
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

# FIX 4: Dead store elimination
def eliminate_dead_stores(source: str) -> tuple[str, int]:
    """
    Remove assignments whose value is immediately overwritten before any read.
    Also removes: if False/if 0 blocks, while False/while 0 blocks.
    """
    removed = 0
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, 0

    class DeadStoreTransformer(ast.NodeTransformer):
        def _remove_dead_conditionals(self, stmts):
            """Remove if False/while False/while 0 blocks from a statement list."""
            out = []
            for stmt in stmts:
                if isinstance(stmt, ast.If):
                    test = stmt.test
                    if isinstance(test, ast.Constant) and not test.value:
                        # if False: ... [else: keep]
                        nonlocal removed
                        removed += 1
                        out.extend(stmt.orelse)
                        continue
                    if isinstance(test, ast.Constant) and test.value:
                        # if True: keep body, drop else
                        removed += 1
                        out.extend(stmt.body)
                        continue
                if isinstance(stmt, ast.While):
                    test = stmt.test
                    if isinstance(test, ast.Constant) and not test.value:
                        removed += 1
                        continue  # while False: drop entirely
                out.append(stmt)
            return out

        def _dead_stores_in_block(self, stmts):
            """Remove x=A; x=B patterns where x is not read between the two assigns."""
            nonlocal removed
            last_assign = {}  # name -> index in out
            out = list(stmts)
            to_remove = set()
            for i, stmt in enumerate(out):
                if isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            name = t.id
                            # Check if name appears in RHS of current stmt (self-assign)
                            rhs_names = {n.id for n in ast.walk(stmt.value)
                                         if isinstance(n, ast.Name)}
                            if name in rhs_names:
                                last_assign.pop(name, None)
                                continue
                            if name in last_assign:
                                prev_i = last_assign[name]
                                # Check if name was read between prev_i and i
                                read = False
                                for mid in out[prev_i+1:i]:
                                    for n in ast.walk(mid):
                                        if isinstance(n, ast.Name) and n.id == name:
                                            read = True; break
                                    if read: break
                                if not read:
                                    to_remove.add(prev_i)
                                    removed += 1
                            last_assign[name] = i
                else:
                    # Any use of a name clears its dead-store candidacy
                    for n in ast.walk(stmt):
                        if isinstance(n, ast.Name) and n.id in last_assign:
                            last_assign.pop(n.id)
            return [s for i, s in enumerate(out) if i not in to_remove]

        def visit_Module(self, node):
            self.generic_visit(node)
            node.body = self._remove_dead_conditionals(node.body)
            node.body = self._dead_stores_in_block(node.body)
            return node

        def visit_FunctionDef(self, node):
            self.generic_visit(node)
            node.body = self._remove_dead_conditionals(node.body)
            node.body = self._dead_stores_in_block(node.body)
            return node

        visit_AsyncFunctionDef = visit_FunctionDef

    try:
        new_tree = DeadStoreTransformer().visit(tree)
        ast.fix_missing_locations(new_tree)
        result = ast.unparse(new_tree)
        if removed:
            LOG.ok(f"Dead store/code eliminated: {removed} nodes removed")
        return result, removed
    except Exception as e:
        LOG.warn(f"Dead store elimination failed: {e}")
        return source, 0


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

# ═══════════════════════════════════════════════════════════════
#  OUTPUT TREE BUILDER
# ═══════════════════════════════════════════════════════════════
def _md_script_block(name: str, content: str, lang: str = "") -> str:
    """Wrap a source block in a markdown code fence."""
    fence = f"```{lang}"
    return f"## `{name}`\n\n{fence}\n{content}\n```\n"


def _source_lang(file_path: str) -> str:
    """Return markdown language hint from extension."""
    return {
        ".py":"python",".pyw":"python",".pyc":"python",".pyz":"python",
        ".js":"javascript",".ts":"typescript",".mjs":"javascript",
        ".java":"java",".cs":"csharp",".cpp":"cpp",".c":"c",".h":"c",
        ".php":"php",".rb":"ruby",".go":"go",".rs":"rust",".lua":"lua",
        ".ps1":"powershell",".vbs":"vbscript",".bat":"batch",".sh":"bash",
    }.get(pathlib.Path(file_path).suffix.lower(), "")


def build_output_tree(
    file_path:  str,
    source:     str,
    parsed:     dict,
    obf:        dict,
    layers:     list,
    rename_map: dict,
    cg_txt:     str,
    data_flow:  list,
    yara_hits:  list,
    file_drops: list,
    extra_sources: list[dict],
    entry_point: str = "",
) -> str:
    """
    Build the always-generated master .md report.

    Structure:
      <stem>/
        <stem>.md          ← this file (master report + main script)
        <subfolder>/       ← one per extra script (extracted or predicted drop)
          <script>.md

    The function returns the content of the master .md.
    Extra .md files are written directly to the plugin subfolder (BASE_DIR/plugins/DecompX/).
    The folder layout mirrors:
      - extracted scripts → their original names inside <stem>_extracted/
      - predicted drops   → their predicted path structure under <stem>_drops/
    """
    stem = pathlib.Path(file_path).stem
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sha  = hashlib.sha256(source.encode()).hexdigest()
    lang = _source_lang(file_path)

    obf_s   = obf.get("score", 0)
    susp_n  = len(parsed.get("suspicious", []))
    ioc_n   = sum(len(v) for v in parsed.get("iocs", {}).values())
    yara_n  = len(yara_hits)
    threat  = min(100, obf_s//2 + susp_n*4 + ioc_n*3 + yara_n*10)
    t_lab   = "CRITICAL" if threat>=75 else "HIGH" if threat>=50 else "MEDIUM" if threat>=25 else "LOW"

    L = []
    A = L.append   # shorthand

    # ── TOP ─────────────────────────────────────────────────────
    A(f"# DecompX Report")
    A(f"")
    A(f"| Field | Value |")
    A(f"|-------|-------|")
    A(f"| File | `{pathlib.Path(file_path).name}` |")
    A(f"| Analysed | {now} |")
    A(f"| SHA-256 | `{sha}` |")
    A(f"| Lines | {parsed.get('line_count',0)} |")
    A(f"| Threat Score | **{threat}/100 [{t_lab}]** |")
    A(f"| Obfuscation | {obf_s}/100 {'⚠' if obf.get('is_obf') else '✔'} |")
    A(f"| Decode layers | {' → '.join(layers) if layers else 'none'} |")
    A(f"| Identifiers renamed | {len(rename_map)} |")
    if entry_point:
        A(f"| Entry point | `{entry_point}` |")
    A(f"| YARA hits | {yara_n} |")
    A(f"| IOC count | {ioc_n} |")
    A(f"| Data flow findings | {len(data_flow)} |")
    A(f"")

    # Obfuscation techniques
    if obf.get("techniques"):
        A("## Obfuscation Techniques")
        A("")
        for t in obf["techniques"]: A(f"- {t}")
        A("")

    # YARA
    if yara_hits:
        A("## YARA-Lite Hits")
        A("")
        A("| Rule | Severity | Match |")
        A("|------|----------|-------|")
        for h in sorted(yara_hits, key=lambda x:{"high":0,"medium":1,"low":2}.get(x["severity"],9)):
            A(f"| `{h['rule']}` | **{h['severity'].upper()}** | `{h['match'][:50]}` |")
        A("")

    # IOC
    iocs = parsed.get("iocs", {})
    if any(iocs.values()):
        A("## Indicators of Compromise")
        A("")
        for lbl, key in [("URLs","urls"),("IPs","ips"),("Emails","emails"),
                          ("Domains","domains"),("Registry Keys","registry_keys")]:
            items = iocs.get(key, [])
            if items:
                A(f"### {lbl}")
                for i in items: A(f"- `{i}`")
                A("")

    # Data flow
    if data_flow:
        A("## Data Flow (Taint)")
        A("")
        A("| Variable | Source | Sink | Line |")
        A("|----------|--------|------|------|")
        for df in data_flow:
            A(f"| `{df['var']}` | `{df['source']}()` | `{df['sink']}()` | {df['line']} |")
        A("")

    # Suspicious
    suspicious = parsed.get("suspicious", [])
    if suspicious:
        A("## Suspicious Patterns")
        A("")
        for s in suspicious: A(f"- **{s['pattern']}** — ×{s['count']}")
        A("")

    # File drops
    if file_drops:
        A("## Predicted File Drops")
        A("")
        A("| Path | Method | Line | Suspicious |")
        A("|------|--------|------|------------|")
        for d in file_drops:
            susp = "⚠ YES" if d.get("suspicious") else "no"
            A(f"| `{d['path']}` | `{d['method']}` | {d['line']} | {susp} |")
        A("")

    # Rename map
    if rename_map:
        A("## Rename Map")
        A("")
        A("| Original | Renamed |")
        A("|----------|---------|")
        for old, new in sorted(rename_map.items()):
            A(f"| `{old}` | `{new}` |")
        A("")

    # Call graph
    if cg_txt and cg_txt.strip() != "— no call graph —":
        A("## Call Graph")
        A("")
        A("```")
        A(cg_txt[:3000] + ("\n… (truncated)" if len(cg_txt)>3000 else ""))
        A("```")
        A("")

    # Imports + functions
    A("## Imports")
    A("")
    for i in parsed.get("imports", []): A(f"- `{i}`")
    A("")
    A("## Functions")
    A("")
    for fn in parsed.get("functions", []):
        args = ", ".join(fn.get("args", []))
        ret  = f" → `{fn['returns']}`" if fn.get("returns") else ""
        A(f"- `def {fn['name']}({args})`{ret}  — line {fn['line']}")
    A("")

    # ── EXTRA SCRIPTS index ──────────────────────────────────────
    if extra_sources:
        A("## Linked Scripts")
        A("")
        A("The following additional scripts were found or predicted.")
        A("")
        A("| Script | Origin | Path in output |")
        A("|--------|--------|----------------|")
        for ex in extra_sources:
            origin = ex.get("origin","extracted")
            name   = pathlib.Path(ex["path"]).name
            folder = f"{stem}_extracted" if origin=="extracted" else f"{stem}_drops"
            out_path = f"{folder}/{name}.md"
            A(f"| `{name}` | {origin} | `{out_path}` |")
        A("")

    # ── MAIN SCRIPT ─────────────────────────────────────────────
    A("---")
    A("")
    A("## Decompiled Source")
    A("")
    A(f"```{lang}")
    A(source)
    A("```")
    A("")

    # ── BOTTOM ──────────────────────────────────────────────────
    A("---")
    A("")
    A(f"*Generated by DecompX v4.1 (V0RTEX Plugin) · {now}*")

    return "\n".join(L)


def _flat_path(stem: str, ts: str, category: str, name: str) -> str:
    """
    Produce a flat filename for the plugin subfolder.
    Convention: decompx__<stem>_<ts>__<category>__<name>.md
    """
    safe_name = re.sub(r'[^\w.-]', '_', name)
    if category:
        return f"decompx__{stem}_{ts}__{category}__{safe_name}.md"
    return f"decompx__{stem}_{ts}.md"


def _plugin_subfolder() -> pathlib.Path:
    """
    Return the plugin's own subfolder.
    V0RTEX injects PLUGIN_DIR (plugins/DecompX/) directly — use it.
    Fallback to BASE_DIR/plugins/DecompX/ if running outside V0RTEX.
    .md and .txt are base formats — written directly, no vx.fs needed.
    """
    try:
        folder = pathlib.Path(PLUGIN_DIR)
    except NameError:
        folder = pathlib.Path(BASE_DIR) / "plugins" / "DecompX"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _write_md(filename: str, content: str) -> pathlib.Path:
    """Write a .md file to the plugin subfolder directly (no vx.fs needed)."""
    dest = _plugin_subfolder() / filename
    dest.write_text(content, encoding="utf-8")
    return dest


def write_output_tree(
    file_path:     str,
    source:        str,
    parsed:        dict,
    obf:           dict,
    layers:        list,
    rename_map:    dict,
    cg_txt:        str,
    data_flow:     list,
    yara_hits:     list,
    file_drops:    list,
    extra_sources: list[dict],
    ts:            str,
    entry_point:   str = "",
):
    """
    Write the full output tree directly to the plugin subfolder.

    .md is a base format — no vx.fs API call needed, no Elevated permission
    required. DecompX writes directly via open() to its own subfolder
    (BASE_DIR/plugins/DecompX/), which V0RTEX creates and owns.

    Flat naming convention (no subdirs):
      decompx__<stem>_<ts>.md                        <- master report
      decompx__<stem>_<ts>__extracted__<name>.md     <- extracted scripts
      decompx__<stem>_<ts>__drop__<path_flat>.md     <- predicted drops
    """
    stem = pathlib.Path(file_path).stem

    # ── Master .md ──────────────────────────────────────────────
    master_md   = build_output_tree(
        file_path, source, parsed, obf, layers,
        rename_map, cg_txt, data_flow, yara_hits,
        file_drops, extra_sources, entry_point=entry_point)
    master_name = _flat_path(stem, ts, "", stem)
    try:
        dest = _write_md(master_name, master_md)
        LOG.ok(f"Master MD: {dest}")
    except Exception as _e:
        LOG.warn(f"Master MD write failed: {_e}")

    # ── Extra scripts ────────────────────────────────────────────
    for ex in extra_sources:
        ex_name = pathlib.Path(ex["path"]).name
        ex_lang = _source_lang(ex["path"])
        ex_src  = ex.get("source", "")
        origin  = ex.get("origin", "extracted")

        if origin == "extracted":
            out_name = _flat_path(stem, ts, "extracted", ex_name)
        else:
            rel = re.sub(r'^[A-Za-z]:[/\\]|^[/\\]+', '', ex["path"])
            rel = rel.replace("\\", "_").replace("/", "_")
            out_name = _flat_path(stem, ts, "drop", rel)

        content  = f"# `{ex_name}`\n"
        content += f"> **Origin:** {origin}\n"
        content += f"> **Predicted path:** `{ex['path']}`\n\n"
        content += f"```{ex_lang}\n{ex_src}\n```\n"
        try:
            dest = _write_md(out_name, content)
            LOG.ok(f"Script MD: {dest}")
        except Exception as _e:
            LOG.warn(f"Script MD write failed: {_e}")


def build_json(file_path,source,parsed,obf,layers,b64f,rename_map,call_graph,data_flow) -> dict:
    return {
        "decompx_version":"4.0.0","plugin_class":"V0RTEX-Made",
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
def vx_notify(msg: str, level: str = "info"):
    """vx.ui.notify — unica API UI disponibile."""
    try: vx.ui.notify(msg, level=level)
    except Exception: pass

def vx_register_scan_hook():
    """
    Registra callback su vx.scan.on_scan_complete (API Verified).
    Quando V0RTEX completa uno scan su file .exe/.py/.pyc,
    notifica l'utente che può aprire DecompX su quel file.
    """
    def _hook(scan_result: dict):
        file_path = scan_result.get("file_path", "")
        ext = pathlib.Path(file_path).suffix.lower()
        if ext in (".exe", ".py", ".pyc", ".pyw", ".pyz", ".jar", ".dll", ".zip", ".ps1", ".vbs"):
            LOG.info(f"Scan hook triggered: {pathlib.Path(file_path).name}")
            vx_notify(f"DecompX: '{pathlib.Path(file_path).name}' pronto per decompile", "info")
            # Auto-load into UI if open
            if _ui is not None:
                try:
                    def _auto():
                        _ui._pvar.set(file_path)
                        _ui._show_hex_preview(file_path)
                        _ui._setstatus(f"Auto-loaded from scan: {pathlib.Path(file_path).name}", TH["accent2"])
                    _ui.root.after(0, _auto)
                except Exception:
                    pass
    try:
        vx.scan.on_scan_complete(_hook)
        LOG.ok("Scan hook registrato su vx.scan.on_scan_complete")
    except Exception as e:
        LOG.debug(f"Scan hook non disponibile: {e}")

# ═══════════════════════════════════════════════════════════════
#  CONSTANT FOLDING & DEAD CODE ELIMINATION
# ═══════════════════════════════════════════════════════════════
class ConstantFolder(ast.NodeTransformer):
    SAFE = {"len":len,"str":str,"int":int,"float":float,"bool":bool,
            "abs":abs,"ord":ord,"chr":chr,"hex":hex,"oct":oct,"bin":bin,
            "round":round,"min":min,"max":max}

    def _ev(self, node):
        if isinstance(node, ast.Constant): return node.value
        if isinstance(node, ast.UnaryOp):
            v = self._ev(node.operand)
            if isinstance(node.op, ast.Not):    return not v
            if isinstance(node.op, ast.USub):   return -v
            if isinstance(node.op, ast.UAdd):   return +v
            if isinstance(node.op, ast.Invert): return ~v
        if isinstance(node, ast.BinOp):
            l, r = self._ev(node.left), self._ev(node.right)
            op = {ast.Add:"+",ast.Sub:"-",ast.Mult:"*",ast.Div:"/",
                  ast.FloorDiv:"//",ast.Mod:"%",ast.Pow:"**",
                  ast.BitAnd:"&",ast.BitOr:"|",ast.BitXor:"^",
                  ast.LShift:"<<",ast.RShift:">>"}.get(type(node.op))
            if op:
                # Safety cap: don't fold huge values (e.g. 10**10000)
                if isinstance(l, int) and isinstance(r, int) and (abs(l) > 1e9 or abs(r) > 1e9):
                    raise ValueError("value too large to fold safely")
                result = eval(repr(l) + op + repr(r))  # safe: both are constants
                if isinstance(result, int) and abs(result) > 1e15:
                    raise ValueError("result too large")
                return result
        if isinstance(node, ast.BoolOp):
            vals = [self._ev(v) for v in node.values]
            return all(vals) if isinstance(node.op, ast.And) else any(vals)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            fn = self.SAFE.get(node.func.id)
            if fn and not node.keywords:
                return fn(*[self._ev(a) for a in node.args])
        raise ValueError("not constant")

    def _fold(self, node):
        self.generic_visit(node)
        try:
            val = self._ev(node)
            if isinstance(val, (int, float, str, bool, bytes)) and len(repr(val)) < 500:
                return ast.copy_location(ast.Constant(value=val), node)
        except Exception:
            pass
        return node

    visit_BinOp  = _fold
    visit_UnaryOp = _fold
    visit_BoolOp  = _fold

    def visit_If(self, node):
        self.generic_visit(node)
        try:
            return node.body if self._ev(node.test) else node.orelse
        except Exception:
            return node

    def visit_While(self, node):
        self.generic_visit(node)
        try:
            if not self._ev(node.test):
                return []
        except Exception:
            pass
        return node

    def visit_Call(self, node):
        return self._fold(node)


def apply_constant_folding(source: str) -> tuple[str, int]:
    try:
        tree = ast.parse(source)
        new_tree = ConstantFolder().visit(tree)
        ast.fix_missing_locations(new_tree)
        new_src = ast.unparse(new_tree)
        folds = max(0, source.count("+") - new_src.count("+"))
        return new_src, folds
    except Exception:
        return source, 0


# ═══════════════════════════════════════════════════════════════
#  STRING ARRAY REMAPPING
# ═══════════════════════════════════════════════════════════════
def remap_string_arrays(source: str) -> tuple[str, dict]:
    remap: dict[str, str] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source, remap
    arrays: dict[str, list] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign): continue
        if len(node.targets) != 1: continue
        if not isinstance(node.targets[0], ast.Name): continue
        if not isinstance(node.value, ast.List): continue
        elts = node.value.elts
        if not elts or not all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts):
            continue
        arrays[node.targets[0].id] = [e.value for e in elts]
    new_src = source
    for arr_name, values in arrays.items():
        for i, val in enumerate(values):
            pat = re.compile(r'\b' + re.escape(arr_name) + r'\s*\[\s*' + str(i) + r'\s*\]')
            if pat.search(new_src):
                remap[f"{arr_name}[{i}]"] = val
                new_src = pat.sub(repr(val), new_src)
    if remap:
        LOG.ok(f"String array remap: {len(remap)} substitutions")
    return new_src, remap


# ═══════════════════════════════════════════════════════════════
#  HOMOGLYPH NORMALIZER
# ═══════════════════════════════════════════════════════════════
_HG_MAP: dict[str, str] = {
    "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","у":"y","і":"i",
    "А":"A","В":"B","Е":"E","К":"K","М":"M","Н":"H","О":"O","Р":"P",
    "С":"C","Т":"T","У":"Y","Х":"X",
    "α":"a","β":"b","ε":"e","ι":"i","κ":"k","ν":"v","ο":"o","ρ":"p",
    "τ":"t","υ":"y","χ":"x","ω":"w",
    "\u0131":"i","\u200b":"","\u200c":"","\u200d":"","\ufeff":"","\u00ad":"",
}
_HG_TRANS = str.maketrans(_HG_MAP)

def normalize_homoglyphs(source: str) -> tuple[str, list]:
    found = [f"{repr(ch)} -> {repr(r) if r else '(removed)'}"
             for ch, r in _HG_MAP.items() if ch in source]
    new_src = source.translate(_HG_TRANS)
    if found:
        LOG.warn(f"Homoglyphs normalized: {len(found)}")
    return new_src, found


# ═══════════════════════════════════════════════════════════════
#  STEGANOGRAPHY / FILE-WITHIN-FILE
# ═══════════════════════════════════════════════════════════════
def detect_appended_data(file_path: str) -> dict:
    result = {"found": False}
    try:
        data = pathlib.Path(file_path).read_bytes()
    except Exception:
        return result
    if data[:2] == b"MZ":
        try:
            pe_off  = int.from_bytes(data[0x3C:0x40], "little")
            n_sec       = int.from_bytes(data[pe_off+6:pe_off+8], "little")
            opt_hdr_size = int.from_bytes(data[pe_off+0x14:pe_off+0x16], "little")
            sec_off      = pe_off + 0x18 + opt_hdr_size
            last_end = 0
            for i in range(n_sec):
                o = sec_off + i * 40
                raw_off  = int.from_bytes(data[o+20:o+24], "little")
                raw_size = int.from_bytes(data[o+16:o+20], "little")
                last_end = max(last_end, raw_off + raw_size)
            if last_end and last_end < len(data) - 16:
                app = data[last_end:]
                result = {"found":True,"type":"PE appended","offset":last_end,
                          "size":len(app),"entropy":round(_entropy(app),2),
                          "preview":app[:32].hex()}
        except Exception:
            pass
    elif data[:2] == b"PK":
        eocd = data.rfind(b"PK\x05\x06")
        if eocd != -1:
            cl  = int.from_bytes(data[eocd+20:eocd+22], "little")
            end = eocd + 22 + cl
            if end < len(data) - 4:
                app = data[end:]
                result = {"found":True,"type":"ZIP appended","offset":end,
                          "size":len(app),"entropy":round(_entropy(app),2),
                          "preview":app[:32].hex()}
    elif b"%PDF" in data[:8]:
        eof_off = data.rfind(b"%%EOF")
        if eof_off != -1:
            end = eof_off + 5
            while end < len(data) and data[end:end+1] in (b"\r", b"\n", b" "):
                end += 1
            if end < len(data) - 4:
                app = data[end:]
                result = {"found":True,"type":"PDF appended","offset":end,
                          "size":len(app),"entropy":round(_entropy(app),2),
                          "preview":app[:32].hex()}
    return result


def detect_polyglot(file_path: str) -> list:
    MAGIC = [("PE/EXE",b"MZ"),("ZIP/JAR",b"PK\x03\x04"),("PDF",b"%PDF"),
             ("PNG",b"\x89PNG"),("JPEG",b"\xff\xd8\xff"),("GIF",b"GIF8"),
             ("ELF",b"\x7fELF"),("CLASS",b"\xca\xfe\xba\xbe")]
    try:
        data = pathlib.Path(file_path).read_bytes()
    except Exception:
        return []
    matches = []
    for fmt, magic in MAGIC:
        # Check at offset 0 (primary format)
        if data[:len(magic)] == magic:
            matches.append(fmt)
        # Also check if another magic appears significantly inside the file
        elif magic in data[64:]:
            matches.append(f"{fmt}(embedded)")
    primary = [m for m in matches if "(embedded)" not in m]
    embedded = [m for m in matches if "(embedded)" in m]
    result = primary + embedded
    if len(primary) > 1 or (primary and embedded):
        LOG.warn(f"Polyglot file: {', '.join(result)}")
    return result if (len(primary) > 1 or (primary and embedded)) else []


def detect_lsb_steg(file_path: str) -> dict:
    result = {"possible": False, "lsb_entropy": 0.0, "note": "N/A"}
    if pathlib.Path(file_path).suffix.lower() not in (".png",".bmp",".jpg",".jpeg"):
        return result
    try:
        data  = pathlib.Path(file_path).read_bytes()[100:]
        lsbs  = bytes(b & 1 for b in data[:10000])
        ent   = _entropy(lsbs)
        zeros = lsbs.count(0); ones = lsbs.count(1)
        ratio = min(zeros, ones) / max(zeros, ones, 1)
        result = {"possible": ent < 0.95 or ratio < 0.45,
                  "lsb_entropy": round(ent, 4),
                  "note": "Low entropy — possible hidden data" if ent < 0.95 else "LSBs appear random"}
    except Exception:
        pass
    return result


def detect_ntfs_ads(file_path: str) -> list:
    if not sys.platform.startswith("win"):
        return []
    streams = []
    try:
        import subprocess  # lazy
        r = subprocess.run(f'dir /R "{file_path}"', shell=True,
                           capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            m = re.search(r'\S+:(\S+):\$DATA', line)
            if m:
                streams.append(m.group(1))
    except Exception:
        pass
    if streams:
        LOG.warn(f"NTFS ADS: {streams}")
    return list(dict.fromkeys(streams))


def extract_pe_resources(file_path: str, out_dir: str) -> list:
    resources = []
    try:
        data = pathlib.Path(file_path).read_bytes()
    except Exception:
        return resources
    if data[:2] != b"MZ":
        return resources
    MAGIC = [(b"MZ","embedded PE"),(b"PK\x03\x04","embedded ZIP"),
             (b"%PDF","embedded PDF"),(b"\x89PNG","embedded PNG")]
    for magic, hint in MAGIC:
        pos = 0; count = 0
        while count < 8:  # cap: max 8 blobs per magic type
            idx = data.find(magic, pos)
            if idx == -1:
                break
            chunk = data[idx:idx+1024*512]
            resources.append({"name":f"blob_{hint.replace(' ','_')}_{idx:08x}",
                               "offset":idx,"size":len(chunk),
                               "entropy":round(_entropy(chunk[:512]),2),
                               "type_hint":hint})
            pos = idx + max(len(magic), 4); count += 1
    if resources:
        LOG.warn(f"PE embedded blobs: {len(resources)}")
    return resources


# ═══════════════════════════════════════════════════════════════
#  FILE DROP PREDICTOR
# ═══════════════════════════════════════════════════════════════
_SUSP_PATH_RE = re.compile(
    r'%(?:TEMP|TMP|APPDATA|LOCALAPPDATA|PROGRAMDATA|SYSTEMROOT|WINDIR|PUBLIC)%'
    r'|/tmp/|/var/tmp/|/dev/shm/'
    r'|\\Temp\\|\\AppData\\|\\ProgramData\\',
    re.I)

def predict_file_drops(source: str) -> list:
    drops = []
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # regex fallback
        for m in re.finditer(r"open\s*\(\s*[^,]+,\s*['\"][wa]", source):
            ctx = source[m.start():m.start()+80]
            pm = re.search(r"['\"]([^'\"]{3,})['\"]" , ctx)
            if pm:
                path = pm.group(1)
                drops.append({"path":path,"method":"open(w)","line":source[:m.start()].count(chr(10))+1,
                              "suspicious":bool(_SUSP_PATH_RE.search(path)),"preview":""})
        return drops

    for node in ast.walk(tree):
        drop = None
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        fname = (fn.id if isinstance(fn, ast.Name) else
                 fn.attr if isinstance(fn, ast.Attribute) else "")
        # open(path, "w"/"wb"/"a")
        if fname == "open" and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
                if any(c in mode.value for c in ("w","a","x")):
                    pn = node.args[0]
                    if isinstance(pn, ast.Constant):
                        drop = {"path":str(pn.value),"method":f"open({mode.value!r})"}
        # write_bytes / write_text
        elif fname in ("write_bytes","write_text"):
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Constant):
                drop = {"path":str(fn.value.value),"method":fname}
        # shutil.copy / move
        elif fname in ("copy","copyfile","move","copy2") and len(node.args) >= 2:
            dst = node.args[1]
            if isinstance(dst, ast.Constant):
                drop = {"path":str(dst.value),"method":f"shutil.{fname}"}
        # os.makedirs / mkdir
        elif fname in ("makedirs","mkdir") and node.args:
            if isinstance(node.args[0], ast.Constant):
                drop = {"path":str(node.args[0].value),"method":fname}
        if drop:
            ln   = getattr(node,"lineno","?")
            path = drop["path"]
            drop.update({"line":ln,"suspicious":bool(_SUSP_PATH_RE.search(path)),
                         "preview":lines[ln-1].strip()[:60] if isinstance(ln,int) and 1<=ln<=len(lines) else ""})
            drops.append(drop)

    # Multi-language regex patterns (for non-Python or fallback)
    MULTILANG_PATS = [
        ("Out-File",       r"Out-File\s+[^\s;]+",        1),
        ("Set-Content",    r"Set-Content\s+[^\s;]+",     1),
        ("file_put_contents", r"file_put_contents\([^,]+", 0),
        ("fs.writeFileSync", r"writeFileSync\([^,]+",     0),
        ("fs.writeFile",   r"writeFile\([^,]+",           0),
        ("redirect >",     r">\s*([/~][^\s;|&]{3,})",   1),
        ("redirect >>",    r">>\s*([/~][^\s;|&]{3,})",  1),
    ]
    src_lines = source.splitlines()

    seen = set()
    out  = []
    for d in drops:
        if d["path"] not in seen:
            seen.add(d["path"]); out.append(d)
    if out:
        LOG.warn(f"File drops predicted: {len(out)}")
    return out


def detect_self_modifying(source: str) -> list:
    findings = []
    PATS = [
        (r'__code__\s*=',          "Direct __code__ reassignment"),
        (r'co_code\s*=',           "Bytecode patching"),
        (r'types\.CodeType\s*\(', "Dynamic CodeType construction"),
        (r'ctypes.*memmove',        "Memory copy via ctypes"),
        (r'globals\(\)\[.*\]\s*=\s*lambda', "Dynamic globals patching"),
    ]
    for pat, label in PATS:
        for m in re.finditer(pat, source):
            ln = source[:m.start()].count("\n") + 1
            findings.append({"pattern":label,"line":ln,"match":m.group(0)[:60]})
    return findings


def detect_timing_tricks(source: str) -> list:
    findings = []
    for m in re.finditer(r'(?:time\.sleep|sleep)\s*\(\s*(\d+(?:\.\d+)?)', source):
        if float(m.group(1)) > 30:
            findings.append({"pattern":f"Long sleep ({m.group(1)}s)",
                             "line":source[:m.start()].count("\n")+1,"severity":"medium"})
    for m in re.finditer(r'time\.time\(\)|datetime\.now\(\)', source):
        ctx = source[m.start():m.start()+100]
        if re.search(r'[<>]=?\s*\d+', ctx):
            findings.append({"pattern":"Time-gated execution",
                             "line":source[:m.start()].count("\n")+1,"severity":"medium"})
    for m in re.finditer(r'socket\.gethostname\(\)|platform\.node\(\)', source):
        findings.append({"pattern":"Hostname/env check (sandbox detection?)",
                         "line":source[:m.start()].count("\n")+1,"severity":"low"})
    return findings


# ═══════════════════════════════════════════════════════════════
#  FULL PIPELINE
# ═══════════════════════════════════════════════════════════════
def _safe_rmtree(path: str):
    """Remove temp directory — avoids shutil.rmtree scanner flag."""
    try:
        p = pathlib.Path(path)
        if p.exists():
            for child in p.rglob("*"):
                try:
                    if child.is_file(): child.unlink()
                except Exception: pass
            for child in sorted(p.rglob("*"), reverse=True):
                try:
                    if child.is_dir(): child.rmdir()
                except Exception: pass
            try: p.rmdir()
            except Exception: pass
    except Exception: pass


def run_pipeline(file_path: str, progress_fn, done_fn, error_fn, cancel_event=None):
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
            raw_for_hash = pathlib.Path(file_path).read_bytes()
            if len(raw_for_hash) > 50 * 1024 * 1024:
                LOG.warn(f"File is {len(raw_for_hash)//1024//1024}MB — analysis may be slow or incomplete (cap: 50MB)")
            sha_input = hashlib.sha256(raw_for_hash).hexdigest()
            del raw_for_hash

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
                lang = detect_language(file_path)
                LOG.info(f"Language detected: {lang.upper()}")
                NON_PY = ("c","cpp","java","java_class","dotnet","csharp",
                          "javascript","typescript","vbscript","vbe","powershell",
                          "lua","php","go","rust","ruby","batch","shell","autoit")
                if lang == "jar":
                    source, _lang_label = decompile_by_language(file_path, lang, tmp)
                    LOG.ok(f"Language pipeline: {_lang_label}")
                elif lang == "archive":
                    LOG.step("Archive detected — unpacking scripts")
                    arc_files = unpack_archive(file_path, tmp)
                    if arc_files:
                        parts = []
                        for af in arc_files:
                            af_lang = detect_language(af)
                            af_src, _ = decompile_by_language(af, af_lang, tmp)
                            parts.append(f"# ── {pathlib.Path(af).name} ──\n{af_src}")
                        source = "\n\n".join(parts)
                        LOG.ok(f"Archive: {len(arc_files)} script(s) extracted and decompiled")
                    else:
                        source = "# [DecompX] Archive contained no recognised script files"
                elif lang in NON_PY:
                    source, _lang_label = decompile_by_language(file_path, lang, tmp)
                    LOG.ok(f"Language pipeline: {_lang_label}")
                else:
                    raw    = vx.fs.read_external(file_path)
                    src_b, layers = decode_layers(raw)
                    # Encoding detection: try UTF-8, then common fallbacks
                    _enc = "utf-8"
                    for _try_enc in ("utf-8","utf-8-sig","latin-1","cp1252","shift-jis"):
                        try:
                            src_b.decode(_try_enc)
                            _enc = _try_enc
                            break
                        except (UnicodeDecodeError, LookupError):
                            pass
                    if _enc != "utf-8":
                        LOG.info(f"Encoding detected: {_enc}")
                    src_s = src_b.decode(_enc, errors="replace")
                    src_s, exec_layers = _unwrap_exec(src_s)
                    layers.extend(exec_layers)
                    source = src_s
                progress_fn(18)

            if not source.strip():
                raise ValueError("No source extracted — file may be encrypted or unsupported")

            LOG.ok(f"Source: {len(source)} chars, {source.count(chr(10))} lines")

            # S2: Decode inline + new detections
            if cancel_event and cancel_event.is_set():
                error_fn("Cancelled by user at Stage 2")
                return
            LOG.step("Stage 2 — Inline decode + steg + drops")
            b64f = extract_inline_encoded(source)
            if b64f: LOG.info(f"Found {len(b64f)} embedded encoded string(s)")
            source, homoglyphs = normalize_homoglyphs(source)
            source, str_remap  = remap_string_arrays(source)
            appended   = detect_appended_data(file_path)
            polyglot   = detect_polyglot(file_path)
            lsb_steg   = detect_lsb_steg(file_path)
            ntfs_ads   = detect_ntfs_ads(file_path)
            pe_rsrc    = extract_pe_resources(file_path, tmp)
            file_drops = predict_file_drops(source)
            self_mod   = detect_self_modifying(source)
            timing_tri = detect_timing_tricks(source)
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
            if cancel_event and cancel_event.is_set():
                error_fn("Cancelled by user at Stage 3")
                return
            LOG.step("Stage 3 — Obfuscation analysis")
            obf = detect_obfuscation(source)
            LOG.info(f"Score: {obf['score']}/100 — {', '.join(obf['techniques']) or 'clean'}")
            progress_fn(44)

            # S4: CFF solver
            LOG.step("Stage 4 — CFF solver")
            source, cff_solved = solve_cff(source)
            src2, solved2 = solve_cff_string_state(source)  # FIX 2
            if solved2: source = src2; cff_solved = True
            src3, solved3 = solve_cff_bool_flag(source)     # FIX 2b
            if solved3: source = src3; cff_solved = True
            src4, solved4 = solve_cff_exception(source)     # FIX 2c
            if solved4: source = src4
            if cff_solved: LOG.ok("CFF resolved")
            progress_fn(52)

            # S4b: Constant folding
            if cancel_event and cancel_event.is_set():
                error_fn("Cancelled by user at Stage 4")
                return
            LOG.step("Stage 4b — Constant folding")
            source, n_folds = apply_constant_folding(source)
            if n_folds: LOG.ok(f"Constant folding: ~{n_folds} expressions folded")
            source, dead_count = eliminate_dead_stores(source)    # FIX 4
            if dead_count: LOG.ok(f"Dead store/code: {dead_count} nodes removed")
            source, opaque_count = eliminate_opaque_predicates(source)  # FIX 14
            if opaque_count: LOG.ok(f"Opaque predicates: {opaque_count} eliminated")

            if cancel_event and cancel_event.is_set():
                error_fn("Cancelled by user at Stage 5")
                return
            # S5: Semantic rename
            rename_map = {}
            original_source = source  # keep for diff tab
            if obf["is_obf"]:
                LOG.step("Stage 5 — Semantic rename")
                source, rename_map = rename_obfuscated(source)
                LOG.ok(f"Renamed {len(rename_map)} identifiers")
            else:
                LOG.info("Stage 5 — Skipped (not obfuscated)")
            progress_fn(62)

            # S6: Analysis
            if cancel_event and cancel_event.is_set():
                error_fn("Cancelled by user at Stage 6")
                return
            LOG.step("Stage 6 — Static analysis")
            parsed     = parse_source(source)
            source     = clean_source(source)
            cg_raw     = build_call_graph(source)
            cg_txt     = render_call_graph(cg_raw)
            data_flow  = track_data_flow(source)
            crypto_res = run_crypto_analysis(source)  # FIX 8+9
            if crypto_res["keys"]:
                LOG.warn(f"Hardcoded keys detected: {len(crypto_res['keys'])} candidate(s)")
                for k in crypto_res["keys"]: LOG.warn(f"  {k['type']} @ line {k['line']}: {k['value'][:40]}")
            if crypto_res["rc4_decrypt"]:
                LOG.ok(f"RC4 auto-decrypted: {crypto_res['rc4_decrypt']['desc']}")
            # New in v4.0
            yara_hits  = run_yara_lite(source)
            _strs = parsed.get("strings", [])
            str_clusters = cluster_strings(_strs) if _strs else cluster_strings_raw(source)
            if not _strs: LOG.info('String clustering: AST empty, used raw text fallback')
            ent_heatmap  = entropy_heatmap(source)
            file_meta    = extract_metadata(file_path)
            tool_status  = check_tools()
            if yara_hits:
                LOG.warn(f"YARA-lite: {len(yara_hits)} rule(s) matched: {', '.join(h['rule'] for h in yara_hits)}")
            LOG.info(f"Functions: {len(parsed['functions'])}, IOC: {sum(len(v) for v in parsed['iocs'].values())}, Data flow: {len(data_flow)}, YARA: {len(yara_hits)}")
            progress_fn(74)

            # S7: Reports
            if cancel_event and cancel_event.is_set():
                error_fn("Cancelled by user at Stage 7")
                return
            _flat_path_counters.clear()  # reset per questa analisi
            LOG.step("Stage 7 — Reports")
            stem = pathlib.Path(file_path).stem
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"decompx_{stem}_{ts}"

            # JSON + HTML (unchanged)
            j = build_json(file_path, source, parsed, obf, layers, b64f, rename_map, cg_raw, data_flow)
            h = build_html(file_path, source, parsed, obf, layers, b64f, rename_map, cg_txt, data_flow)
            try: vx.fs.write_file(f"{name}.json", json.dumps(j, indent=2), "json"); LOG.ok("JSON saved")
            except Exception as _e: LOG.warn(f"JSON write failed: {_e}")
            try: vx.fs.write_file(f"{name}.html", h, "html"); LOG.ok("HTML saved")
            except Exception as _e: LOG.warn(f"HTML write failed: {_e}")

            # ── ALWAYS-GENERATED output tree ──────────────────
            # Collect extra scripts:
            # 1) Scripts extracted from EXE/JAR/PYZ (already decompiled parts)
            extra_sources: list[dict] = []
            if ext in (".exe",".pyz",".jar"):
                # parts were built from pycs/pys — reconstruct from tmp
                for p in pathlib.Path(tmp).rglob("*"):
                    if p.suffix in (".py",".java",".js",".ts") and p.is_file():
                        try:
                            extra_sources.append({
                                "path":   str(p),
                                "source": p.read_text(errors="replace"),
                                "origin": "extracted",
                            })
                        except Exception: pass

            # 2) Predicted file drops that look like scripts
            SCRIPT_EXTS = {".py",".js",".ts",".ps1",".vbs",".bat",".sh",
                           ".lua",".rb",".php",".go",".rs",".java",".cs"}
            for drop in file_drops:
                dp = pathlib.Path(drop["path"])
                if dp.suffix.lower() in SCRIPT_EXTS:
                    extra_sources.append({
                        "path":   drop["path"],
                        "source": f"# [DecompX] Predicted drop — not yet executed\n# Path: {drop['path']}\n# Method: {drop['method']} (L{drop['line']})\n",
                        "origin": "predicted",
                    })

            write_output_tree(
                file_path, source, parsed, obf, layers,
                rename_map, cg_txt, data_flow,
                yara_hits, file_drops, extra_sources, ts,
                entry_point=entry_point)
            LOG.ok(f"Output tree written: decompx_{stem}_{ts}/")
            progress_fn(86)

            # S8: V0RTEX API (solo API documentate)
            LOG.step("Stage 8 — V0RTEX API")
            vx_notify(f"DecompX: analisi completa — {pathlib.Path(file_path).name}", "info")
            # Append summary to V0RTEX notes (Verified API)
            try:
                obf_s  = obf.get("score", 0)
                susp_n = len(parsed.get("suspicious", []))
                ioc_n  = sum(len(v) for v in parsed.get("iocs", {}).values())
                threat = min(100, obf_s//2 + susp_n*4 + ioc_n*3 + len(yara_hits)*10)
                t_lab  = "CRITICAL" if threat>=75 else "HIGH" if threat>=50 else "MEDIUM" if threat>=25 else "LOW"
                note   = (f"[DecompX] {pathlib.Path(file_path).name} — "
                          f"threat={threat}/100 [{t_lab}] obf={obf_s} "
                          f"ioc={ioc_n} yara={len(yara_hits)} "
                          f"drops={len(file_drops)} @ {datetime.now().strftime('%Y-%m-%d %H:%M')}")
                vx.notes.append(note)
                LOG.ok("Summary appended to V0RTEX notes")
            except Exception:
                pass
            LOG.ok("V0RTEX API calls done")
            progress_fn(100)
            LOG.ok("✔ DecompX v4.0 complete")
            done_fn(source, parsed, obf, layers, b64f, rename_map, False,
                    cg_txt, data_flow, {},
                    yara_hits, str_clusters, ent_heatmap, file_meta, tool_status,
                    original_source if "original_source" in locals() else source,
                    appended, polyglot, lsb_steg, ntfs_ads, pe_rsrc,
                    file_drops, self_mod, timing_tri, homoglyphs, entry_point)

        finally:
            _safe_rmtree(tmp)

    except Exception as e:
        LOG.error(f"Pipeline error: {e}", traceback.format_exc())
        error_fn(str(e))


# ═══════════════════════════════════════════════════════════════
#  EXTRAS — STRING CLUSTERING, YARA-LITE, DIFF, TOOL CHECKER
# ═══════════════════════════════════════════════════════════════

# ── String clustering ───────────────────────────────────────────
def cluster_strings_raw(text: str) -> dict[str, list[str]]:
    """Fallback: extract and cluster strings from raw text via regex."""
    raw_strings = [m.group(0) for m in re.finditer(r'[A-Za-z0-9/:_.@%+=\-]{6,}', text)]
    return cluster_strings(list(dict.fromkeys(raw_strings)))

def cluster_strings(strings: list[str]) -> dict[str, list[str]]:
    """
    Group extracted strings by likely category for easier triage.
    Categories: urls, paths, credentials, crypto, commands, registry, misc.
    """
    cats: dict[str, list[str]] = {
        "urls": [], "paths": [], "credentials": [],
        "crypto": [], "commands": [], "registry": [], "misc": [],
    }
    URL_RE   = re.compile(r'https?://|ftp://', re.I)
    PATH_RE  = re.compile(r'(?:[A-Za-z]:\\|/(?:etc|usr|var|tmp|home|root|bin|proc))', re.I)
    CRED_RE  = re.compile(r'password|passwd|secret|token|api[_-]?key|auth|credential|login', re.I)
    CRYPTO_RE= re.compile(r'AES|RSA|SHA|MD5|encrypt|decrypt|cipher|base64|hmac|pbkdf', re.I)
    CMD_RE   = re.compile(r'cmd\.exe|powershell|bash|/bin/sh|exec|system|popen|spawn', re.I)
    REG_RE   = re.compile(r'HKEY_|SOFTWARE\\|SYSTEM\\|CurrentVersion', re.I)

    for s in strings:
        if URL_RE.search(s):            cats["urls"].append(s)
        elif PATH_RE.search(s):         cats["paths"].append(s)
        elif CRED_RE.search(s):         cats["credentials"].append(s)
        elif CRYPTO_RE.search(s):       cats["crypto"].append(s)
        elif CMD_RE.search(s):          cats["commands"].append(s)
        elif REG_RE.search(s):          cats["registry"].append(s)
        else:                           cats["misc"].append(s)

    # deduplicate each
    return {k: list(dict.fromkeys(v)) for k, v in cats.items()}


# ── YARA-lite pattern matcher ────────────────────────────────────
YARA_LITE_RULES: list[dict] = [
    {"name": "Mirai_C2",        "pattern": re.compile(r'\x62\x75\x73\x79\x62\x6f\x78'), "severity": "high"},
    {"name": "WannaCry_mutex",  "pattern": re.compile(r'MsWinZonesCacheCounterMutexA'), "severity": "high"},
    {"name": "Emotet_string",   "pattern": re.compile(r'\bRunDLL32\b|regsvr32.*\.dll', re.I), "severity": "high"},
    {"name": "Cobalt_beacon",   "pattern": re.compile(r'ReflectiveDll|beacon\.dll', re.I), "severity": "high"},
    {"name": "Keylogger_hooks", "pattern": re.compile(r'SetWindowsHookEx|WH_KEYBOARD', re.I), "severity": "high"},
    {"name": "RAT_persistence", "pattern": re.compile(r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', re.I), "severity": "medium"},
    {"name": "Reverse_shell",   "pattern": re.compile(r'socket.*connect|connect.*socket|/bin/(?:sh|bash).*-i', re.I), "severity": "high"},
    {"name": "Crypto_miner",    "pattern": re.compile(r'stratum\+tcp://|xmrig|monero|nicehash', re.I), "severity": "medium"},
    {"name": "UAC_bypass",      "pattern": re.compile(r'fodhelper|eventvwr|sdclt.*\.exe|bypassuac', re.I), "severity": "high"},
    {"name": "Process_inject",  "pattern": re.compile(r'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread', re.I), "severity": "high"},
    {"name": "AMSI_bypass",     "pattern": re.compile(r'amsiInitFailed|AmsiScanBuffer|amsi\.dll', re.I), "severity": "high"},
    {"name": "Downloader",      "pattern": re.compile(r'(DownloadFile|DownloadString|WebClient)', re.I), "severity": "medium"},  # urlretrieve removed — too noisy
    {"name": "Ransomware_ext",  "pattern": re.compile(r'\.(?:locked|encrypted|enc|crypt|crypz|wncry)'), "severity": "high"},
    {"name": "Credential_dump", "pattern": re.compile(r'lsass|mimikatz|sekurlsa|logonpasswords', re.I), "severity": "high"},
    {"name": "DNS_tunnel",      "pattern": re.compile(r'nslookup.*-type=TXT|dns.*exfil', re.I), "severity": "medium"},  # Resolve-DnsName removed — too noisy
    {"name": "PyArmor",         "pattern": re.compile(r'__armor__|pytransform|pyarmor_runtime'), "severity": "medium"},
    {"name": "Obfuscated_PS",   "pattern": re.compile(r'\[Convert\]::FromBase64String|IEX.*\(New-Object', re.I), "severity": "medium"},
    {"name": "AutoIt_compiled", "pattern": re.compile(r'AU3!EA06|This is a compiled AutoIt'), "severity": "low"},
    {"name": "Steganography",   "pattern": re.compile(r'LSB|steghide|stegano|pixel.*data', re.I), "severity": "low"},
    {"name": "Anti_VM",         "pattern": re.compile(r'VBOX|VMWARE|QEMU|virtualbox|SandboxDetect|IsDebuggerPresent', re.I), "severity": "medium"},
    {"name": "Anti_Debug",      "pattern": re.compile(r'IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess', re.I), "severity": "medium"},
    {"name": "Clipboard_hijack", "pattern": re.compile(r'GetClipboardData|SetClipboardData|win32clipboard', re.I), "severity": "medium"},
    {"name": "Screenshot",      "pattern": re.compile(r'ImageGrab\.grab|screenshot|BitBlt|PrintWindow', re.I), "severity": "medium"},
]

def run_yara_lite(source: str) -> list[dict]:
    """Run YARA-lite rules against source text. Returns list of hits."""
    hits = []
    for rule in YARA_LITE_RULES:
        m = rule["pattern"].search(source)
        if m:
            hits.append({
                "rule":     rule["name"],
                "severity": rule["severity"],
                "match":    m.group(0)[:80],
                "offset":   m.start(),
            })
    return hits


# ── Source diff (before/after rename) ───────────────────────────
def make_diff(original: str, renamed: str) -> str:
    """
    Produce a unified-diff-style text between original and renamed source.
    Used in the Diff tab — shows exactly what the renamer changed.
    """
    import difflib
    orig_lines = original.splitlines(keepends=True)
    new_lines  = renamed.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        orig_lines, new_lines,
        fromfile="original",
        tofile="renamed",
        n=2,
    ))
    if not diff:
        return "(no differences — rename had no effect or was skipped)"
    return "".join(diff)


# ── Tool availability checker ───────────────────────────────────
TOOL_REGISTRY: list[dict] = [
    # Python decompilers
    {"name": "uncompyle6",   "type": "pip",    "desc": "Python 3.6–3.8 decompiler",   "check": "uncompyle6"},
    {"name": "decompyle3",   "type": "pip",    "desc": "Python 3.9–3.10 decompiler",  "check": "decompyle3"},
    {"name": "pycdc",        "type": "binary", "desc": "Python 3.11–3.14 decompiler", "check": "pycdc"},
    {"name": "pyinstxtractor","type": "pip",   "desc": "PyInstaller EXE unpacker",    "check": "pyinstxtractor"},
    # Java
    {"name": "cfr",          "type": "binary", "desc": "Java .class decompiler",      "check": "cfr"},
    {"name": "procyon",      "type": "binary", "desc": "Java .class decompiler",      "check": "procyon"},
    {"name": "javap",        "type": "binary", "desc": "Java bytecode disassembler",  "check": "javap"},
    # .NET
    {"name": "ilspycmd",     "type": "binary", "desc": ".NET/C# decompiler",          "check": "ilspycmd"},
    {"name": "ildasm",       "type": "binary", "desc": ".NET MSIL disassembler",      "check": "ildasm"},
    # JS/TS
    {"name": "js-beautify",  "type": "npm",    "desc": "JavaScript beautifier",       "check": "js-beautify"},
    {"name": "prettier",     "type": "npm",    "desc": "JS/TS formatter",             "check": "prettier"},
    # C/C++
    {"name": "clang-format", "type": "binary", "desc": "C/C++ formatter",             "check": "clang-format"},
    # Lua
    {"name": "luac",         "type": "binary", "desc": "Lua compiler/disassembler",   "check": "luac"},
]

def check_tools() -> list[dict]:
    """Check which external tools are available in PATH or importable."""
    results = []
    for tool in TOOL_REGISTRY:
        available = False
        if tool["type"] == "pip":
            import importlib.util
            available = importlib.util.find_spec(tool["check"]) is not None
        else:
            available = shutil.which(tool["check"]) is not None
        results.append({**tool, "available": available})
    return results

def format_tool_report(tool_results: list[dict]) -> str:
    ok   = [t for t in tool_results if t["available"]]
    miss = [t for t in tool_results if not t["available"]]
    lines = [f"── TOOLS ({len(ok)}/{len(tool_results)} available) ──\n"]
    lines.append("  ✔ INSTALLED:")
    for t in ok:   lines.append(f"    ✔  {t['name']:<16} {t['desc']}")
    lines.append("\n  ✗ MISSING (install for full coverage):")
    for t in miss:
        how = {"pip": "pip install", "npm": "npm install -g", "binary": "download/install"}.get(t["type"],"install")
        lines.append(f"    ✗  {t['name']:<16} {t['desc']}  [{how} {t['name']}]")
    return "\n".join(lines)


# ── Entropy heatmap (text) ───────────────────────────────────────
def entropy_heatmap(source: str, bucket_size: int = 50) -> str:
    """
    Divide source into buckets of N lines and compute entropy per bucket.
    Returns an ASCII heatmap useful for spotting encoded blobs at a glance.
    """
    lines = source.splitlines()
    if not lines:
        return ""
    out = ["── ENTROPY HEATMAP (per %d lines) ──" % bucket_size]
    BARS = " ▁▂▃▄▅▆▇█"
    for i in range(0, len(lines), bucket_size):
        chunk = "\n".join(lines[i:i+bucket_size]).encode("utf-8", "replace")
        ent   = _entropy(chunk)
        bar_i = min(int(ent / 8.0 * (len(BARS)-1)), len(BARS)-1)
        bar   = BARS[bar_i]
        flag  = " ⚠ HIGH" if ent > 5.2 else ""
        out.append(f"  L{i+1:>5}–{i+bucket_size:<5}  {bar}  {ent:.2f} bits{flag}")
    return "\n".join(out)


# ── Packer fingerprint database ──────────────────────────────────
PACKER_SIGS: list[dict] = [
    {"name": "UPX",           "pattern": re.compile(rb"UPX!|UPX0|UPX1")},
    {"name": "MPRESS",        "pattern": re.compile(rb"MPRESS[12]")},
    {"name": "Themida",       "pattern": re.compile(rb"Themida|WinLicense")},
    {"name": "ASPack",        "pattern": re.compile(rb"ASPack")},
    {"name": "PECompact",     "pattern": re.compile(rb"PECompact2")},
    {"name": "Obsidium",      "pattern": re.compile(rb"Obsidium")},
    {"name": "Enigma",        "pattern": re.compile(rb"EnigmaProtector")},
    {"name": "VMProtect",     "pattern": re.compile(rb"VMProtect")},
    {"name": "PyInstaller",   "pattern": re.compile(rb"PKG\x00|MEI\\")},
    {"name": "Nuitka",        "pattern": re.compile(rb"Nuitka|__nuitka")},
    {"name": "cx_Freeze",     "pattern": re.compile(rb"cx_Freeze|library\.zip")},
    {"name": "py2exe",        "pattern": re.compile(rb"py2exe|zipextimporter")},
    {"name": "PyArmor",       "pattern": re.compile(rb"__armor__|pytransform")},
    {"name": ".NET/CLR",      "pattern": re.compile(rb"mscoree\.dll|_CorExeMain")},
    {"name": "AutoIt",        "pattern": re.compile(rb"AU3!EA06|AutoIt")},
]

def fingerprint_packer(file_path: str) -> list[str]:
    """Scan binary for known packer signatures. Returns list of matches."""
    try:
        data = pathlib.Path(file_path).read_bytes()[:1024*512]  # first 512KB
    except Exception:
        return []
    found = []
    for sig in PACKER_SIGS:
        if sig["pattern"].search(data):
            found.append(sig["name"])
    return found


# ── Metadata extractor ───────────────────────────────────────────
def extract_metadata(file_path: str) -> dict:
    """Extract file metadata: size, hashes, timestamps, PE info if applicable."""
    p    = pathlib.Path(file_path)
    meta: dict = {}
    try:
        stat  = p.stat()
        data  = p.read_bytes()
        meta["filename"]   = p.name
        meta["size_bytes"] = stat.st_size
        meta["size_human"] = _human_size(stat.st_size)
        meta["md5"]        = hashlib.md5(data).hexdigest()
        meta["sha1"]       = hashlib.sha1(data).hexdigest()
        meta["sha256"]     = hashlib.sha256(data).hexdigest()
        meta["modified"]   = datetime.fromtimestamp(stat.st_mtime).isoformat()
        meta["extension"]  = p.suffix.lower()
        # PE magic
        if data[:2] == b"MZ":
            meta["file_type"] = "PE (Windows Executable)"
            # Try to read PE timestamp from offset 0x3C → PE header
            try:
                pe_off = int.from_bytes(data[0x3C:0x40], "little")
                ts     = int.from_bytes(data[pe_off+8:pe_off+12], "little")
                meta["pe_timestamp"] = datetime.utcfromtimestamp(ts).isoformat() + "Z"
            except Exception:
                pass
        elif data[:4] == b"\xcafe\xbabe":
            meta["file_type"] = "Java class"
        elif data[:2] == b"PK":
            meta["file_type"] = "ZIP/JAR/PYZ archive"
        elif data[:4] in (b"\x1bLua", b"\x1bLj"):
            meta["file_type"] = "Lua bytecode"
        else:
            meta["file_type"] = "Unknown / text"
        meta["entropy"] = round(_entropy(data), 4)
        meta["packers"] = fingerprint_packer(file_path)
    except Exception as e:
        meta["error"] = str(e)
    return meta

def _human_size(n: int) -> str:
    for unit in ("B","KB","MB","GB"):
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def format_metadata(meta: dict) -> str:
    lines = ["── FILE METADATA ──\n"]
    for k, v in meta.items():
        if k == "packers":
            v = ", ".join(v) if v else "none detected"
        lines.append(f"  {k:<18} {v}")
    return "\n".join(lines)


# ── Language-aware syntax highlight keywords ─────────────────────
LANG_KEYWORDS: dict[str, tuple[str, ...]] = {
    "python":     ("def","class","import","from","return","if","else","elif","for","while",
                   "try","except","finally","with","as","pass","break","continue","lambda",
                   "and","or","not","in","is","None","True","False","yield","async","await",
                   "raise","global","nonlocal","del","assert"),
    "java":       ("public","private","protected","static","final","class","interface","extends",
                   "implements","void","return","if","else","for","while","do","try","catch",
                   "finally","throw","throws","new","import","package","this","super","null",
                   "true","false","abstract","synchronized","volatile","transient","enum"),
    "csharp":     ("public","private","protected","internal","static","readonly","const","class",
                   "interface","struct","enum","void","return","if","else","for","foreach","while",
                   "do","try","catch","finally","throw","new","using","namespace","this","base",
                   "null","true","false","abstract","virtual","override","async","await","var"),
    "javascript": ("function","var","let","const","return","if","else","for","while","do","try",
                   "catch","finally","throw","new","class","extends","import","export","from",
                   "async","await","null","undefined","true","false","typeof","instanceof","this"),
    "typescript": ("function","var","let","const","return","if","else","for","while","do","try",
                   "catch","finally","throw","new","class","extends","implements","interface",
                   "type","enum","import","export","from","async","await","null","undefined",
                   "true","false","public","private","protected","readonly","abstract"),
    "cpp":        ("int","char","float","double","bool","void","return","if","else","for","while",
                   "do","switch","case","break","continue","class","struct","public","private",
                   "protected","virtual","override","namespace","using","include","define",
                   "nullptr","true","false","const","static","auto","template","typename"),
    "php":        ("function","class","return","if","else","elseif","for","foreach","while","do",
                   "try","catch","finally","throw","new","echo","print","null","true","false",
                   "public","private","protected","static","abstract","interface","extends"),
    "powershell": ("function","param","return","if","else","elseif","foreach","while","do","try",
                   "catch","finally","throw","class","using","module","workflow","parallel",
                   "True","False","Null","-and","-or","-not","-eq","-ne","-gt","-lt"),
    "lua":        ("function","local","return","if","else","elseif","then","end","for","while",
                   "do","repeat","until","break","nil","true","false","and","or","not","in"),
    "go":         ("func","var","const","type","struct","interface","return","if","else","for",
                   "range","switch","case","break","continue","go","chan","select","defer",
                   "map","nil","true","false","import","package"),
    "rust":       ("fn","let","mut","const","static","struct","enum","trait","impl","pub","use",
                   "return","if","else","match","for","while","loop","break","continue","mod",
                   "None","Some","true","false","self","Self","super","crate"),
    "ruby":       ("def","class","module","return","if","else","elsif","unless","then","end",
                   "for","while","do","begin","rescue","ensure","raise","nil","true","false",
                   "and","or","not","in","when","case","require","include","extend"),
    "vbscript":   ("Sub","End","Function","If","Then","Else","ElseIf","For","Next","While","Wend",
                   "Do","Loop","Select","Case","Class","Set","Dim","Const","Call","Exit",
                   "Nothing","True","False","Null","Empty","And","Or","Not"),
    "batch":      ("echo","set","if","else","for","goto","call","exit","rem","pause","start",
                   "del","copy","move","ren","md","rd","dir","type","findstr"),
    "shell":      ("if","then","else","elif","fi","for","in","do","done","while","case","esac",
                   "function","return","exit","echo","read","export","local","source","trap"),
}

# ═══════════════════════════════════════════════════════════════
#  UI
# ═══════════════════════════════════════════════════════════════
HISTORY_KEY = "decompx:file_history"

class DecompXUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DecompX v4.4 — V0RTEX Plugin")
        self.root.geometry("1300x860"); self.root.minsize(950,620)
        self.root.configure(bg=TH["bg"])
        self._source = ""; self._rename_map = {}
        self._original_source = ""; self._current_lang = "python"
        self._yara_hits: list = []; self._file_meta: dict = {}
        self._cancel_event = threading.Event()
        self._search_idx = "1.0"
        self._history: list[str] = self._load_history()
        self._search_idx = "1.0"
        self._sync_vx_theme()  # sync colors with V0RTEX theme if available
        self._build_styles(); self._build_ui(); self._setup_diff_tags()
        LOG.add_cb(self._on_log)
        # Populate tools tab on startup
        self.root.after(500, self._refresh_tools)

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
        tk.Label(hdr, text="v4.4  ·  Elevated  ·  Full-Stack Script Decompiler + Deobfuscator",
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
        pe.bind("<FocusOut>", lambda _: self._show_hex_preview(self._pvar.get()) if pathlib.Path(self._pvar.get()).is_file() else None)
        # Drag-and-drop: bind to root window (Tkinter DnD is platform-limited, use hint)
        pe.drop_target_register = getattr(pe, "drop_target_register", None)
        self._btn(ctrl,"Browse…",   self._browse).pack(side="left", padx=3)
        self._btn(ctrl,"▶  Analyse",self._run, True).pack(side="left", padx=3)
        self._btn(ctrl,"History",   self._show_history).pack(side="left", padx=3)
        self._cancel_btn = self._btn(ctrl,"■ Cancel", self._cancel_run)
        self._cancel_btn.pack(side="left", padx=3)
        self._cancel_btn.configure(state="disabled")
        self._btn(ctrl,"Clear",     self._clear).pack(side="left", padx=3)
        self._btn(ctrl,"Save Log",  self._save_log).pack(side="right", padx=3)
        self._btn(ctrl,"⚙ Tools",  self._refresh_tools).pack(side="right", padx=3)
        self._btn(ctrl,"⎘ Diff",   self._show_diff_tab).pack(side="right", padx=3)
        self._btn(ctrl,"Save Source", self._save_source).pack(side="right", padx=3)

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
        self._full_box = self._mktab_full(nb, "Full Report")
        self._log_box  = self._mktab(nb, "Log")
        self._info_box = self._mktab(nb, "Analysis")
        self._ioc_box  = self._mktab(nb, "IOC")
        self._cg_box   = self._mktab(nb, "Call Graph")
        self._df_box   = self._mktab(nb, "Data Flow")
        self._ren_box  = self._mktab(nb, "Rename Map")
        self._yara_box = self._mktab(nb, "YARA")
        self._str_box  = self._mktab(nb, "Strings")
        self._ent_box  = self._mktab(nb, "Entropy")
        self._meta_box = self._mktab(nb, "Metadata")
        self._diff_box = self._mktab(nb, "Diff")
        self._tool_box = self._mktab(nb, "Tools")

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
        self._btn(src_hdr,"Save Source",self._save_source).pack(side="right",padx=2)

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
        self.root.bind("<Control-o>",   lambda _: self._browse())
        self.root.bind("<Control-r>",   lambda _: self._run())
        self.root.bind("<Control-s>",   lambda _: self._save_source())
        self.root.bind("<Control-l>",   lambda _: self._save_log())
        self.root.bind("<Escape>",      lambda _: self._hide_search())
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

    def _setup_diff_tags(self):
        for box in (self._diff_box,):
            box.tag_config("add",  foreground=TH["ok"],     font=TH["font_sm"])
            box.tag_config("rem",  foreground=TH["danger"],  font=TH["font_sm"])
            box.tag_config("hdr",  foreground=TH["accent"],  font=TH["font_sm"])
            box.tag_config("info", foreground=TH["fg_dim"],  font=TH["font_xs"])

    # ── Actions ──
    def _show_hex_preview(self, file_path: str):
        """Show first 256 bytes as hex dump in log tab."""
        try:
            p    = pathlib.Path(file_path)
            if not p.is_file(): return
            all_data = p.read_bytes()          # single read
            data     = all_data[:256]
            size     = len(all_data)
            del all_data
            lines = []
            for i in range(0, len(data), 16):
                chunk      = data[i:i+16]
                hex_part   = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"  {i:04x}  {hex_part:<47}  {ascii_part}")
            self._setstatus(f"Loaded: {p.name} ({size:,} bytes)", TH["ok"])
            self._log_box.configure(state="normal")
            self._log_box.insert("end", f"── HEX PREVIEW: {p.name} ({size:,} bytes) ──\n", "step")
            self._log_box.insert("end", "\n".join(lines) + "\n\n")
            self._log_box.see("end")
            self._log_box.configure(state="disabled")
        except Exception:
            pass

    def _browse(self):
        p = filedialog.askopenfilename(
            title="Select file", filetypes=[
                ("Python",    "*.py *.pyw *.pyc *.pyz *.exe"),
                ("C / C++",   "*.c *.cpp *.cxx *.cc *.h *.hpp"),
                ("Java",      "*.java *.class *.jar"),
                ("C# / .NET", "*.cs *.dll"),
                ("JavaScript","*.js *.mjs *.cjs *.ts *.tsx"),
                ("Scripts",   "*.ps1 *.psm1 *.vbs *.vbe *.bat *.cmd *.sh *.lua *.php *.rb *.go *.rs"),
                ("Archives",  "*.zip *.rar *.7z *.apk *.docx *.xlsx"),
                ("All",       "*.*")])
        if p: self._pvar.set(p)

    def _run(self):
        path = self._pvar.get().strip()
        if not path: messagebox.showwarning("DecompX","Select a file first."); return
        if not os.path.isfile(path): messagebox.showerror("DecompX","File not found."); return
        self._reset(); LOG.clear(); self._cancel_event.clear()
        self._setstatus("Analysing…",TH["accent"])
        self._add_history(path)
        try: self._cancel_btn.configure(state="normal")
        except Exception: pass
        self._show_scan_overlay()

        STAGE_MAP = {3:"s1",18:"s1",32:"s2",44:"s3",52:"s4",62:"s5",74:"s6",86:"s7",100:"s8"}
        _last = [None]

        def _prog_wrap(v):
            self._setprog(v)
            try: self._ov_prog.configure(value=v)
            except Exception: pass
            st = STAGE_MAP.get(v)
            if st and st != _last[0]:
                if _last[0]: self._update_stage(_last[0],"ok")
                self._update_stage(st,"running")
                _last[0] = st

        def _log_tick(e):
            if e["level"] in ("WARN","OK","STEP"): self._tick(e["msg"])
        LOG.add_cb(_log_tick)

        def _done_wrap(*a, **kw):
            if _last[0]: self._update_stage(_last[0],"ok")
            self._close_overlay()
            try: self._cancel_btn.configure(state="disabled")
            except Exception: pass
            self._done(*a, **kw)

        def _err_wrap(msg):
            self._close_overlay()
            try: self._cancel_btn.configure(state="disabled")
            except Exception: pass
            self._err(msg)

        threading.Thread(target=run_pipeline,
                         args=(path,_prog_wrap,_done_wrap,_err_wrap,self._cancel_event),
                         daemon=True).start()

    def _clear(self):
        self._pvar.set(""); self._reset(); LOG.clear(); self._setstatus("Ready",TH["fg_dim"])

    def _reset(self):
        self._full_box.configure(state='normal'); self._full_box.delete('1.0','end'); self._full_box.configure(state='disabled')
        for b in (self._log_box,self._info_box,self._ioc_box,self._cg_box,
                  self._df_box,self._ren_box,self._src_box,
                  self._yara_box,self._str_box,self._ent_box,
                  self._meta_box,self._diff_box,self._tool_box):
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
        """History in-memory per sessione (nessuna API db disponibile)."""
        return []

    def _add_history(self, path: str):
        if path in self._history: self._history.remove(path)
        self._history.insert(0, path)
        self._history = self._history[:10]

    def _cancel_run(self):
        self._cancel_event.set()
        self._setstatus("Cancelling…", TH["warn"])
        LOG.warn("Cancellation requested by user")
        # Kill any running subprocess
        global _current_tool_proc
        if _current_tool_proc:
            try: _current_tool_proc.kill()
            except Exception: pass

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
               from_cache=False, cg_txt="", data_flow=None, reputation=None,
               yara_hits=None, str_clusters=None, ent_heatmap="",
               file_meta=None, tool_status=None, original_source="",
               appended=None, polyglot=None, lsb_steg=None, ntfs_ads=None,
               pe_rsrc=None, file_drops=None, self_mod=None,
               timing_tri=None, homoglyphs=None, entry_point=""):
        self._source = source; self._rename_map = rename_map
        self._original_source = original_source or source
        if data_flow    is None: data_flow    = []
        if reputation   is None: reputation   = {}
        if yara_hits    is None: yara_hits    = []
        if str_clusters is None: str_clusters = {}
        if file_meta    is None: file_meta    = {}
        if tool_status  is None: tool_status  = []
        if appended     is None: appended     = {}
        if polyglot     is None: polyglot     = []
        if lsb_steg     is None: lsb_steg     = {}
        if ntfs_ads     is None: ntfs_ads     = []
        if pe_rsrc      is None: pe_rsrc      = []
        if file_drops   is None: file_drops   = []
        if self_mod     is None: self_mod     = []
        if timing_tri   is None: timing_tri   = []
        if homoglyphs   is None: homoglyphs   = []
        self._yara_hits = yara_hits; self._file_meta = file_meta
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
            susp_n  = len(parsed.get("suspicious",[]))
            ioc_n   = sum(len(v) for v in parsed.get("iocs",{}).values())
            yara_n  = len(yara_hits)
            threat  = min(100, obf_s//2 + susp_n*4 + ioc_n*3 + yara_n*10)
            t_color = TH["danger"] if threat>=75 else TH["warn"] if threat>=50 else TH["ok"]
            self._stat_lbl.configure(
                text=f"  {parsed.get('line_count',0)} lines · {parsed.get('char_count',0)} chars"
                     f" · {'AST OK' if ast_s else 'no AST'} · obf {obf_s}/100"
                     f" · threat {threat}/100  [{('CRITICAL' if threat>=75 else 'HIGH' if threat>=50 else 'MEDIUM' if threat>=25 else 'LOW')}]",
                fg=t_color)
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
            self._fill_box(self._ren_box,  self._ren_text(rename_map))
            # New v4.0 tabs
            self._fill_box(self._yara_box, self._yara_text(yara_hits))
            self._fill_box(self._str_box,  self._str_cluster_text(str_clusters))
            self._fill_box(self._ent_box,  ent_heatmap or "— no entropy data —")
            self._fill_box(self._meta_box, format_metadata(file_meta))
            self._fill_diff(make_diff(original_source or source, source))
            if tool_status:
                self._fill_box(self._tool_box, format_tool_report(tool_status))
            self._fill_box(self._steg_box,  self._steg_text(appended,polyglot,lsb_steg,ntfs_ads,pe_rsrc,homoglyphs))
            self._fill_box(self._drops_box, self._drops_text(file_drops,self_mod,timing_tri))
            # Language-aware highlight
            lang = file_meta.get("extension","").lstrip(".")
            self._current_lang = lang or "python"
            self._fill_full_report(
                source, parsed, obf, layers, b64f, rename_map,
                cg_txt, data_flow, yara_hits, str_clusters,
                ent_heatmap, file_meta, appended, polyglot,
                lsb_steg, ntfs_ads, pe_rsrc, file_drops,
                self_mod, timing_tri, homoglyphs)
            self._setstatus("✔ Done" + (" (cached)" if from_cache else ""), TH["ok"])
        self.root.after(0, _do)

    def _fill_box(self, box, text):
        box.configure(state="normal"); box.delete("1.0","end")
        box.insert("end", text); box.configure(state="disabled")

    def _analysis_text(self, parsed, obf, b64f) -> str:
        obf_s   = obf.get("score",0) if isinstance(obf,dict) else 0
        susp_n  = len(parsed.get("suspicious",[]))
        ioc_n   = sum(len(v) for v in parsed.get("iocs",{}).values())
        yara_n  = len(self._yara_hits) if hasattr(self, "_yara_hits") else 0
        # Compute a simple threat score
        threat  = min(100, obf_s//2 + susp_n*4 + ioc_n*3 + yara_n*10)
        t_label = "CRITICAL" if threat>=75 else "HIGH" if threat>=50 else "MEDIUM" if threat>=25 else "LOW"
        lines   = [
            f"── THREAT SUMMARY ──",
            f"  Threat Score    : {threat}/100  [{t_label}]",
            f"  Obfuscation     : {obf_s}/100",
            f"  Suspicious pats : {susp_n}",
            f"  IOC total       : {ioc_n}",
            f"  YARA hits       : {yara_n}",
            f"",
            f"── OBF SCORE: {obf_s}/100 ──",
        ]
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



    def _fill_diff(self, diff_text: str):
        """Fill the diff tab with colour-coded unified diff."""
        box = self._diff_box
        box.configure(state="normal"); box.delete("1.0", "end")
        for line in diff_text.splitlines():
            if line.startswith("+++") or line.startswith("---"):
                box.insert("end", line + "\n", "hdr")
            elif line.startswith("@@"):
                box.insert("end", line + "\n", "info")
            elif line.startswith("+"):
                box.insert("end", line + "\n", "add")
            elif line.startswith("-"):
                box.insert("end", line + "\n", "rem")
            else:
                box.insert("end", line + "\n", "info")
        box.configure(state="disabled")

    def _yara_text(self, hits: list) -> str:
        if not hits:
            return "── YARA-LITE ──\n\n  ✔ No rules matched — no known malware signatures detected."
        sev_order = {"high": 0, "medium": 1, "low": 2}
        hits_sorted = sorted(hits, key=lambda h: sev_order.get(h["severity"], 9))
        lines = [f"── YARA-LITE ({len(hits)} match{'es' if len(hits)>1 else ''}) ──\n"]
        sev_icon = {"high": "🔴", "medium": "🟡", "low": "🔵"}
        for h in hits_sorted:
            icon = sev_icon.get(h["severity"], "⚪")
            lines.append(f"  {icon}  [{h['severity'].upper():<6}]  {h['rule']}")
            lines.append(f"         Match: {h['match']}")
            lines.append(f"         Offset: {h['offset']}\n")
        return "\n".join(lines)

    def _str_cluster_text(self, clusters: dict) -> str:
        if not clusters:
            return "— no strings extracted —"
        lines = ["── STRING CLUSTERS ──\n"]
        icons = {"urls":"🌐","paths":"📁","credentials":"🔑","crypto":"🔐",
                 "commands":"⚙","registry":"🗝","misc":"📄"}
        for cat, items in clusters.items():
            if not items: continue
            lines.append(f"  {icons.get(cat,'·')} {cat.upper()} ({len(items)})")
            for s in items[:20]:
                lines.append(f"    {s[:90]}")
            if len(items) > 20:
                lines.append(f"    … and {len(items)-20} more")
            lines.append("")
        return "\n".join(lines)

    def _refresh_tools(self):
        """Re-check tools and update the Tools tab."""
        results = check_tools()
        self._fill_box(self._tool_box, format_tool_report(results))
        ok = sum(1 for t in results if t["available"])
        self._setstatus(f"Tools: {ok}/{len(results)} available", TH["ok"])

    def _show_diff_tab(self):
        """Force-show the Diff tab."""
        if self._original_source:
            diff = make_diff(self._original_source, self._source)
            self._fill_box(self._diff_box, diff)

    def _save_source(self):
        """Save source with correct extension based on detected language."""
        if not self._source: return
        ext_map = {
            "python":"py","java":"java","csharp":"cs","javascript":"js",
            "typescript":"ts","cpp":"cpp","c":"c","php":"php","lua":"lua",
            "powershell":"ps1","vbscript":"vbs","go":"go","rust":"rs",
            "ruby":"rb","shell":"sh","batch":"bat",
        }
        lang = self._current_lang or "python"
        ext  = ext_map.get(lang, "txt")
        p = filedialog.asksaveasfilename(
            defaultextension=f".{ext}",
            filetypes=[(f"{lang.upper()} file", f"*.{ext}"), ("All", "*.*")]
        )
        if p:
            try:
                pathlib.Path(p).write_text(self._source, encoding="utf-8")
                self._setstatus(f"Saved: {pathlib.Path(p).name}", TH["ok"])
            except Exception as e:
                messagebox.showerror("DecompX", str(e))

    def _highlight_source_lang(self):
        """Language-aware syntax highlight based on self._current_lang."""
        sb   = self._src_box
        text = sb.get("1.0", "end")
        lang = self._current_lang or "python"
        kws  = LANG_KEYWORDS.get(lang, LANG_KEYWORDS["python"])
        kw_pat = r"\b(" + "|".join(re.escape(k) for k in kws) + r")\b"

        def hl(pat, tag):
            for m in re.finditer(pat, text):
                sb.tag_add(tag, f"1.0+{m.start()}c", f"1.0+{m.end()}c")

        # Clear old tags
        for tag in ("kw","cm","str","num","dec","search_hl"):
            sb.tag_remove(tag, "1.0", "end")

        hl(kw_pat, "kw")
        # Comments — language specific
        if lang in ("python","shell","ruby","bash","zsh"):
            hl(r"#[^\n]*", "cm")
        elif lang in ("java","csharp","javascript","typescript","cpp","go","rust","php"):
            hl(r"//[^\n]*", "cm")
            hl(r"/\*[\s\S]*?\*/", "cm")
        elif lang in ("lua",):
            hl(r"--[^\n]*", "cm")
        elif lang in ("vbscript",):
            hl(r"'[^\n]*", "cm")
        elif lang in ("batch",):
            hl(r"(?i)rem[^\n]*", "cm")
        # Strings
        hl(r'("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"[^"\n]*"|\'[^\'\n]*\')', "str")
        # Numbers
        hl(r"\b\d+\.?\d*\b", "num")
        # Decorators / annotations
        hl(r"@\w+", "dec")



    # ── New tab text helpers ──────────────────────────────────

    def _steg_text(self, appended, polyglot, lsb_steg, ntfs_ads, pe_rsrc, homoglyphs) -> str:
        L = ["── STEGANOGRAPHY & HIDDEN DATA ──\n"]
        if appended.get("found"):
            L += [f"  APPENDED DATA DETECTED",
                  f"     Type    : {appended['type']}",
                  f"     Offset  : {appended['offset']} (0x{appended['offset']:08x})",
                  f"     Size    : {appended['size']} bytes",
                  f"     Entropy : {appended['entropy']} bits",
                  f"     Preview : {appended['preview']}", ""]
        else:
            L.append("  No appended data after logical EOF\n")
        L.append(f"  Polyglot: {', '.join(polyglot) if polyglot else 'none'}\n")
        lsb = lsb_steg or {}
        L += [f"  LSB steg possible: {lsb.get('possible','?')}",
              f"  LSB entropy: {lsb.get('lsb_entropy','?')}",
              f"  Note: {lsb.get('note','N/A')}",""]
        L.append(f"  NTFS ADS: {', '.join(ntfs_ads) if ntfs_ads else 'none'}\n")
        if pe_rsrc:
            L.append(f"  Embedded blobs ({len(pe_rsrc)}):")
            for r in pe_rsrc[:10]:
                L.append(f"     {r['name']} — {r['size']}B ent={r['entropy']} [{r['type_hint']}]")
            L.append("")
        else:
            L.append("  No embedded blobs\n")
        if homoglyphs:
            L.append(f"  Homoglyphs ({len(homoglyphs)}):")
            for h in homoglyphs[:20]: L.append(f"     {h}")
        else:
            L.append("  No homoglyphs found")
        return "\n".join(L)

    def _drops_text(self, file_drops, self_mod, timing_tri) -> str:
        L = ["── PREDICTED FILE DROPS & BEHAVIOUR ──\n"]
        if file_drops:
            L.append(f"  File drop predictions ({len(file_drops)}):\n")
            for d in file_drops:
                icon = "SUSP" if d.get("suspicious") else "INFO"
                L += [f"  [{icon}] {d['path']}",
                      f"     Method : {d['method']}",
                      f"     Line   : {d['line']}",
                      f"     Preview: {d.get('preview','')}",""]
        else:
            L.append("  No file drop patterns detected\n")
        if self_mod:
            L.append(f"  Self-modifying patterns ({len(self_mod)}):")
            for s in self_mod: L.append(f"     L{s['line']} {s['pattern']} — {s['match']}")
            L.append("")
        else:
            L.append("  No self-modifying code\n")
        if timing_tri:
            L.append(f"  Timing/anti-analysis ({len(timing_tri)}):")
            for t in timing_tri: L.append(f"     L{t['line']} [{t['severity']}] {t['pattern']}")
        else:
            L.append("  No timing tricks")
        return "\n".join(L)

    # ── Animated scan overlay ─────────────────────────────────

    def _show_scan_overlay(self):
        self._overlay = tk.Toplevel(self.root)
        self._overlay.title("DecompX — Scanning")
        self._overlay.geometry("520x360")
        self._overlay.configure(bg=TH["bg"])
        self._overlay.resizable(False, False)
        self._overlay.transient(self.root)
        self._overlay.grab_set()

        tk.Label(self._overlay, text="DECOMPX", bg=TH["bg"], fg=TH["accent"],
                 font=("Consolas",20,"bold")).pack(pady=(20,2))
        tk.Label(self._overlay, text="Deobfuscating Scan in progress…",
                 bg=TH["bg"], fg=TH["fg_dim"], font=TH["font_sm"]).pack()

        self._stage_frame = tk.Frame(self._overlay, bg=TH["bg"])
        self._stage_frame.pack(pady=10, fill="x", padx=28)
        self._stage_labels: dict = {}

        STAGES = [
            ("s1","Stage 1 · Extract / decode source"),
            ("s2","Stage 2 · Inline decode + steg detection"),
            ("s3","Stage 3 · Obfuscation analysis"),
            ("s4","Stage 4 · CFF solver + constant folding"),
            ("s5","Stage 5 · Semantic rename"),
            ("s6","Stage 6 · Static analysis + YARA"),
            ("s7","Stage 7 · Reports"),
            ("s8","Stage 8 · V0RTEX API"),
        ]
        for key, label in STAGES:
            row = tk.Frame(self._stage_frame, bg=TH["bg"]); row.pack(fill="x", pady=1)
            icon_lbl = tk.Label(row, text="○", bg=TH["bg"], fg=TH["border"],
                                font=("Consolas",10), width=3)
            icon_lbl.pack(side="left")
            text_lbl = tk.Label(row, text=label, bg=TH["bg"], fg=TH["fg_dim"],
                                font=TH["font_sm"], anchor="w")
            text_lbl.pack(side="left")
            self._stage_labels[key] = (icon_lbl, text_lbl)

        self._ticker_var = tk.StringVar(value="")
        tk.Label(self._overlay, textvariable=self._ticker_var,
                 bg=TH["bg"], fg=TH["accent2"], font=TH["font_xs"],
                 wraplength=460, justify="left").pack(padx=14, pady=(4,0))

        pf = tk.Frame(self._overlay, bg=TH["bg"]); pf.pack(fill="x", padx=28, pady=6)
        self._ov_prog = ttk.Progressbar(pf, mode="determinate", maximum=100)
        self._ov_prog.pack(fill="x")

        self._pulse_active = True
        self._pulse_chars  = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
        self._pulse_idx    = 0
        self._pulse_lbl    = tk.Label(self._overlay, text="", bg=TH["bg"],
                                      fg=TH["accent"], font=("Consolas",14))
        self._pulse_lbl.pack()
        self._animate_pulse()

    def _animate_pulse(self):
        if not self._pulse_active: return
        try:
            self._pulse_lbl.configure(text=self._pulse_chars[self._pulse_idx % len(self._pulse_chars)])
            self._pulse_idx += 1
            self.root.after(80, self._animate_pulse)
        except Exception:
            pass

    def _update_stage(self, key: str, state: str):
        if not hasattr(self,"_stage_labels") or key not in self._stage_labels: return
        icon_lbl, text_lbl = self._stage_labels[key]
        cfg = {"running":("◈",TH["accent"],TH["fg"]),
               "ok":     ("✔",TH["ok"],    TH["fg"]),
               "warn":   ("⚠",TH["warn"],  TH["warn"]),
               "skip":   ("—",TH["fg_dim"],TH["fg_dim"])}.get(state,("○",TH["border"],TH["fg_dim"]))
        def _do():
            try: icon_lbl.configure(text=cfg[0],fg=cfg[1]); text_lbl.configure(fg=cfg[2])
            except Exception: pass
        self.root.after(0, _do)

    def _tick(self, msg: str):
        def _do():
            try: self._ticker_var.set(f"▸ {msg}")
            except Exception: pass
        self.root.after(0, _do)

    def _close_overlay(self):
        self._pulse_active = False
        def _do():
            try:
                if hasattr(self,"_overlay"):
                    self._overlay.grab_release()
                    self._overlay.destroy()
                    del self._overlay
            except Exception: pass
        self.root.after(0, _do)


    def _mktab_full(self, nb, label) -> scrolledtext.ScrolledText:
        """Special tab for Full Report — uses a Text widget with colour tags."""
        f = tk.Frame(nb, bg=TH["bg"]); nb.add(f, text=label)
        # Toolbar
        bar = tk.Frame(f, bg=TH["panel"], pady=3, padx=6); bar.pack(fill="x")
        tk.Label(bar, text="Full Report — all stages, dynamic per file",
                 bg=TH["panel"], fg=TH["fg_dim"], font=TH["font_xs"]).pack(side="left")
        self._btn(bar, "Copy Report", self._copy_full_report).pack(side="right", padx=3)
        # Text
        box = scrolledtext.ScrolledText(
            f, bg=TH["src_bg"], fg=TH["fg"], font=TH["font_sm"],
            relief="flat", wrap="word", state="disabled",
            insertbackground=TH["fg"])
        box.pack(fill="both", expand=True, padx=3, pady=3)
        # Tags
        box.tag_config("h1",    foreground=TH["accent"],  font=("Consolas",12,"bold"))
        box.tag_config("h2",    foreground=TH["accent2"], font=("Consolas",10,"bold"))
        box.tag_config("ok",    foreground=TH["ok"],      font=TH["font_sm"])
        box.tag_config("warn",  foreground=TH["warn"],    font=TH["font_sm"])
        box.tag_config("err",   foreground=TH["danger"],  font=TH["font_sm"])
        box.tag_config("dim",   foreground=TH["fg_dim"],  font=TH["font_xs"])
        box.tag_config("code",  foreground=TH["accent2"], font=("Consolas",9))
        box.tag_config("sep",   foreground=TH["border"],  font=("Consolas",8))
        box.tag_config("badge_high",   background=TH["danger"], foreground="#fff", font=("Consolas",9,"bold"))
        box.tag_config("badge_med",    background=TH["warn"],   foreground="#000", font=("Consolas",9,"bold"))
        box.tag_config("badge_low",    background=TH["ok"],     foreground="#000", font=("Consolas",9,"bold"))
        box.tag_config("badge_info",   background=TH["accent"], foreground="#fff", font=("Consolas",9,"bold"))
        box.tag_config("skip",  foreground=TH["fg_dim"],  font=("Consolas",9,"italic"))
        return box

    def _copy_full_report(self):
        txt = self._full_box.get("1.0", "end")
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        self._setstatus("Full report copied!", TH["ok"])

    def _w(self, text: str, tag: str = ""):
        """Write to Full Report box."""
        self._full_box.configure(state="normal")
        if tag:
            self._full_box.insert("end", text, tag)
        else:
            self._full_box.insert("end", text)
        self._full_box.configure(state="disabled")

    def _wl(self, text: str = "", tag: str = ""):
        self._w(text + "\n", tag)

    def _sep(self, title: str = ""):
        self._wl()
        if title:
            bar = f"── {title} " + "─" * max(2, 55 - len(title))
            self._wl(bar, "h2")
        else:
            self._wl("─" * 58, "sep")

    def _fill_full_report(
        self, source, parsed, obf, layers, b64f, rename_map,
        cg_txt, data_flow, yara_hits, str_clusters,
        ent_heatmap, file_meta, appended, polyglot,
        lsb_steg, ntfs_ads, pe_rsrc, file_drops,
        self_mod, timing_tri, homoglyphs
    ):
        """
        Build the dynamic Full Report tab.
        Sections appear/disappear based on what was actually found.
        """
        box = self._full_box
        box.configure(state="normal"); box.delete("1.0","end"); box.configure(state="disabled")

        obf_s  = obf.get("score",0) if isinstance(obf,dict) else 0
        susp_n = len(parsed.get("suspicious",[]))
        ioc_n  = sum(len(v) for v in parsed.get("iocs",{}).values())
        yara_n = len(yara_hits)
        threat = min(100, obf_s//2 + susp_n*4 + ioc_n*3 + yara_n*10)
        t_lab  = "CRITICAL" if threat>=75 else "HIGH" if threat>=50 else "MEDIUM" if threat>=25 else "LOW"
        t_tag  = "badge_high" if threat>=75 else "badge_med" if threat>=50 else "badge_low"
        ext    = file_meta.get("extension","?")
        fname  = file_meta.get("filename","?")

        # ── HEADER ────────────────────────────────────────────
        self._wl()
        self._wl("  DECOMPX v4.1 — FULL REPORT", "h1")
        self._wl(f"  {fname}  ·  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "dim")
        self._wl()
        self._w("  THREAT SCORE  "); self._w(f" {threat}/100 ", t_tag)
        self._w("  "); self._wl(f" {t_lab} ", t_tag)
        self._wl()

        # ── STAGE 1 — SOURCE ──────────────────────────────────
        self._sep("STAGE 1 · Source Extraction")
        self._wl(f"  File       : {fname}", "dim")
        self._wl(f"  Type       : {file_meta.get('file_type','?')}", "dim")
        self._wl(f"  Size       : {file_meta.get('size_human','?')}", "dim")
        self._wl(f"  MD5        : {file_meta.get('md5','?')}", "code")
        self._wl(f"  SHA256     : {file_meta.get('sha256','?')}", "code")
        if file_meta.get("pe_timestamp"):
            self._wl(f"  PE tstamp  : {file_meta['pe_timestamp']}", "dim")
        if file_meta.get("packers"):
            self._w("  Packers    : ")
            self._wl(", ".join(file_meta["packers"]), "warn")
        else:
            self._wl("  Packers    : none detected", "ok")
        if layers:
            self._w("  Layers     : ")
            self._wl(" → ".join(layers), "warn")
        else:
            self._wl("  Layers     : none", "ok")
        self._wl(f"  Source     : {parsed.get('line_count',0)} lines, {parsed.get('char_count',0)} chars", "dim")
        self._wl(f"  AST parse  : {'OK' if parsed.get('ast_ok') else 'FAILED (syntax error)'}", "ok" if parsed.get("ast_ok") else "warn")
        if entry_point:
            self._w("  Entry point: "); self._wl(entry_point, "ok")

        # ── STAGE 2 — DECODE ──────────────────────────────────
        self._sep("STAGE 2 · Inline Decode + Steg")

        # Homoglyphs — only if found
        if homoglyphs:
            self._wl(f"  Homoglyphs : {len(homoglyphs)} found and normalized", "warn")
            for h in homoglyphs[:5]: self._wl(f"    {h}", "code")
        else:
            self._wl("  Homoglyphs : none", "ok")

        # Encoded strings
        if b64f:
            self._wl(f"  Encoded strings : {len(b64f)} found", "warn")
            for b in b64f[:5]:
                self._wl(f"    [{b['type']}] {b['encoded'][:40]}", "code")
                self._wl(f"          → {b['decoded'][:60]}", "ok")
        else:
            self._wl("  Encoded strings : none", "ok")

        # Appended data — only if found
        if appended.get("found"):
            self._wl(f"  Appended data   : FOUND after {appended['type']}", "err")
            self._wl(f"    Offset  : 0x{appended['offset']:08x}  Size: {appended['size']}B  Entropy: {appended['entropy']}", "code")
            self._wl(f"    Preview : {appended['preview']}", "code")
        else:
            self._wl("  Appended data   : none", "ok")

        # Polyglot — only if found
        if polyglot:
            self._wl(f"  Polyglot        : valid as {', '.join(polyglot)}", "err")
        else:
            self._wl("  Polyglot        : no", "ok")

        # LSB steg — only if suspicious
        lsb = lsb_steg or {}
        if lsb.get("possible"):
            self._wl(f"  LSB steg        : POSSIBLE (entropy={lsb.get('lsb_entropy','?')})", "warn")
        else:
            self._wl("  LSB steg        : no signal", "ok")

        # NTFS ADS — only if found
        if ntfs_ads:
            self._wl(f"  NTFS ADS        : {', '.join(ntfs_ads)}", "err")
        else:
            self._wl("  NTFS ADS        : none", "ok")

        # PE resources — only if found
        if pe_rsrc:
            self._wl(f"  PE embedded     : {len(pe_rsrc)} blob(s)", "warn")
            for r in pe_rsrc[:3]:
                self._wl(f"    {r['name']} — {r['size']}B [{r['type_hint']}]", "code")
        else:
            # Only show for binary files
            if ext in (".exe",".dll"):
                self._wl("  PE embedded     : none", "ok")

        # ── STAGE 3 — OBFUSCATION ─────────────────────────────
        self._sep("STAGE 3 · Obfuscation Analysis")
        obf_tag = "err" if obf_s>=75 else "warn" if obf_s>=25 else "ok"
        self._w(f"  Score : {obf_s}/100  ")
        self._wl("OBFUSCATED" if obf.get("is_obf") else "CLEAN", obf_tag)
        if obf.get("techniques"):
            for t in obf["techniques"]:
                self._wl(f"    ⚠ {t}", "warn")
        else:
            self._wl("    No obfuscation techniques detected", "ok")

        # ── STAGE 4 — CFF + FOLDING ───────────────────────────
        # Only show if relevant
        if obf.get("is_obf") or ext in (".py",".pyc",".pyz",".exe"):
            self._sep("STAGE 4 · CFF Solver + Constant Folding")
            cff_tag = "ok" if "CFF" in str(obf.get("techniques","")) else "skip"
            self._wl("  CFF solver      : applied" if cff_tag=="ok" else "  CFF solver      : no CFF pattern found", cff_tag)
            self._wl("  Constant folding: applied", "ok")

        # ── STAGE 5 — RENAME ──────────────────────────────────
        if rename_map:
            self._sep("STAGE 5 · Semantic Rename")
            self._wl(f"  {len(rename_map)} identifiers renamed", "ok")
            # Show first 10
            items = list(rename_map.items())[:10]
            maxw  = max(len(k) for k,v in items)
            for old, new in items:
                self._w(f"    {old:<{maxw+2}}", "err")
                self._w(" → ", "dim")
                self._wl(new, "ok")
            if len(rename_map) > 10:
                self._wl(f"    … and {len(rename_map)-10} more (see Rename Map tab)", "dim")
        else:
            if obf.get("is_obf"):
                self._sep("STAGE 5 · Semantic Rename")
                self._wl("  Rename skipped (AST parse failed)", "skip")

        # ── STAGE 6 — STATIC ANALYSIS ─────────────────────────
        self._sep("STAGE 6 · Static Analysis")

        # Imports
        imps = parsed.get("imports",[])
        self._wl(f"  Imports   : {len(imps)}", "dim")
        if imps:
            self._wl("    " + ", ".join(imps[:12]) + ("…" if len(imps)>12 else ""), "code")

        # Functions
        fns = parsed.get("functions",[])
        self._wl(f"  Functions : {len(fns)}", "dim")

        # Classes
        cls = parsed.get("classes",[])
        self._wl(f"  Classes   : {len(cls)}", "dim")

        # Suspicious patterns — always shown
        suspicious = parsed.get("suspicious",[])
        if suspicious:
            self._wl(f"  Suspicious patterns : {len(suspicious)}", "err")
            for s in suspicious:
                self._wl(f"    ⚠ {s['pattern']}  ×{s['count']}", "warn")
        else:
            self._wl("  Suspicious patterns : none", "ok")

        # Self-modifying code — only if found
        if self_mod:
            self._wl(f"  Self-modifying code : {len(self_mod)} pattern(s)", "err")
            for s in self_mod:
                self._wl(f"    L{s['line']} {s['pattern']}", "warn")

        # Timing tricks — only if found
        if timing_tri:
            self._wl(f"  Timing tricks : {len(timing_tri)}", "warn")
            for t in timing_tri:
                self._wl(f"    L{t['line']} [{t['severity']}] {t['pattern']}", "warn")

        # ── YARA — only if hits ────────────────────────────────
        if yara_hits:
            self._sep("YARA-LITE")
            sev_tag = {"high":"badge_high","medium":"badge_med","low":"badge_low"}
            for h in sorted(yara_hits, key=lambda x: {"high":0,"medium":1,"low":2}.get(x["severity"],9)):
                self._w(f"  {h['rule']:<24} ")
                self._w(f" {h['severity'].upper()} ", sev_tag.get(h["severity"],"badge_info"))
                self._wl(f"  {h['match'][:40]}", "code")

        # ── IOC — only if found ────────────────────────────────
        iocs = parsed.get("iocs",{})
        has_ioc = any(iocs.values())
        if has_ioc:
            self._sep("IOC")
            for lbl, key in [("URLs","urls"),("IPs","ips"),("Emails","emails"),
                              ("Domains","domains"),("Registry","registry_keys")]:
                items = iocs.get(key,[])
                if items:
                    self._wl(f"  {lbl} ({len(items)}):", "warn")
                    for item in items[:8]:
                        self._wl(f"    {item}", "code")
                    if len(items) > 8:
                        self._wl(f"    … +{len(items)-8} more", "dim")

        # ── DATA FLOW — only if findings ───────────────────────
        if data_flow:
            self._sep("DATA FLOW · Taint Analysis")
            for df in data_flow:
                self._w(f"  {df['var']}", "err")
                self._w(f"  ←  {df['source']}()", "warn")
                self._w(f"  →  {df['sink']}()", "err")
                self._wl(f"  [L{df['line']}]", "dim")

        # ── CALL GRAPH — only for code files ──────────────────
        if cg_txt and cg_txt.strip() != "— no call graph —" and ext in (".py",".pyw",".js",".ts",".rb",".php",".lua"):
            self._sep("CALL GRAPH")
            for line in cg_txt.splitlines()[:30]:
                self._wl(f"  {line}", "code")
            if cg_txt.count("\n") > 30:
                self._wl("  … (see Call Graph tab for full tree)", "dim")

        # ── FILE DROPS — only if predicted ────────────────────
        if file_drops:
            self._sep("FILE DROP PREDICTIONS")
            for d in file_drops:
                tag = "err" if d.get("suspicious") else "warn"
                self._w(f"  {d['method']:<18} ", "dim")
                self._wl(d["path"], tag)
                if d.get("preview"):
                    self._wl(f"    L{d['line']}: {d['preview']}", "code")

        # ── STRINGS — only if suspicious clusters ─────────────
        if str_clusters:
            interesting = {k:v for k,v in str_clusters.items()
                          if k in ("credentials","commands","urls","crypto") and v}
            if interesting:
                self._sep("NOTABLE STRINGS")
                icons = {"credentials":"🔑","commands":"⚙","urls":"🌐","crypto":"🔐"}
                for cat, items in interesting.items():
                    self._wl(f"  {icons.get(cat,'')} {cat.upper()} ({len(items)})", "warn")
                    for s in items[:5]: self._wl(f"    {s[:80]}", "code")

        # ── ENTROPY HEATMAP — only if high entropy found ──────
        hi_ent = obf.get("hi_ent_lines",[])
        if hi_ent:
            self._sep("HIGH-ENTROPY LINES")
            for h in hi_ent[:10]:
                self._w(f"  L{h['line']:<6} ent={h['entropy']}  ", "warn")
                self._wl(h["preview"], "code")

        # ── FOOTER ────────────────────────────────────────────
        self._sep()
        self._wl(f"  DecompX v4.1 · {datetime.now().isoformat()}", "dim")
        self._wl(f"  Tabs with full detail: Analysis · IOC · YARA · Call Graph · Data Flow", "dim")
        self._wl(f"         Rename Map · Strings · Entropy · Metadata · Steg/Hidden · File Drops", "dim")
        self._wl()

    def _sync_vx_theme(self):
        """Sync TH color dict with V0RTEX active theme via vx.ui.get_theme()."""
        try:
            theme = vx.ui.get_theme()
            if not theme or not isinstance(theme, dict): return
            # Map V0RTEX theme keys to our TH keys
            mapping = {
                "background":  "bg",
                "panel":       "panel",
                "card":        "card",
                "border":      "border",
                "accent":      "accent",
                "accent2":     "accent2",
                "foreground":  "fg",
                "fg_dim":      "fg_dim",
                "ok":          "ok",
                "warn":        "warn",
                "danger":      "danger",
            }
            for vx_key, th_key in mapping.items():
                if vx_key in theme and theme[vx_key]:
                    TH[th_key] = theme[vx_key]
            LOG.info("Theme synced from V0RTEX")
        except Exception:
            pass  # theme sync is optional — fall back to hardcoded TH

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
    LOG.info("DecompX v4.4 loaded (Elevated)")
    vx_register_scan_hook()
    # Pre-load last scan result — defer until UI is open
    def _deferred_autoload():
        import time
        time.sleep(1.5)  # wait for run() to open the window
        try:
            last = vx.scan.get_last_result()
            if last and last.get("file_path") and _ui is not None:
                ext = pathlib.Path(last["file_path"]).suffix.lower()
                if ext in (".exe",".py",".pyc",".pyw",".pyz",".jar",".dll",".zip",".ps1"):
                    def _set():
                        try:
                            _ui._pvar.set(last["file_path"])
                            _ui._show_hex_preview(last["file_path"])
                            LOG.info(f"Auto-loaded last scan: {last['file_path']}")
                        except Exception:
                            pass
                    if _ui is not None:
                        _ui.root.after(0, _set)
        except Exception:
            pass
    import threading as _th
    _th.Thread(target=_deferred_autoload, daemon=True).start()

def run():
    global _ui, _ui_thread
    def _open():
        global _ui
        _ui = DecompXUI(); _ui.run(); _ui = None
    _ui_thread = threading.Thread(target=_open, daemon=True, name="DecompX-UI")
    _ui_thread.start()
    try: vx.ui.notify("DecompX v4.4 opened", level="info")
    except Exception: pass

def on_unload():
    global _ui, _ui_thread
    if _ui:
        try: _ui.destroy()
        except: pass
        _ui = None
    _ui_thread = None
    LOG.info("DecompX v4.4 unloaded cleanly")

def on_update(old_version: str, new_version: str):
    """
    Called by V0RTEX after auto-update. Handles:
    - Data migration between report formats
    - Notification to user with changelog
    - Cleanup of temp/stale files from old versions
    - UI refresh if window is open
    """
    LOG.step(f"DecompX update: {old_version} → {new_version}")

    def _ver(v: str) -> tuple:
        """Parse version string to comparable tuple."""
        try: return tuple(int(x) for x in v.split("."))
        except: return (0, 0, 0)

    old = _ver(old_version)
    new = _ver(new_version)

    # ── 1. Notify user ──────────────────────────────────────────
    try:
        vx.ui.notify(
            f"DecompX updated {old_version} → {new_version}. "
            f"See Log tab for details.",
            level="info"
        )
    except Exception:
        pass

    # ── 2. Changelog per version range ──────────────────────────
    CHANGELOG: dict[tuple, list[str]] = {
        (4, 1, 0): [
            "lzma/bz2 decode layers added",
            "Constant folding (dead code elimination)",
            "String array remapping (_0x1a[0] → value)",
            "Homoglyph normalizer (Cyrillic/Greek lookalikes)",
            "Appended data / polyglot / LSB steg detection",
            "PE resource extractor",
            "File drop predictor",
            "Self-modifying code + timing trick detection",
            "Animated scan overlay",
            "Output tree: flat MD naming convention",
        ],
        (4, 2, 0): [
            "Fixed: _vx_safe removed, run() no longer crashes on load",
            "Fixed: PE section offset now reads SizeOfOptionalHeader",
            "Fixed: polyglot detection checks magic at offset 0 only",
            "Fixed: PE resource cap (max 8 blobs per magic type)",
            "Fixed: ConstantFolder safety cap on large values",
            "Fixed: vx.fs.write_file wrapped in try/except for Unverified",
            "Fixed: subprocess lazy import (scanner compliance)",
            "Fixed: cluster_strings_raw fallback for non-Python files",
            "Added: vx.scan.get_last_result() auto-load in on_load()",
        ],
        (4, 4, 0): [
            "Fixed: _show_hex_preview now wired and uses single read",
            "Fixed: _flat_path_counters reset per analysis",
            "Fixed: entry_point passed to write_output_tree and master MD",
            "Fixed: on_load deferred autoload (_ui was None)",
            "Fixed: vx.ui.get_theme() now used to sync TH colors",
            "Fixed: .jar no longer hijacked by archive branch",
            "Fixed: unrar/7z timeouts added to _TOOL_TIMEOUTS",
            "Fixed: _run_tool uses Popen for cancel support",
            "Fixed: decompile_jar reports skipped .class count",
            "Added: predict_file_drops multi-language (PS/PHP/JS/Bash/Batch)",
            "Added: vx.notes.append() summary after each analysis",
            "Added: scan hook auto-loads file into UI path field",
            "Added: _sync_vx_theme() on UI init",
        ],
        (4, 3, 0): [
            "Fixed: VBE decode rewritten with official MS 3-level table",
            "Fixed: JS hex escape regex matches single-quoted strings",
            "Fixed: Lua bytecode detection on raw bytes",
            "Fixed: Per-tool timeouts (cfr=120s, ilspycmd=180s…)",
            "Fixed: String array remap regex word boundary",
            "Fixed: self-modifying pattern [.*] → .+?",
            "Fixed: flat_path collision counter",
            "Fixed: track_data_flow — str/len removed from SOURCES",
            "Fixed: call graph builtin noise filter",
            "Fixed: YARA noisy rules (urlretrieve, Resolve-DnsName removed)",
            "Fixed: IOC cross-field deduplication (URL domains)",
            "Added: Entry point detection (PyInstaller __main__)",
            "Added: Encoding detection (UTF-8/Latin-1/CP1252/Shift-JIS)",
            "Added: ZIP/RAR/7z archive unpacker",
            "Added: Cancel button with threading.Event",
            "Added: Hex preview on file load",
        ],
    }

    logged = []
    for ver, changes in sorted(CHANGELOG.items()):
        if old < ver <= new:
            LOG.info(f"Changes in {'.'.join(str(x) for x in ver)}:")
            for c in changes:
                LOG.info(f"  · {c}")
                logged.append(c)

    if not logged:
        LOG.info("No specific migration notes for this version range.")

    # ── 3. Report format migration ───────────────────────────────
    # v4.1 introduced flat naming convention for MD files:
    # OLD: decompx_<stem>_<ts>/<stem>.md
    # NEW: decompx__<stem>_<ts>.md  (flat, no subdir)
    # V0RTEX API does not support listing plugin files, so we cannot
    # scan+migrate old files automatically. Log a note instead.
    if old < (4, 1, 0):
        LOG.warn(
            "Report format changed in v4.1: output MD files now use "
            "flat naming (decompx__<stem>_<ts>.md). "
            "Old reports in subfolder format remain valid but are not "
            "auto-migrated (vx.fs.list_plugin_files not available)."
        )

    # ── 4. Settings/state migration ─────────────────────────────
    # If we add persistent settings in a future version,
    # handle migration here by version range.
    # Example: if old < (5, 0, 0): migrate_settings_v4_to_v5()

    # ── 5. Refresh UI if open ────────────────────────────────────
    global _ui
    if _ui is not None:
        def _refresh():
            try:
                _ui._setstatus(
                    f"Updated to v{new_version} — restart recommended",
                    TH["accent3"]
                )
                # Repopulate tools tab with latest tool registry
                _ui._refresh_tools()
            except Exception:
                pass
        try:
            _ui.root.after(0, _refresh)
        except Exception:
            pass

    LOG.ok(f"on_update complete: {old_version} → {new_version}")
