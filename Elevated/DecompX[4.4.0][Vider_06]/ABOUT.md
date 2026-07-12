# DecompX

> Full-stack script decompiler & deobfuscator for malware research — Python/C/C++/Java/C#/.NET/JS/TS/PS1/VBE/Lua/PHP/Go/Rust/Ruby/Batch/Shell, EXE/PYC/PYZ/JAR/.class/.dll, semantic rename, CFF solver, XOR brute-force, call graph, data flow, YARA-lite, string clustering, threat scoring, entropy heatmap, packer fingerprinting, file metadata, coloured diff, tool checker, vx API. pycdc is an optional binary (not PyPI) — see github.com/zrax/pycdc. SCANNER NOTE: base64/marshal/exec used exclusively to ANALYSE target files, never to execute or exfiltrate. subprocess imported lazily inside functions only..

**Author:** [Vider_06](https://github.com/Vider_06)
**Version:** 4.4.0
**Class:** ⚡ Elevated
**Target OS:** Windows
**Min V0RTEX Version:** 1.0.1

---

## What it does

*(Add description here)*

## Elevated Permissions

List all granted elevated permissions and explain exactly how each one is used.

| Permission | Usage |
|---|---|
| `fs.read.external` |  |
| `fs.read.v0rtex.logs` |  |
| `fs.read.v0rtex.reports` |  |
| `fs.write.csv` |  |
| `fs.write.html` |  |
| `fs.write.json` |  |
| `fs.write.pdf` |  |
| `fs.write.xml` |  |
| `fs.write.zip` |  |
| `net.background` |  |
| `net.listen` |  |
| `proc.read` |  |
| `sys.read.env` |  |

> V0RTEX will display this list to the user before loading the plugin. The user must confirm.

## Dependencies

uncompyle6, decompyle3, pyinstxtractor

## Installation

Install via the Plugin Manager, or copy `DecompX.py` to:
```
V0rtex_System\V0RTEX_v<version>\plugins\
```
V0RTEX will show the full permission list on first load and ask for confirmation before the plugin runs.

## Usage

*(Add usage instructions here)*

## Notes

*(Add notes here)*
