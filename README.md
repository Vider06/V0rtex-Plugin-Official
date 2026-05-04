<div align="center">

# V0RTEX Plugin Hub

**The official home for V0RTEX plugins.**

Browse, install, and publish plugins for the [V0RTEX malware analysis platform](https://github.com/Vider06/V0rtex).

[![Verified](https://img.shields.io/badge/Verified-✅-brightgreen)]()
[![Elevated](https://img.shields.io/badge/Elevated-⚡-yellow)]()
[![V0RTEX--Made](https://img.shields.io/badge/V0RTEX--Made-🔴-red)]()

</div>

---

## What is this repository?

This is the official V0RTEX Plugin Hub — the central place where all Verified, Elevated, and V0RTEX-Made plugins are published, reviewed, and maintained by the **S.E.A (Security Enforcement Authoritie**.

| I want to... | Go to |
|---|---|
| Find and install plugins | Browse `Verified/`, `Elevated/`, or `V0RTEX-Made/` below |
| Submit my plugin for review | [SUBMITTING.md](SUBMITTING.md) |
| Submit a plugin update | [UPDATING.md](UPDATING.md) |
| Read the full plugin policy | [POLICY.md](POLICY.md) |
| Report a malicious plugin | [Discussions → 🚨 Report](https://github.com/Vider06/V0rtex-Plugin-Official/discussions) |
| See recognized developers | [HALL_OF_FAME.md](HALL_OF_FAME.md) |

---

## Plugin Classes

| Class | Description | Trust |
|---|---|---|
| 🔴 V0RTEX-Made | Written by Vider_06. Full V0RTEX access. | Maximum |
| ⚡ Elevated | Verified + explicit special permissions. | High |
| ✅ Verified | Reviewed, signed, limited V0RTEX API. | Standard |
| ⚠️ Unverified | Not here — user-installed at their own risk. | None |
| 🚫 Banned | Permanently blocked in V0RTEX. | — |

---

## Repository Structure

```
V0rtex-Plugin-Official/
├── .github/
│   ├── DISCUSSION_TEMPLATE/     ← pre-filled forms for submissions and reports
│   └── ISSUE_TEMPLATE/
│
├── Verified/
│   └── PluginName[version][Author]/
│       ├── plugin_name.py
│       ├── plugin.json
│       ├── CHANGELOG.md
│       ├── ABOUT.md
│       └── VERIFICATION.md
│
├── Elevated/
│   └── PluginName[version][Author]/   (same structure)
│
├── V0RTEX-Made/
│   └── PluginName[version][Vider06]/  (same structure)
│
├── README.md
├── SUBMITTING.md
├── UPDATING.md
├── POLICY.md
├── HALL_OF_FAME.md
├── LICENSE.md
└── manifest.json
```

> ⚠️ The Banned plugin list is maintained in a **separate private repository** accessible only to the D.V.V. V0RTEX queries it automatically at startup — it is never exposed publicly.

---

## Plugin Folder Naming

Every plugin folder follows this exact naming convention:

```
PluginName[version][AuthorGitHubUsername]
```

The folder name is updated by the D.V.V. whenever a new version is accepted.

---

## Plugin Manager

The **V0RTEX Plugin Manager** (`plugin_manager.py`) is a standalone tool that lets you browse, install, update, and uninstall plugins directly — without manually copying files.

**Download:** [plugin_manager.py](plugin_manager.py) *(coming soon)*

---

## Links

| Resource | URL |
|---|---|
| V0RTEX | https://github.com/Vider06/V0rtex |
| V0RTEX Plugin Hub | https://github.com/Vider06/V0rtex-Plugin-Official |
| Banned Plugins (private) | https://github.com/Vider06/V0rtex-Banned-Plugins |

---

*V0RTEX Plugin Hub — © 2024–2026 Vider_06. All rights reserved.*

---

## plugin.json — Field Reference (D.V.V. / S.E.A.)

This section documents the fields in each plugin's `plugin.json` that are relevant to V0RTEX at runtime. All fields are written and maintained by the S.E.A. — plugin authors do not set these manually.

| Field | Type | Description |
|---|---|---|
| `hash_full` | string | SHA-256 of the exact plugin `.py` file as verified by S.E.A. |
| `hash_structural` | string | SHA-256 of the file with all `#` comments and docstrings removed |
| `hash_ast` | string | SHA-256 of the normalized AST (variable/function names stripped) |
| `ast_token_count` | integer | AST node count used for similarity scoring |
| `violation` | object or null | Active S.E.A. enforcement record (Level 1 or 2). `null` if no active violation. |

### violation object format

```json
"violation": {
  "level": 1,
  "reason": "Short description of the violation",
  "fix_deadline": "YYYY-MM-DD"
}
```

- `level` — `1` (Warning, plugin remains loadable) or `2` (Suspension, plugin blocked)
- `reason` — human-readable reason shown to the user in V0RTEX
- `fix_deadline` — ISO date by which the developer must fix the issue. Empty string if not applicable.

Level 3 and 4 violations are not stored here — they result in the plugin being added to the private Banned list (`V0rtex-Banned-Plugins`) and removed from this repository entirely.

When `violation` is `null`, V0RTEX treats the plugin as clean. When it contains a Level 1 object, V0RTEX shows a 🟡 badge in CFG → PLUGINS. Level 2 shows 🟠 and the plugin cannot be enabled.
