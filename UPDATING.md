# Submitting a Plugin Update

Every update to a Verified or Elevated plugin must go through a **full D.V.V. re-review** before publication. You cannot push changes directly.

---

## Who Can Submit Updates

Only the original author (the GitHub account on record in `plugin.json`). To transfer authorship, contact the D.V.V. via a Discussion.

---

## How to Submit

1. Go to **[Discussions](https://github.com/Vider06/V0rtex-Plugin-Official/discussions)**
2. Open a new Discussion in the **🔄 Update Requests** category
3. The form will pre-fill — complete every field, especially the changelog
4. Wait for the D.V.V. to respond

---

## Re-Review Process

Every update is treated as a brand new submission. The D.V.V. verifies:

- Full code for new malicious content or behavior changes
- Changelog accuracy vs actual code diff
- Dependency and permission changes
- Breaking changes and user impact

**Inaccurate changelogs = Level 3 violation.** The D.V.V. always checks the diff.

---

## Outcomes

### ✅ Accepted
- New version signed and published
- Old `.py` archived as `plugin_name_vX.X.X_archived.py`
- `plugin.json`, `CHANGELOG.md`, `VERIFICATION.md` updated
- Folder renamed: `PluginName[2.0.0][Author]`
- `manifest.json` updated
- Auto-update pushed to users
- Discussion closed

### 🔄 Changes Requested
Reply in the **same Discussion** — do not open a new one.

### ❌ Rejected — Cooldowns

| Reason | Cooldown |
|---|---|
| Minor issues | None |
| Moderate issues (undeclared dep, behavior change missing from changelog) | **3 days** |
| Serious issues (policy violation, misleading changelog) | **7 days** |
| Severe issues (malicious code, permission escalation attempt) | **Permanent ban** |

Submitting during a cooldown resets it.

---

## Version Numbering

`MAJOR.MINOR.PATCH` — new version must always be higher than current live version.

| Increment | When |
|---|---|
| `PATCH` | Bug fixes, no behavior change |
| `MINOR` | New features, backward compatible |
| `MAJOR` | Breaking changes, permission changes, significant rewrites |

---

*D.V.V. — Dipartimento di Verifica V0RTEX*
