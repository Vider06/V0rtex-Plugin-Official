# Submitting a Plugin for Verification

This document explains how to submit your plugin to be reviewed by the D.V.V. and published in the [V0RTEX Plugin Hub](https://github.com/Vider06/V0rtex-Plugin-Official).

---

## Before You Submit

Your plugin must meet **all** of the following:

- [ ] Header complete and accurate, with `Class: Unverified`
- [ ] Tested and working on the target OS with Python 3.10+
- [ ] Has its own **public** GitHub repository with a README
- [ ] All third-party dependencies declared in the header
- [ ] `on_unload()` implemented if the plugin opens files or spawns threads
- [ ] Does not violate any rule in [POLICY.md](POLICY.md)
- [ ] `Background-Network` and `Background-Endpoints` correctly filled
- [ ] `Min-V0RTEX-Version` set correctly

Incomplete submissions are closed immediately without review.

---

## How to Submit

1. Go to **[Discussions](https://github.com/Vider06/V0rtex-Plugin-Official/discussions)**
2. Open a new Discussion in the **🔖 Verification Requests** category
3. The form will pre-fill — complete every field
4. Wait for the D.V.V. to respond — **no guaranteed timeline**

---

## Review Process

1. D.V.V. reviews for malicious content, policy compliance, and API correctness
2. **Accepted** → plugin signed, folder created, published, Discussion closed as Accepted
3. **Changes needed** → D.V.V. comments — update and reply in the **same Discussion**
4. **Rejected** → Discussion closed with reason

Do not open duplicate submissions for the same plugin.

---

## What Gets Created on Acceptance

```
Verified/
└── PluginName[1.0.0][YourUsername]/
    ├── plugin_name.py       ← your script
    ├── plugin.json          ← metadata (filled by D.V.V.)
    ├── CHANGELOG.md         ← initial entry (filled by D.V.V.)
    ├── ABOUT.md             ← your plugin README (copied from your repo)
    └── VERIFICATION.md      ← D.V.V. review record
```

---

## Requesting Elevated Permissions

Only after your plugin is already Verified. Open a Discussion in **⚡ Elevated Permission Requests** specifying which permissions you need (exact IDs from [POLICY.md](POLICY.md)) and why.

---

*D.V.V. — Dipartimento di Verifica V0RTEX*
