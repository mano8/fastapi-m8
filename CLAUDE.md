# fastapi-m8

## Layer
Platform (FastAPI application framework)

---

## Purpose
Application factory wiring `auth-sdk-m8` into FastAPI services using `fa-auth-m8`.

---

## Rules
- No business logic
- Only reusable service scaffolding
- Must remain minimal and reusable across services
- No coupling to fa-auth-m8 or any domain service

---

## Workspace integration

When nested in a workspace, locate the nearest ancestor containing
`.workspace/policy.index.json` and apply its `python` policy.

If no workspace policy exists, use this file, `pyproject.toml`, repository
documentation and existing CI as the authoritative local context.
