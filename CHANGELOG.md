# Changelog

All notable changes to `fastapi-m8` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

---

## [1.5.0] — 2026-06-12 · Track auth-sdk-m8 1.2.1 tiered security headers; HSTS/CSP opt-in

> **Requires `auth-sdk-m8 >= 1.2.1`** — picks up the tiered response-header model. The
> always-on subset (`X-Content-Type-Options`, `X-Frame-Options`) and the production-gated
> subset (`Referrer-Policy`, `Permissions-Policy`) are unchanged; **HSTS and CSP are now
> express opt-in** instead of being inferred from the production gate.

### Changed

- `auth-sdk-m8` pin → `>=1.2.1,<2.0.0`; `COMPAT_MATRIX` gains a `1.5` entry for the same
  range. `create_app` keeps wiring `add_security_headers_middleware`; the tier change lives
  in the shared SDK so `fa-auth-m8` and every consumer move together.
- `ConsumerServiceSettings` inherits two new knobs from `CommonSettings`: `HSTS_ENABLED`
  and `CONTENT_SECURITY_POLICY_ENABLED` (both default `False`). No service redeclares them.
- README **Response Security Headers** section rewritten as a three-tier table with the
  opt-in rationale; security-header tests rewritten for the tiered model (local always-on
  subset, local HSTS/CSP hard-block even when opted in, production-without-opt-in, full
  opt-in, opt-in decoupled from the production gate on `staging`, master-switch suppression,
  `HSTS_MAX_AGE=0`, `includeSubDomains` off, custom CSP).

### ⚠️ Behaviour change

HSTS and CSP, emitted automatically in production by `fastapi-m8 1.3.0`–`1.4.0`, are now
**off until explicitly enabled** and are **never emitted when `ENVIRONMENT=local`** even
when opted in — preventing a production-configured build run on localhost from poisoning the
host's HSTS cache. To restore the previous production behaviour:

```ini
HSTS_ENABLED=true
CONTENT_SECURITY_POLICY_ENABLED=true
```

---

## [1.4.0] — 2026-06-11 · Auth event-stream consumer surface (SC)

> **Requires `auth-sdk-m8 >= 1.2.0`** — additive: ships the `events/` SSE client package.
> Consumers need no changes until they opt into the stream.

### Added

- `build_event_stream_client(settings, on_event=…, on_gap=…)` — convenience factory that
  constructs the SDK's `AuthEventStreamClient` straight from a `ConsumerServiceSettings`
  instance (derives the SSE stream URL from `INTROSPECTION_URL`, unwraps
  `PRIVATE_API_SECRET` / `EVENT_SIGNING_KEY`), so services wire the fa-auth event-stream
  bridge in their lifespan without touching SDK internals.
- Re-exports on the package root: `AuthEventStreamClient`, `AuthStreamEvent`,
  `derive_stream_url`.
- `EVENT_STREAM_CONNECT_TIMEOUT` (default `5`) and `EVENT_STREAM_READ_TIMEOUT`
  (default `60`) settings on `ConsumerServiceSettings` — client-side timeouts for the
  stream; keep the read timeout above fa-auth's heartbeat interval. Explicit factory args
  still override them.

### Changed

- `auth-sdk-m8` pin → `>=1.2.0,<2.0.0` and the `events` extra is now required;
  `COMPAT_MATRIX` gains a `1.4` entry for the same range.

### Fixed

- `.env.example` / README: replaced the stale `change-me-event-signing-32-chars`
  placeholder with the DEV-ONLY convention fa-auth uses
  (`DEV-ONLY-do-not-use-event-signing-key-Aa1!`); event-signing docs reframed around the
  SSE bridge (HMAC verification of stream payloads) rather than the deprecated Redis bus.

### Notes

- The stream is a **best-effort cache accelerator**, not the revocation authority — the JTI
  blacklist behind `INTROSPECTION_URL` remains source of truth. Stream loss is non-fatal.

---

## [1.3.0] — 2026-06-10 · Delegate security-header layer to auth-sdk-m8 1.1.0 (N2)

### Changed

- Response-hardening middleware moved into `auth-sdk-m8`
  (`auth_sdk_m8.security.headers.add_security_headers_middleware`); `create_app` now wires
  the shared SDK implementation so the auth provider and all consumers use one layer (N2).
  Emitted headers and behaviour are unchanged.
- The six header knobs (`SECURITY_HEADERS_ENABLED`, `HSTS_MAX_AGE`,
  `HSTS_INCLUDE_SUBDOMAINS`, `CONTENT_SECURITY_POLICY`, `REFERRER_POLICY`,
  `PERMISSIONS_POLICY`) are now inherited from `CommonSettings` instead of redeclared on
  `ConsumerServiceSettings`. Same names and defaults — no env/migration changes.
- Requires `auth-sdk-m8>=1.1.0`.

---

## [1.2.0] — 2026-06-06 · Consume auth-sdk-m8 1.0.0 secure-by-default signing & binding (F1/F2)

> **Requires `auth-sdk-m8 >= 1.0.0`** — a breaking release: default access-token algorithm
> is now **RS256** and **strict `iss`/`aud` binding** is enforced. Review opt-outs below.

### Security

- Factory-built apps inherit secure-by-default validation (F1/F2): `build_auth_deps()`
  passes the full settings object to `build_access_validator()`, which reads
  `ACCESS_TOKEN_ALGORITHM`, `TOKEN_ISSUER`/`TOKEN_AUDIENCE`, `TOKEN_STRICT_VALIDATION` and
  `JWKS_URI`. Result: RS256 validation (JWKS-resolved when `JWKS_URI` is set) and
  wrong-`aud`/wrong-`iss` rejection out of the box.
- Effective posture logged at build time (`auth.validation algorithm=… strict=… jwks=…
  iss=… aud=… role=…`), mirroring `revocation.mode`.

### Changed

- `auth-sdk-m8` pin → `>=1.0.0,<2.0.0`; `COMPAT_MATRIX` gains a `1.2` entry for the same range.

### Migration

- Strict binding is on by default — settings **fail closed at boot** unless both
  `TOKEN_ISSUER` and `TOKEN_AUDIENCE` are set. Opt out with `TOKEN_STRICT_VALIDATION=false`.
- RS256 is the default — provide `ACCESS_PUBLIC_KEY_FILE` (or `JWKS_URI`). Shared-secret
  signing must opt back in via `ACCESS_TOKEN_ALGORITHM=HS256` + `ACCESS_SECRET_KEY`.
- Event-bus signing is on by default — `EVENT_SIGNING_KEY` required at boot unless
  `EVENT_SIGNING_ENABLED=false`. See the
  [auth-sdk-m8 1.0.0 migration guide](../auth-sdk-m8/CHANGELOG.md).
- `.env.example` and README aligned with the new defaults/opt-outs.

---

## [1.1.4] — 2026-06-06 · Security hardening (fail-closed default, TrustedHostMiddleware, production docs gating)

### Security

- `RemoteRevocationClient` now defaults to `fail_closed=True` (F6) — previously always
  `fail_closed=False`, silently letting revoked tokens through on network errors. Opt out
  with `ACCESS_REVOCATION_FAILURE_MODE=fail_open`.
- `TrustedHostMiddleware` registered when `ALLOWED_HOSTS` is set (F8) — non-allowlisted
  `Host` headers get HTTP 400. `testserver` is auto-allowed in non-production. Empty
  (default) = permissive dev mode.
- Production docs gating (F5) — `openapi_url`/`docs_url`/`redoc_url` use
  `settings.effective_set_*` (from `auth-sdk-m8 ≥ 0.7.3`), disabling all three doc endpoints
  when `ENVIRONMENT=production` and `SERVE_DOCS_IN_PRODUCTION` is unset.

### Changed

- `auth-sdk-m8` pin → `>=0.7.3` (for `effective_set_*` + `SERVE_DOCS_IN_PRODUCTION`).
- `_version.py` realigned to `1.1.4` (was stale at `1.1.2` after the 1.1.3 patch).

---

## [1.1.3] — 2026-06-05 · Shell script permissions

### Fixed

- `fastapi_m8/scripts/docker_start.sh` was stored as `100644`; the missing execute bit
  caused `Permission denied` on `core.filemode=false` hosts (WSL2, Windows, some CI).
  Fixed via `git update-index --chmod=+x`.

---

## [1.1.2] — 2026-06-03 · Metrics initialisation + tagless-route fix

### Fixed

- `_add_metrics_middleware` now calls `auth_sdk_m8.observability.metrics.setup()` before
  adding `MetricsMiddleware` — previously `_m` stayed `None`, so every request was a no-op
  and `/metrics` returned empty.
- `generate_unique_id_function` no longer raises `IndexError` on tagless routes
  (e.g. `include_in_schema=False`); the route name is used as the prefix when no tags exist.

---

## [1.1.0] — 2026-06-03 · Secure-by-default revocation + API cleanup

### Security

- `build_auth_deps` reads `ACCESS_REVOCATION_FAILURE_MODE` and passes `fail_closed=` to
  `RemoteRevocationClient` (previously hard-wired to fail-open). Effective mode logged at
  INFO on startup; a WARNING is emitted per request denied for unverifiable revocation.
  Default posture is now `fail_closed` (requires `auth-sdk-m8>=0.7.1`). Opt out with
  `ACCESS_REVOCATION_FAILURE_MODE=fail_open`; tighten with `AUTH_STRICT_MODE=true`.

### Changed

- `create_app` now takes `HealthConfig` / `AppLifecycle` dataclasses instead of flat
  keyword args. This was the actual shipped 1.0.0 API — the 1.0.x README documented a
  signature that crashed at import.

  ```python
  # Before (1.0.x README — never worked)
  app = create_app(settings, router, auth_deps=auth, db_engine=engine, health_checks=[check])
  # After (1.1.x — matches the code)
  from fastapi_m8 import AppLifecycle, HealthConfig
  app = create_app(settings, router, health=HealthConfig(checks=[check]),
                   lifecycle=AppLifecycle(auth_deps=auth, db_engine=engine))
  ```

- `auth-sdk-m8` pin → `>=0.7.1,<0.8.0` (lazy-redis + revocation default fix).
- `redis` dropped from core deps (eager-import workaround fixed in auth-sdk-m8 0.7.1).
- `COMPAT_MATRIX["1.1"]` added so the compat guard checks the correct range.

### Removed

- Dead `is_in_grace` / `STARTUP_GRACE_SECONDS` startup-grace logic (`_health.py`), never
  wired into `create_app`, plus its 3 tests.

---

## [1.0.0] — 2026-05-26 · Initial release

### Added

- `create_app(settings, router, *, service_name, service_version, health, lifecycle)` —
  single-call factory wiring CORS, health endpoint, lifespan, and auth/DB teardown.
- `HealthConfig` and `AppLifecycle` dataclasses for health and lifecycle configuration.
- `ConsumerServiceSettings` — extends `CommonSettings` + `ConsumerAuthMixin` with
  service fields (`API_PREFIX`, `AUTH_PREFIX`, DB fields).
- `build_auth_deps(settings)` — builds `AuthDeps` (validator + revocation client +
  dependency factories).
- `create_db_engine(settings)` — SQLAlchemy wrapper with `session()` / `session_dep()`.
- `GET {API_PREFIX}/health/` — liveness/readiness endpoint with scrubbed detail mode.
- `fastapi-m8-prestart` — console script that waits for DB readiness before booting.
- Runtime compat guard (`_compat._assert_compat`) against the `auth-sdk-m8` range.
