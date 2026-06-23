# Changelog

All notable changes to `fastapi-m8` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [3.0.0] — 2026-06-23 · auth-sdk-m8 2.0.0 alignment — single-mount `/ping` + SDK major floor

> **MAJOR.** Two independent breaking changes, either of which alone forces this bump:
> (1) `mount_service_meta` single-mounts `/ping` at the effective prefix — callers that
> relied on a bare root `/ping` when a prefix is configured must switch container/sidecar
> probes to `{API_PREFIX}/ping`; (2) the **required** `auth-sdk-m8` floor crosses a major
> (`<2.0.0` → `>=2.0.0,<3.0.0`), which removed deprecated SDK APIs — `pip install -U
> fastapi-m8` now force-upgrades the SDK across that major. (Supersedes the never-released
> 2.2.0 label: the same work, correctly versioned as a major.)

### ⚠️ Breaking change — `/ping` is now single-mount

`auth-sdk-m8 2.0.0` removed the dual-mount behaviour introduced in 1.5.0. When `API_PREFIX`
is set (the normal consumer case), `/ping` is now mounted **only** at `{API_PREFIX}/ping`
(e.g. `/api/ping`). The root `/ping` no longer exists when a prefix is configured.

- **What was true in 2.1.x:** root `GET /ping` always returned 200 regardless of
  `API_PREFIX`; additionally `GET {API_PREFIX}/ping` was mounted (schema-hidden copy).
- **What is true in 3.0.x:** only `GET {API_PREFIX}/ping` exists when a prefix is set;
  only `GET /ping` (root) when no prefix is set. The single mount is **always in the
  OpenAPI schema** — it is no longer hidden.
- **Action required:** update container `livenessProbe` / sidecar healthcheck URLs from
  `/ping` → `{API_PREFIX}/ping` (e.g. `/api/ping`). No Python code change is needed.

### Changed

- **Requires `auth-sdk-m8 >= 2.0.0, < 3.0.0`** (was `>= 1.5.0, < 2.0.0`). The
  dependency floor, `COMPAT_MATRIX` `2.2` entry, and `pyproject.toml` pin are updated.
  auth-sdk-m8 2.0.0 also ships `ConsumerScope` / `ConsumerCredential` /
  `ConsumerCredentialRegistry` / `make_consumer_authorizer` (Phase 9.1) and the
  `SECURITY.md` mTLS guidance (Phase 9.2) — available to consumers via the SDK without
  any fastapi-m8 code change.

### Why the floor is a **major** — auth-sdk-m8 2.0.0 dropped deprecated APIs

auth-sdk-m8 2.0.0 is a major because it **removes** every previously-deprecated
surface. fastapi-m8 was never coupled to any of them, so no consumer-facing code,
import, or setting changes here — the full suite is green at 100 % against the SDK
2.0.0 final. The removals, and why fastapi-m8 is already clear of each:

- **Redis Pub/Sub event bus** (`auth_sdk_m8.redis_events`: `EventBus` /
  `EventPublisher` / `EventSubscriber`). fastapi-m8 consumes auth events over the
  **fa-auth SSE bridge** (`auth_sdk_m8.events.AuthEventStreamClient`, re-exported as
  `build_event_stream_client` / `AuthEventStreamClient` since 1.4.0), never the
  Redis bus. The retained signing helpers moved to `auth_sdk_m8.events._signing`
  (wire format unchanged); fastapi-m8 does not import them directly.
- **`ComSecurityHelper.decode_access_token`** + `LEGACY_ACCESS_TOKEN_VALIDATION_CONFIG`.
  fastapi-m8 validates tokens through `build_auth_deps()` → `build_access_validator`
  (`TokenValidator`), the non-deprecated path.
- **`TOKEN_ALGORITHM`** knob. `ConsumerServiceSettings` exposes `ACCESS_TOKEN_ALGORITHM`
  directly (RS256 default); the deprecated seeding knob was never surfaced.
- **Module-level `settings_customise_sources()`**. The `_FILE`/Vault source ordering
  comes from the retained `CommonSettings.settings_customise_sources` **classmethod**
  that `ConsumerServiceSettings` inherits — unchanged and still regression-tested.

---

## [2.1.0] — 2026-06-19 · Security-remediation hardening + proxy-routable `{API_PREFIX}/ping`

> **Requires `auth-sdk-m8 >= 1.5.0`** — `mount_service_meta` dual-mounts `/ping`.

### Added

- **Proxy-routable `/ping`** picked up from `auth-sdk-m8 1.5.0`. `mount_service_meta`
  now dual-mounts the liveness probe: the unchanged root `GET /ping` **plus** a
  `GET {API_PREFIX}/ping` copy. `create_app` already passes `prefix=API_PREFIX`, so
  the prefixed probe appears automatically with **no call-site change** — liveness
  now resolves behind a prefix-routing reverse proxy (Traefik forwards only
  `PathPrefix({API_PREFIX})`, so the root-only `/ping` previously 404'd at the
  gateway while `{API_PREFIX}/meta` resolved). The prefixed copy is
  `include_in_schema=False`, so OpenAPI still carries a single `ping` operation.
- **`_FILE` secret mounts for consumers** (security remediation 6.1). Documented and
  regression-tested that `ConsumerServiceSettings` inherits the Docker/K8s
  `<FIELD>_FILE` convention from `auth-sdk-m8`'s `CommonSettings` — no consumer code
  change. Any secret can be mounted from a file via `<FIELD>_FILE` (e.g.
  `DB_PASSWORD_FILE`, `PRIVATE_API_SECRET_FILE`, `METRICS_SCRAPE_CREDENTIAL_FILE`)
  pointing under `/run/secrets/*`, so the production overlay keeps plaintext secrets
  out of env files. The mount outranks plaintext `.env`/env values but not explicit
  constructor kwargs; a missing file fails closed at construction; file-sourced
  `SecretStr` values stay masked in `repr`. Coverage spans consumer-declared
  (`METRICS_SCRAPE_CREDENTIAL`), `ConsumerAuthMixin` (`PRIVATE_API_SECRET`), and
  `CommonSettings` (`DB_PASSWORD`) fields.
- **Revocation-cache observability** (security remediation 7.x.2). The consumer-side
  JTI revocation cache now emits best-effort Prometheus metrics on the shared
  `auth-sdk-m8[observability]` registry: `revocation_cache_lookups_total{result="hit"|"miss"}`
  and a `revocation_cache_ttl_seconds` gauge for the configured stale-window TTL. Emission
  is zero-cost when observability is disabled or the extra is absent. Metrics carry **no
  JTI, user ID, or secret** as a label or value, and cache construction logs the TTL only
  (never the introspection URL or secret) — satisfying the "keys/secrets are never logged"
  acceptance criterion. The SDK owns the event-stream signals (connected/gap/reconnect);
  this is the consumer cache hit/miss + TTL side.
- `create_app` now **auto-runs the shared `check_config_health()`** (from
  `auth_sdk_m8.core.config`) as an internal startup validator, **prepended** to any
  caller-provided `startup_validators`. It runs inside the lifespan (not at import time),
  so a fatal misconfiguration (e.g. production `localhost` CORS origins, a wildcard
  `ALLOWED_HOSTS` under strict mode) aborts startup with `ConfigurationError` **before**
  user validators run and before the service is marked ready. Consumers now get the same
  production safety checks the auth service already runs, automatically.

### Changed

- **Requires `auth-sdk-m8 >= 1.5.0`** (was `>= 1.4.0`). The dependency floor and the
  `COMPAT_MATRIX` `2.1` entry are bumped so the dual-mounted `{API_PREFIX}/ping` is
  guaranteed present; on `auth-sdk-m8 1.4.0` only the root `/ping` exists.
- `ALLOWED_HOSTS` is no longer redefined on `ConsumerServiceSettings` — it is inherited
  from `CommonSettings` (auth-sdk-m8), the single source of truth. The default is now
  `None` (unset) rather than `[]`; both are falsy, so `TrustedHostMiddleware` is still
  skipped when unset. Production/strict gating lives in `check_config_health`.

---

## [2.0.0] — 2026-06-16 · Auto-mounted `/meta` + `/ping`; required service metadata

> **Requires `auth-sdk-m8 >= 1.4.0`** — uses `mount_service_meta` + `ServiceMeta` from the SDK.

**BREAKING.** `create_app` now auto-mounts the standard m8 service triad alongside `/health`:

- `GET {API_PREFIX}/meta` — static, cacheable `ServiceMeta` (service/version/contract) read by
  clients pre-auth to assert compatibility. No duplicate route logic — it calls auth-sdk-m8's
  `mount_service_meta`.
- `GET /ping` — prefix-independent, dependency-free liveness (`{"status": "ok"}`).

### Added

- `ConsumerServiceSettings` gains `SERVICE_VERSION`, `CONTRACT_VERSION`, `CONTRACT_RANGE`
  (**required**), plus `API_VERSION` (default `v1`) and `CONTRACT_NAME` (defaults to
  `PROJECT_NAME`), and a `build_service_meta()` helper. Every consumer now **fails closed at
  boot** if it doesn't declare its service/contract identity.

### Changed

- `_openapi_config` falls back to `settings.SERVICE_VERSION` (single source of truth) instead of
  the previous `"0.0.0"` literal when `service_version` isn't passed to `create_app`.
- `auth-sdk-m8` dependency bumped to `>=1.4.0,<2.0.0`; compat matrix adds the `2.0` row.

### Migration

Every consumer must set `SERVICE_VERSION`, `CONTRACT_VERSION`, and `CONTRACT_RANGE` (e.g. in
`.env` / `.env.example`) before it will boot. Point container **liveness** probes at `/ping` and
**readiness** probes at `{API_PREFIX}/health/`.

---

## [1.6.0] — 2026-06-13 · Track auth-sdk-m8 1.3.0; expose `CurrentUser.tenant_id`

> **Requires `auth-sdk-m8 >= 1.3.0`** — picks up the optional `tenant_id` claim added to the
> token payload (`TokenAccessData`/`TokenUserData`) and to `UserModel`. No logic change in
> `fastapi-m8`: `_build_active_user` already forwards every payload field into `UserModel`, so
> the new claim flows through to `CurrentUser.tenant_id` automatically.

### Changed

- `auth-sdk-m8` pin → `>=1.3.0,<2.0.0`; `COMPAT_MATRIX` gains a `1.6` entry for the same range.
  Services injecting `auth.CurrentUser` now see `current_user.tenant_id` populated (a `UUID`)
  whenever the issuing token carries the claim, and `None` for untenanted/legacy tokens.

### Added

- `test_deps`: passthrough assertions pinning the contract that `_build_active_user` forwards
  `tenant_id` — a token carrying the claim yields a `UserModel` whose `.tenant_id` is the
  expected `UUID`; a token without it yields `None`.

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
