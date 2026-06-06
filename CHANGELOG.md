# Changelog

All notable changes to `fastapi-m8` are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) · Versioning: [SemVer](https://semver.org/).

---

## [Unreleased]

---

## [1.2.0] — 2026-06-06 · Consume auth-sdk-m8 1.0.0 secure-by-default signing & binding (F1/F2)

> **Requires `auth-sdk-m8 >= 1.0.0`.** That release is **breaking**: the default
> access-token algorithm is now **RS256** (asymmetric / JWKS) and **strict `iss`/`aud`
> binding** is enforced. Review the opt-outs below before upgrading.

### Security

- **Factory-built apps inherit secure-by-default token validation (F1/F2).**
  `build_auth_deps()` passes the full settings object to `auth-sdk-m8`'s
  `build_access_validator()`, which now reads `ACCESS_TOKEN_ALGORITHM`,
  `TOKEN_ISSUER`/`TOKEN_AUDIENCE`, `TOKEN_STRICT_VALIDATION` and `JWKS_URI` directly.
  A service built on `fastapi-m8` therefore validates **RS256** tokens — resolving keys
  via **JWKS** when `JWKS_URI` is set — and **rejects wrong-`aud`/wrong-`iss` tokens out
  of the box**, with no extra wiring.
- **Effective validation posture is logged at build time** (`auth.validation algorithm=…
  strict=… jwks=… iss=… aud=… role=…`), mirroring the existing `revocation.mode` log so
  the inherited defaults are visible in startup logs.

### Changed

- **`auth-sdk-m8` pin updated to `>=1.0.0,<2.0.0`** and `COMPAT_MATRIX` gains a `1.2`
  entry requiring the same range (enforced at startup via `_assert_compat()`).

### Migration

- **Strict binding is on by default.** Settings now **fail closed at boot** unless both
  `TOKEN_ISSUER` and `TOKEN_AUDIENCE` are set. Single-service/dev deployments that do not
  need cross-service token boundaries can opt out with `TOKEN_STRICT_VALIDATION=false`.
- **RS256 is the default algorithm.** Provide `ACCESS_PUBLIC_KEY_FILE` (or `JWKS_URI` for
  zero-downtime rotation). Operators still on shared-secret signing must opt back in with
  `ACCESS_TOKEN_ALGORITHM=HS256` and `ACCESS_SECRET_KEY`.
- **Event-bus signing is on by default.** Inherited from `auth-sdk-m8 1.0.0`: settings
  require `EVENT_SIGNING_KEY` at boot unless `EVENT_SIGNING_ENABLED=false`. See the
  [auth-sdk-m8 1.0.0 migration guide](../auth-sdk-m8/CHANGELOG.md).
- `.env.example` and the README configuration reference are aligned with the new defaults
  and opt-outs.

---

## [1.1.4] — 2026-06-06 · Security hardening (fail-closed default, TrustedHostMiddleware, production docs gating)

### Security

- **`RemoteRevocationClient` now defaults to `fail_closed=True`** (F6).
  Previously the client was constructed with `fail_closed=False` regardless of the stack's
  configured posture, silently allowing revoked tokens through on network errors.
  Stacks that prefer availability over security can opt out with
  `ACCESS_REVOCATION_FAILURE_MODE=fail_open`.
- **`TrustedHostMiddleware` registered when `ALLOWED_HOSTS` is set** (F8).
  Requests whose `Host` header is not in the allowlist are rejected with HTTP 400.
  `testserver` is automatically allowed in non-production environments so tests continue
  to work without extra configuration. Leave `ALLOWED_HOSTS` empty (the default) for
  local/dev permissive mode.
- **Production docs gating via `effective_set_*` properties** (F5).
  `openapi_url`, `docs_url`, and `redoc_url` now use `settings.effective_set_open_api` /
  `effective_set_docs` / `effective_set_redoc` (from `auth-sdk-m8 ≥ 0.7.3`), which
  automatically disable all three doc endpoints when `ENVIRONMENT=production` and
  `SERVE_DOCS_IN_PRODUCTION` is not set. Non-production behaviour is unchanged.

### Changed

- **`auth-sdk-m8` pin updated to `>=0.7.3`** — required for the `effective_set_*`
  computed properties and `SERVE_DOCS_IN_PRODUCTION` opt-in.
- **`_version.py` aligned with `pyproject.toml`** — was incorrectly left at `1.1.2` after
  the 1.1.3 shell-script-permissions patch; now both reflect `1.1.4`.

---

## [1.1.3] — 2026-06-05 · Shell script permissions

### Fixed

- **`fastapi_m8/scripts/docker_start.sh` was stored as `100644`** in git.
  On hosts with `core.filemode=false` (WSL2, Windows, some CI runners) the missing
  execute bit caused `Permission denied` when the script was invoked directly from a
  bind-mounted Docker volume. Fixed via `git update-index --chmod=+x`.

---

## [1.1.2] — 2026-06-03 · Metrics initialisation + tagless-route fix

### Fixed

- **`_add_metrics_middleware` now calls `auth_sdk_m8.observability.metrics.setup()`** before
  adding `MetricsMiddleware`. Previously the middleware was registered but `_m` stayed `None`,
  so every request was a no-op and `/metrics` always returned empty output.
- **`generate_unique_id_function` no longer raises `IndexError`** on routes with an empty
  `tags` list (e.g. `include_in_schema=False` utility endpoints). The route name is used as
  the unique-id prefix when no tags are present.

---

## [1.1.0] — 2026-06-03 · Secure-by-default revocation + API cleanup

### Security

- **`build_auth_deps` now reads `ACCESS_REVOCATION_FAILURE_MODE`** from the stack settings
  (inherited via `CommonSettings`) and passes `fail_closed=` to `RemoteRevocationClient`.
  Previously the client was hard-wired to `fail_closed=False` (fail-open) regardless of the
  stack's configured posture.
  - The **effective mode is logged at INFO** on startup:
    `revocation.mode effective=<mode> (ACCESS_REVOCATION_FAILURE_MODE=<X>, AUTH_STRICT_MODE=<Y>)`.
  - A **security WARNING** is emitted on every request denied because revocation could not be
    verified: `security.revocation_denied jti=<jti> reason=unverifiable error=<exc>`.
  - **Default posture is now `fail_closed`** (requires `auth-sdk-m8>=0.7.1`; the default was
    changed there). Availability-first stacks set `ACCESS_REVOCATION_FAILURE_MODE=fail_open`;
    high-security stacks set `AUTH_STRICT_MODE=true`.

### Changed

- **`create_app` API uses `HealthConfig` / `AppLifecycle` dataclasses.** The flat keyword
  arguments `auth_deps=`, `db_engine=`, `health_checks=`, `health_check_timeout=`,
  `health_policy=`, `health_detail_public=`, `health_detail_authorizer=`, `health_cache_ttl=`,
  `startup_validators=`, `configure=`, `lifespan_extras=` are replaced by two structured objects.
  This was the actual shipped API in 1.0.0 — the README and example code were documenting the
  pre-refactor signature and crashed at import.

  **Migration:**
  ```python
  # Before (1.0.x README — never worked)
  app = create_app(settings, router, auth_deps=auth, db_engine=engine, health_checks=[check])

  # After (1.1.x — matches the actual code)
  from fastapi_m8 import AppLifecycle, HealthConfig
  app = create_app(
      settings,
      router,
      health=HealthConfig(checks=[check]),
      lifecycle=AppLifecycle(auth_deps=auth, db_engine=engine),
  )
  ```

- **`auth-sdk-m8` pin bumped to `>=0.7.1,<0.8.0`** — requires the lazy-redis and
  `ACCESS_REVOCATION_FAILURE_MODE` default fix in auth-sdk-m8 0.7.1.
- **`redis` dropped from core dependencies** — was only needed to paper over an eager import
  in auth-sdk-m8's `security/blacklist.py`. Fixed at the source in auth-sdk-m8 0.7.1.
- **`COMPAT_MATRIX["1.1"]` added** (`_compat.py`) — the compat guard now checks the correct
  range for 1.1.x installs. A missing key silently no-ops the guard; this entry makes it active.

### Removed

- **Dead `is_in_grace` / `STARTUP_GRACE_SECONDS`** (`_health.py`) — startup grace-window logic
  that was never wired into `create_app`. Deleted along with the 3 corresponding tests.

---

## [1.0.0] — 2026-05-26 · Initial release

### Added

- **`create_app(settings, router, *, service_name, service_version, health, lifecycle)`** —
  single-call factory that wires CORS, health endpoint, lifespan management, and auth/DB teardown.
- **`HealthConfig`** dataclass — health-check configuration (checks, timeout, policy,
  detail_public, detail_authorizer, cache_ttl).
- **`AppLifecycle`** dataclass — lifecycle configuration (auth_deps, db_engine,
  startup_validators, configure, lifespan_extras).
- **`ConsumerServiceSettings`** — extends `auth-sdk-m8`'s `CommonSettings` +
  `ConsumerAuthMixin` with service-specific fields (`API_PREFIX`, `AUTH_PREFIX`, DB fields).
- **`build_auth_deps(settings)`** — builds `AuthDeps` (JWT validator + revocation client +
  FastAPI dependency factories).
- **`create_db_engine(settings)`** — wraps SQLAlchemy engine with `session()` context manager
  and `session_dep()` FastAPI dependency.
- **`GET {API_PREFIX}/health/`** — liveness/readiness endpoint with scrubbed detail mode.
- **`fastapi-m8-prestart`** — console script that waits for DB readiness before booting.
- Runtime compat guard (`_compat._assert_compat`) against `auth-sdk-m8` version range.
