# fastapi-m8

FastAPI application framework for building consumer microservices that integrate with
[fa-auth-m8](../fa-auth-m8). It wires authentication, CORS, health checks, observability,
and database lifecycle into a single `create_app()` call, removing ~90 % of the setup
boilerplate from every consumer service.

---

## Table of Contents

1. [Summary](#summary)
2. [Architecture & Package Roles](#architecture--package-roles)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Configuration Reference](#configuration-reference)
6. [API Reference](#api-reference)
   - [create_app()](#create_app)
   - [ConsumerServiceSettings](#consumerservicesettings)
   - [build_auth_deps()](#build_auth_deps)
   - [create_db_engine()](#create_db_engine)
   - [Health Checks](#health-checks)
7. [Authentication](#authentication)
   - [Token Modes](#token-modes)
   - [Role System](#role-system)
   - [Protecting Routes](#protecting-routes)
8. [Health Endpoint](#health-endpoint)
9. [Database Integration](#database-integration)
10. [Pre-Start Script](#pre-start-script)
11. [Complete Example](#complete-example)
12. [Testing](#testing)
13. [Compatibility](#compatibility)

---

## Summary

`fastapi-m8` is a thin application factory layer that sits on top of FastAPI and
[auth-sdk-m8](../auth-sdk-m8). You bring a settings object, a router, and optional
health checks; the framework wires the rest.

**What it provides:**

| Capability | How |
|---|---|
| JWT validation | `build_auth_deps()` + `auth-sdk-m8` validator |
| Role-based access control | `AuthDeps.get_current_active_admin / _superuser` |
| Token revocation (stateful mode) | `RemoteRevocationClient` → `fa-auth-m8` private API |
| CORS | Auto-wired from `settings.ALLOWED_ORIGINS` |
| Metrics middleware | Optional; toggled via `METRICS_ENABLED` |
| Health endpoint | `GET {API_PREFIX}/health/` with optional detail gating |
| Database lifecycle | `create_db_engine()` wrapping SQLAlchemy |
| Startup validation | `startup_validators` list runs before app signals ready |
| Lifespan management | Auth teardown + DB pool dispose on shutdown |

**What it is NOT:**
- Not an auth issuer — that role belongs to `fa-auth-m8`.
- Not a business logic framework — it only provides plumbing and dependency injection.

---

## Architecture & Package Roles

```
┌───────────────────────────────────────────────────────────────┐
│  Your consumer service  (uses fastapi-m8)                     │
│                                                               │
│  create_app(settings, router, auth_deps=auth, ...)           │
│  ├─ ConsumerServiceSettings ← auth-sdk-m8 CommonSettings     │
│  ├─ build_auth_deps(settings)                                 │
│  │   ├─ TokenValidator (local JWT check, auth-sdk-m8)        │
│  │   └─ RemoteRevocationClient (stateful only, HTTP)          │
│  └─ auto-wired: CORS · metrics · health · lifespan           │
└────────────────────────┬──────────────────────────────────────┘
                         │ Authorization: Bearer <JWT>
                         │ (stateful) POST /private/v1/jti-status
                         ▼
┌───────────────────────────────────────────────────────────────┐
│  fa-auth-m8  (auth_user_service)                              │
│                                                               │
│  POST /user/login/access-token   → issues JWT pair           │
│  POST /user/login/refresh-token/ → rotates tokens            │
│  POST /private/v1/jti-status     → revocation check          │
│                                                               │
│  Backing stores: MySQL / PostgreSQL · Redis                   │
└───────────────────────────────────────────────────────────────┘
```

**Three packages, three responsibilities:**

| Package | Role |
|---|---|
| `fa-auth-m8` | Issues and revokes JWT tokens, manages users and sessions |
| `auth-sdk-m8` | Shared schemas, JWT validation, settings base classes (read-only) |
| `fastapi-m8` | Wires `auth-sdk-m8` into a FastAPI consumer service |

---

## Installation

```bash
# Minimal (no database)
pip install fastapi-m8

# With PostgreSQL
pip install "fastapi-m8[postgres]"

# With MySQL
pip install "fastapi-m8[mysql]"

# With database (driver-agnostic, you choose the driver)
pip install "fastapi-m8[db]"

# Everything
pip install "fastapi-m8[all]"
```

**Runtime requirements:** Python 3.11+

---

## Quick Start

### 1 — Settings

```python
# app/core/config.py
from pathlib import Path
from pydantic_settings import SettingsConfigDict
from fastapi_m8 import ConsumerServiceSettings

class Settings(ConsumerServiceSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

settings = Settings()
```

### 2 — Auth & DB dependencies

```python
# app/core/deps.py
from fastapi_m8 import build_auth_deps, create_db_engine
from app.core.config import settings

auth = build_auth_deps(settings)
engine = create_db_engine(settings)
```

### 3 — Routes

```python
# app/api/items.py
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlmodel import Session
from app.core.deps import auth, engine

router = APIRouter(prefix="/items", tags=["items"])
SessionDep = Annotated[Session, Depends(engine.session_dep)]

@router.get("/")
async def list_items(user: auth.CurrentUser, session: SessionDep):
    return {"owner": user.email}
```

### 4 — App factory

```python
# app/main.py
from fastapi import APIRouter
from fastapi_m8 import create_app, HealthCheckResult, HealthStatus
from sqlmodel import select
from app.core.config import settings
from app.core.deps import auth, engine
from app.api.items import router as items_router

async def check_db() -> HealthCheckResult:
    try:
        with engine.session() as s:
            s.exec(select(1))
        return HealthCheckResult.from_bool("database", True)
    except Exception as exc:
        return HealthCheckResult(name="database", status=HealthStatus.FAIL, error=str(exc))

api_router = APIRouter()
api_router.include_router(items_router)

app = create_app(
    settings,
    api_router,
    service_name="Item Service",
    service_version="1.0.0",
    auth_deps=auth,
    db_engine=engine,
    health_checks=[check_db],
)
```

### 5 — `.env`

```ini
DOMAIN=localhost
ENVIRONMENT=local
PROJECT_NAME=Item Service
STACK_NAME=local
API_PREFIX=/api
AUTH_PREFIX=/auth
BACKEND_HOST=http://localhost:8000
FRONTEND_HOST=http://localhost:3000
BACKEND_CORS_ORIGINS=http://localhost:3000

# Token signing — must match fa-auth-m8
ACCESS_TOKEN_ALGORITHM=HS256
ACCESS_SECRET_KEY=change-me-32-chars-minimum
REFRESH_SECRET_KEY=change-me-refresh-32-chars-min

TOKEN_MODE=stateless
AUTH_SERVICE_ROLE=consumer

# Database
DB_HOST=localhost
DB_PORT=5432
DB_DATABASE=items_db
DB_USER=app_user
DB_PASSWORD=secret
```

Run with:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## Configuration Reference

All settings inherit from `auth-sdk-m8`'s `CommonSettings`. Every field maps 1:1 to an
environment variable.

### Core / Network

| Variable | Required | Default | Description |
|---|---|---|---|
| `DOMAIN` | Yes | — | Public domain, e.g. `localhost` |
| `ENVIRONMENT` | Yes | — | `local` \| `development` \| `staging` \| `production` |
| `PROJECT_NAME` | Yes | — | Human-readable service name (shown in docs) |
| `STACK_NAME` | Yes | — | Docker Compose stack slug |
| `API_PREFIX` | Yes | — | URL prefix for this service's routes, e.g. `/api` |
| `AUTH_PREFIX` | No | `/auth` | Auth endpoint prefix (consumer services) |
| `BACKEND_HOST` | Yes | — | Full backend URL, e.g. `http://127.0.0.1:8000` |
| `FRONTEND_HOST` | Yes | — | Full frontend URL |
| `BACKEND_CORS_ORIGINS` | Yes | — | Comma-separated allowed origins |

### Tokens & Cryptography

| Variable | Required | Default | Description |
|---|---|---|---|
| `TOKEN_MODE` | No | `stateful` | `stateless` \| `hybrid` \| `stateful` (see [Token Modes](#token-modes)) |
| `AUTH_SERVICE_ROLE` | No | `issuer` | Set to `consumer` in all consumer services |
| `ACCESS_TOKEN_ALGORITHM` | No | `HS256` | `HS256` \| `RS256` \| `ES256` |
| `ACCESS_SECRET_KEY` | HS256 only | — | Shared symmetric signing key (≥ 32 chars) |
| `REFRESH_SECRET_KEY` | Yes | — | Refresh token signing key |
| `ACCESS_PUBLIC_KEY_FILE` | RS256/ES256 | — | Path to PEM public key file |
| `JWKS_URI` | RS256/ES256 alt | — | JWKS endpoint URL (auto-fetches and caches public keys) |
| `JWKS_CACHE_TTL_SECONDS` | No | `300` | JWKS key cache TTL in seconds |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | `30` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_MINUTES` | No | `120` | Refresh token lifetime |
| `TOKEN_ISSUER` | No | — | Embeds and enforces `iss` claim when set |
| `TOKEN_AUDIENCE` | No | — | Embeds and enforces `aud` claim when set |

### Stateful Mode (consumer → auth service)

Required only when `TOKEN_MODE=stateful` and `AUTH_SERVICE_ROLE=consumer`.

| Variable | Required | Default | Description |
|---|---|---|---|
| `INTROSPECTION_URL` | Yes | — | `POST` endpoint on auth service for JTI revocation checks, e.g. `http://auth_user_service:8000/user/private/v1/jti-status` |
| `PRIVATE_API_SECRET` | Yes | — | Shared secret for `X-Internal-Token` header (must match auth service) |

### Database

| Variable | Required | Default | Description |
|---|---|---|---|
| `SELECTED_DB` | No | `Mysql` | `Mysql` \| `Postgres` |
| `DB_HOST` | Yes | — | Database host |
| `DB_PORT` | Yes | — | Database port |
| `DB_DATABASE` | Yes | — | Database name |
| `DB_USER` | Yes | — | Database user |
| `DB_PASSWORD` | Yes | — | Database password |
| `TABLES_PREFIX` | No | `app` | Table name prefix |

### Redis

Required when `TOKEN_MODE=stateful` or `hybrid` on the **issuer** side. Consumer services
do not connect to Redis directly.

| Variable | Description |
|---|---|
| `REDIS_HOST` | Redis host |
| `REDIS_PORT` | Redis port |
| `REDIS_USER` | Redis username |
| `REDIS_PASSWORD` | Redis password |
| `REDIS_SSL` | Enable TLS (`true`/`false`, default `false`) |

### Observability

| Variable | Default | Description |
|---|---|---|
| `METRICS_ENABLED` | `false` | Enable Prometheus metrics middleware |
| `METRICS_GROUPS` | — | Comma-separated groups: `traffic`, `performance`, `reliability`, `health`, `auth`, or `all` |

### OpenAPI / Docs

| Variable | Description |
|---|---|
| `SET_OPEN_API` | Expose `/openapi.json` |
| `SET_DOCS` | Expose Swagger UI |
| `SET_REDOC` | Expose ReDoc |

---

## API Reference

### `create_app()`

```python
from fastapi_m8 import create_app

app = create_app(
    settings: ConsumerServiceSettings,
    router: APIRouter,
    *,
    service_name: str | None = None,
    service_version: str | None = None,
    auth_deps: AuthDeps | None = None,
    db_engine: DbEngine | None = None,
    health_checks: list[HealthCheck] | None = None,
    health_check_timeout: float = 0.5,
    health_policy: HealthAggregatePolicy = HealthAggregatePolicy.LENIENT,
    health_detail_public: bool = False,
    health_detail_authorizer: Callable | None = None,
    health_cache_ttl: float = 2.0,
    startup_validators: list[Callable] | None = None,
    configure: Callable[[FastAPI], None] | None = None,
    lifespan_extras: Callable | None = None,
) -> FastAPI
```

**Parameters:**

| Parameter | Description |
|---|---|
| `settings` | Service settings object (subclass of `ConsumerServiceSettings`) |
| `router` | Your domain `APIRouter` (all routes are mounted under this) |
| `service_name` | Overrides `settings.PROJECT_NAME` in health detail response |
| `service_version` | Reported in health detail response |
| `auth_deps` | Output of `build_auth_deps()`. Closed on shutdown |
| `db_engine` | Output of `create_db_engine()`. Disposed on shutdown |
| `health_checks` | List of async callables returning `HealthCheckResult` |
| `health_check_timeout` | Per-check timeout in seconds (default `0.5`) |
| `health_policy` | `LENIENT` (default) or `STRICT` — controls when 503 is returned |
| `health_detail_public` | Expose check details without authentication |
| `health_detail_authorizer` | Custom async callable; receives `Request`, return `bool` |
| `health_cache_ttl` | How long to cache health results in seconds (default `2.0`) |
| `startup_validators` | Async callables run before app signals ready; raise to abort |
| `configure` | Callback receiving the raw `FastAPI` instance for custom middleware |
| `lifespan_extras` | Async context manager run inside the managed lifespan |

**Lifespan sequence:**
1. Run `startup_validators` — raise any exception to prevent ready signal.
2. Enter `lifespan_extras` context (if provided).
3. Set `app.state.service_ready = True`.
4. *(app serves traffic)*
5. Exit `lifespan_extras`.
6. Call `auth_deps.close()` (closes revocation HTTP client).
7. Call `db_engine.dispose()` (closes connection pool).

---

### `ConsumerServiceSettings`

```python
from fastapi_m8 import ConsumerServiceSettings
```

Base settings class. Subclass it and configure `model_config` for your `.env` file.

```python
from pydantic_settings import SettingsConfigDict
from fastapi_m8 import ConsumerServiceSettings

class Settings(ConsumerServiceSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()

# Useful computed properties (inherited from auth-sdk-m8)
settings.is_stateless        # bool
settings.is_stateful         # bool
settings.ALLOWED_ORIGINS     # list[str] — derived from BACKEND_CORS_ORIGINS
settings.SQLALCHEMY_DATABASE_URI  # str — assembled from DB_* fields
```

---

### `build_auth_deps()`

```python
from fastapi_m8 import build_auth_deps, AuthDeps

auth: AuthDeps = build_auth_deps(settings)
```

Returns a frozen dataclass with everything needed for route protection.

| Field | Type | Description |
|---|---|---|
| `auth.CurrentUser` | `Annotated[UserModel, Depends(...)]` | Inject authenticated user into routes |
| `auth.get_current_user` | `async Callable` | FastAPI dependency; validates JWT, checks revocation |
| `auth.get_current_active_admin` | `Callable` | Raises 403 unless user has ADMIN or SUPERADMIN role |
| `auth.get_current_active_superuser` | `Callable` | Raises 403 unless user has SUPERADMIN role and `is_superuser=True` |
| `auth.revocation_client` | `RemoteRevocationClient \| None` | Present only in stateful mode |

**`UserModel` fields available in routes:**

| Field | Type | Description |
|---|---|---|
| `id` | `int` | User primary key |
| `email` | `str` | User email |
| `full_name` | `str \| None` | Display name |
| `role` | `RoleType` | `USER` \| `READER` \| `WRITER` \| `ADMIN` \| `SUPERADMIN` |
| `is_active` | `bool` | Account active flag |
| `is_superuser` | `bool` | Superuser flag |
| `email_verified` | `bool` | Email verification status |

---

### `create_db_engine()`

```python
from fastapi_m8 import create_db_engine, DbEngine

engine: DbEngine = create_db_engine(settings)
```

Wraps SQLAlchemy engine assembled from `settings.SQLALCHEMY_DATABASE_URI`.

| Method | Description |
|---|---|
| `engine.session()` | Context manager yielding a `Session` |
| `engine.session_dep()` | FastAPI dependency (use with `Depends`) |
| `engine.dispose()` | Closes connection pool (called automatically on shutdown) |

```python
from typing import Annotated
from fastapi import Depends
from sqlmodel import Session

SessionDep = Annotated[Session, Depends(engine.session_dep)]

@router.post("/items")
async def create_item(session: SessionDep, item: ItemCreate):
    session.add(Item.model_validate(item))
    session.commit()
```

---

### Health Checks

Implement the `HealthCheck` protocol — any async callable returning `HealthCheckResult`.

```python
from fastapi_m8 import HealthCheck, HealthCheckResult, HealthStatus

# Function-based
async def check_database() -> HealthCheckResult:
    try:
        with engine.session() as s:
            s.exec(select(1))
        return HealthCheckResult.from_bool("database", True)
    except Exception as exc:
        return HealthCheckResult(name="database", status=HealthStatus.FAIL, error=str(exc))

# Class-based (useful when state is needed)
class RedisCheck:
    def __init__(self, client):
        self._client = client

    async def __call__(self) -> HealthCheckResult:
        try:
            await self._client.ping()
            return HealthCheckResult.from_bool("redis", True)
        except Exception as exc:
            return HealthCheckResult(name="redis", status=HealthStatus.FAIL, error=str(exc))
```

`HealthCheckResult` fields:

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Check identifier |
| `status` | `HealthStatus` | `ok` \| `degraded` \| `fail` \| `unknown` |
| `latency_ms` | `float \| None` | Auto-populated by the health subsystem |
| `error` | `str \| None` | Error message (credentials automatically scrubbed) |
| `meta` | `dict \| None` | Arbitrary metadata (sensitive keys auto-redacted) |
| `ok` | `bool` | Computed: `True` when status is `ok` |

`HealthAggregatePolicy`:

| Value | HTTP 503 when |
|---|---|
| `LENIENT` (default) | Any check is `fail` |
| `STRICT` | Any check is `fail` or `unknown` |

---

## Authentication

### Token Modes

Configured via `TOKEN_MODE` on **both** the auth service and all consumer services.
The value must match across the stack.

| Mode | Access token revocation | Requires Redis (issuer) | Google OAuth |
|---|---|---|---|
| `stateless` | None (waits for expiry) | No | No |
| `hybrid` | None for access; refresh is allowlisted | Yes | Yes |
| `stateful` | Immediate, via JTI introspection | Yes | Yes |

**Stateless** — maximum scalability, simplest setup. Logout does not invalidate
in-flight access tokens; they expire naturally.

**Stateful** — highest security. On each request a consumer performs an HTTP call to
`fa-auth-m8` to verify the JWT's JTI has not been revoked. Requires `INTROSPECTION_URL`
and `PRIVATE_API_SECRET` in consumer settings.

**Algorithm options:**

| Algorithm | Key config | Use case |
|---|---|---|
| `HS256` | `ACCESS_SECRET_KEY` (symmetric, shared) | Simple single-service or trusted internal network |
| `RS256` | `ACCESS_PUBLIC_KEY_FILE` or `JWKS_URI` | Multi-service; consumers need only the public key |
| `ES256` | `ACCESS_PUBLIC_KEY_FILE` or `JWKS_URI` | Same as RS256, smaller keys |

With `JWKS_URI` set, the consumer fetches and caches the public key automatically,
refreshing on unknown `kid` headers.

---

### Role System

Roles are hierarchical. Higher roles include all permissions of lower roles.

```
SUPERADMIN > ADMIN > WRITER > READER > USER
```

| Role | Typical use |
|---|---|
| `SUPERADMIN` | Full platform access, user management |
| `ADMIN` | Administrative operations within a service |
| `WRITER` | Create and update resources |
| `READER` | Read-only access |
| `USER` | Base authenticated user |

---

### Protecting Routes

```python
from fastapi import APIRouter, Depends
from typing import Annotated
from app.core.deps import auth

router = APIRouter()

# Any authenticated user
@router.get("/profile")
async def get_profile(user: auth.CurrentUser):
    return {"id": user.id, "email": user.email, "role": user.role}

# ADMIN or SUPERADMIN
@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    admin: Annotated[UserModel, Depends(auth.get_current_active_admin)],
):
    ...

# SUPERADMIN only
@router.post("/admin/bootstrap")
async def bootstrap(
    su: Annotated[UserModel, Depends(auth.get_current_active_superuser)],
):
    ...
```

Unauthorized requests receive:
- `401 Unauthorized` — missing or invalid token
- `403 Forbidden` — valid token but insufficient role

---

## Health Endpoint

Mounted automatically at `GET {API_PREFIX}/health/` (e.g. `/api/health/`).

**Before app is ready** (during startup validators):
```json
HTTP 503
{"status": "initializing", "ready": false}
```

**After ready — public response:**
```json
HTTP 200   (or 503 if any check is "fail")
{"status": "ok"}
```

**After ready — authorized response** (with `X-Internal-Token` header or custom authorizer):
```json
HTTP 200
{
  "status": "ok",
  "checks": [
    {"name": "database", "status": "ok", "latency_ms": 3.2, "error": null, "ok": true}
  ],
  "service": "Item Service",
  "version": "1.0.0",
  "fastapi_m8": "1.0.0",
  "auth_sdk_m8": "0.7.x"
}
```

**Authorization options:**

```python
# Option A — built-in X-Internal-Token (requires PRIVATE_API_SECRET in settings)
app = create_app(settings, router, health_checks=[check_db])
# Pass header: X-Internal-Token: <PRIVATE_API_SECRET>

# Option B — always public
app = create_app(settings, router, health_checks=[check_db], health_detail_public=True)

# Option C — custom authorizer
async def is_internal(request: Request) -> bool:
    return request.client.host == "10.0.0.1"

app = create_app(settings, router, health_checks=[check_db], health_detail_authorizer=is_internal)
```

---

## Database Integration

Install the appropriate extra:

```bash
pip install "fastapi-m8[postgres]"   # psycopg2-binary
pip install "fastapi-m8[mysql]"      # pymysql
```

Configure in `.env`:

```ini
SELECTED_DB=Postgres
DB_HOST=db
DB_PORT=5432
DB_DATABASE=my_app
DB_USER=app
DB_PASSWORD=secret
TABLES_PREFIX=app
```

`SQLALCHEMY_DATABASE_URI` is assembled automatically. You can also set it directly
to override the assembly.

Define models with `TimestampMixin` from `auth-sdk-m8`:

```python
from sqlmodel import SQLModel, Field
from auth_sdk_m8.db.mixins import TimestampMixin

class Item(TimestampMixin, SQLModel, table=True):
    __tablename__ = "app_items"

    id: int | None = Field(default=None, primary_key=True)
    name: str
    owner_id: int
```

---

## Pre-Start Script

A CLI script that blocks until the database is reachable. Use it as a container
init step to prevent your app from starting before the database is ready.

```bash
# Installed entry point
fastapi-m8-prestart

# Or directly
python -m fastapi_m8.scripts.pre_start
```

The script expects `app.core.deps.engine` to be a `DbEngine` instance. It retries
`SELECT 1` up to 300 times with 5-second intervals, then exits. If the module is not
found or `engine` is not a `DbEngine`, it exits gracefully.

**Dockerfile:**

```dockerfile
RUN pip install "fastapi-m8[postgres]"
CMD fastapi-m8-prestart && uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Complete Example

```
my_service/
├── app/
│   ├── core/
│   │   ├── config.py      # Settings subclass
│   │   └── deps.py        # auth + engine singletons
│   ├── api/
│   │   └── items.py       # Domain router
│   └── main.py            # create_app() entry point
├── .env
└── pyproject.toml
```

**`app/core/config.py`**
```python
from pydantic_settings import SettingsConfigDict
from fastapi_m8 import ConsumerServiceSettings

class Settings(ConsumerServiceSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
```

**`app/core/deps.py`**
```python
from fastapi_m8 import build_auth_deps, create_db_engine
from app.core.config import settings

auth = build_auth_deps(settings)
engine = create_db_engine(settings)
```

**`app/api/items.py`**
```python
from typing import Annotated
from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.core.deps import auth, engine

router = APIRouter(prefix="/items", tags=["items"])
SessionDep = Annotated[Session, Depends(engine.session_dep)]

@router.get("/")
async def list_items(user: auth.CurrentUser, session: SessionDep):
    return {"owner": user.email}

@router.delete("/{item_id}/admin")
async def delete_item(
    item_id: int,
    admin: Annotated[object, Depends(auth.get_current_active_admin)],
    session: SessionDep,
):
    return {"deleted": item_id}
```

**`app/main.py`**
```python
from fastapi import APIRouter
from sqlmodel import select
from fastapi_m8 import create_app, HealthCheckResult, HealthStatus
from app.core.config import settings
from app.core.deps import auth, engine
from app.api.items import router as items_router

async def check_db() -> HealthCheckResult:
    try:
        with engine.session() as s:
            s.exec(select(1))
        return HealthCheckResult.from_bool("database", True)
    except Exception as exc:
        return HealthCheckResult(name="database", status=HealthStatus.FAIL, error=str(exc))

api_router = APIRouter()
api_router.include_router(items_router)

app = create_app(
    settings,
    api_router,
    service_name="Item Service",
    service_version="1.0.0",
    auth_deps=auth,
    db_engine=engine,
    health_checks=[check_db],
)
```

---

## Testing

Override settings to avoid reading `.env` files in tests:

```python
# tests/conftest.py
import pytest
from fastapi.testclient import TestClient
from pydantic_settings import SettingsConfigDict
from fastapi_m8 import ConsumerServiceSettings, create_app

class TestSettings(ConsumerServiceSettings):
    model_config = SettingsConfigDict(env_file=None)  # no file — all from kwargs

@pytest.fixture()
def settings():
    return TestSettings(
        DOMAIN="localhost",
        ENVIRONMENT="local",
        PROJECT_NAME="test",
        STACK_NAME="test",
        API_PREFIX="/api",
        BACKEND_HOST="http://localhost:8000",
        FRONTEND_HOST="http://localhost:3000",
        BACKEND_CORS_ORIGINS="http://localhost:3000",
        ACCESS_SECRET_KEY="x" * 32,
        REFRESH_SECRET_KEY="y" * 32,
        TOKEN_MODE="stateless",
        AUTH_SERVICE_ROLE="consumer",
        DB_HOST="localhost",
        DB_PORT=5432,
        DB_DATABASE="test",
        DB_USER="test",
        DB_PASSWORD="test",
    )

@pytest.fixture()
def client(settings):
    from fastapi import APIRouter
    router = APIRouter()
    app = create_app(settings, router)
    return TestClient(app)
```

Use `anyio` for async tests (required by CLAUDE.md):

```python
import pytest
import anyio

@pytest.mark.anyio
async def test_health(client):
    response = client.get("/api/health/")
    assert response.status_code == 200
```

---

## Compatibility

| `fastapi-m8` | `auth-sdk-m8` | Python |
|---|---|---|
| `1.0.x` | `>=0.7.0, <0.8.0` | 3.11, 3.12, 3.13 |

The compatibility matrix is enforced at startup via `COMPAT_MATRIX`. A
`RuntimeError` is raised immediately if the installed `auth-sdk-m8` version is
outside the supported range.

Check at runtime:

```python
from fastapi_m8 import CAPABILITIES, __version__

print(__version__)          # "1.0.0"
print(CAPABILITIES)         # {"async": False, "db_optional": True, ...}
```

`create_async_app()` is a planned API stub for v2.0. Calling it raises
`NotImplementedError`.
