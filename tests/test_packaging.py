"""Verify the packed wheel and sdist actually contain and export fastapi-m8 (§5.2).

Builds real distributions with the project's declared build backend
(hatchling) via ``python -m build --no-isolation`` — no network round-trip to
re-resolve build requirements, since ``hatchling``/``build`` are already dev
dependencies — and proves the built wheel installs into a clean target and its
public surface, including the new API-key introspection client and the
route-audit utility, imports and behaves correctly. ruff/mypy/pytest passing
against the source tree does not prove packaging metadata is correct; only
building and installing the real artifact does.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def built_distributions(tmp_path_factory) -> dict[str, Path]:
    out_dir = tmp_path_factory.mktemp("dist")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out_dir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(out_dir.glob("*.whl"))
    sdists = list(out_dir.glob("*.tar.gz"))
    assert len(wheels) == 1, f"expected exactly one wheel, found {wheels}"
    assert len(sdists) == 1, f"expected exactly one sdist, found {sdists}"
    return {"wheel": wheels[0], "sdist": sdists[0]}


class TestWheelContents:
    def test_wheel_contains_the_public_modules(
        self, built_distributions: dict[str, Path]
    ) -> None:
        with zipfile.ZipFile(built_distributions["wheel"]) as zf:
            names = zf.namelist()
        assert "fastapi_m8/__init__.py" in names
        assert "fastapi_m8/_deps.py" in names
        assert "fastapi_m8/_api_key.py" in names
        assert "fastapi_m8/_revocation.py" in names
        assert "fastapi_m8/_route_audit.py" in names
        assert "fastapi_m8/config.py" in names

    def test_wheel_excludes_the_test_suite(
        self, built_distributions: dict[str, Path]
    ) -> None:
        with zipfile.ZipFile(built_distributions["wheel"]) as zf:
            names = zf.namelist()
        assert not any(name.startswith("tests/") for name in names)


class TestSdistContents:
    def test_sdist_contains_the_route_audit_source(
        self, built_distributions: dict[str, Path]
    ) -> None:
        with tarfile.open(built_distributions["sdist"]) as tf:
            names = tf.getnames()
        assert any(n.endswith("fastapi_m8/_route_audit.py") for n in names)
        assert any(n.endswith("fastapi_m8/_api_key.py") for n in names)


class TestInstalledWheelImports:
    def test_public_api_imports_and_audits_a_route_from_a_clean_install(
        self, built_distributions: dict[str, Path], tmp_path: Path
    ) -> None:
        """A clean install (no fastapi-m8 source on sys.path) exercises the
        public surface end to end: build a minimal AuthDeps, wire a bare
        API-key route, and prove ``audit_api_key_routes`` flags it — the same
        behavior asserted against the source tree in test_route_audit.py, now
        proven against the packaged artifact.
        """
        install_dir = tmp_path / "site"
        install_dir.mkdir()
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--target",
                str(install_dir),
                str(built_distributions["wheel"]),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        probe = f"""
import sys
sys.path.insert(0, {str(install_dir)!r})
import fastapi_m8 as fm8
assert fm8.build_auth_deps is not None
assert fm8.audit_api_key_routes is not None
assert fm8.ConsumerServiceSettings is not None

from fastapi import Depends, FastAPI

settings = fm8.ConsumerServiceSettings(
    DOMAIN="localhost",
    ENVIRONMENT="local",
    API_PREFIX="/api",
    PROJECT_NAME="probe-service",
    STACK_NAME="probe-stack",
    BACKEND_HOST="http://localhost:8000",
    FRONTEND_HOST="http://localhost:3000",
    BACKEND_CORS_ORIGINS="http://localhost:3000",
    SECRET_KEY="Probe-Wheel-Test_Key-2026_xyz-abc-9!",
    ACCESS_SECRET_KEY="Probe-Wheel-Test_Key-2026_xyz-abc-9!",
    REFRESH_SECRET_KEY="Probe-Wheel-Test_Key-2026_xyz-abc-9!",
    EVENT_SIGNING_KEY="Probe-Wheel-Test_Key-2026_xyz-abc-9!",
    ACCESS_TOKEN_ALGORITHM="HS256",
    TOKEN_STRICT_VALIDATION=False,
    DB_HOST="localhost", DB_PORT=3306, DB_DATABASE="testdb",
    DB_USER="testuser", DB_PASSWORD="ValidPass1!",
    REDIS_HOST="localhost", REDIS_PORT=6379,
    REDIS_USER="redisuser", REDIS_PASSWORD="ValidPass1!",
    AUTH_SERVICE_ROLE="consumer",
    TOKEN_MODE="stateless",
    AUTH_PREFIX="/auth",
    SERVICE_VERSION="1.0.0", API_VERSION="v1",
    CONTRACT_VERSION="1.0", CONTRACT_RANGE=">=1.0.0 <2.0.0",
    API_KEY_INTROSPECTION_ENABLED=True,
    INTERNAL_CLIENT_ID="probe-consumer",
    PRIVATE_API_SECRET="supersecret",
    INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
)
auth = fm8.build_auth_deps(settings)
assert auth.get_current_api_key_principal is not None

from auth_sdk_m8.schemas.base import RoleType

assert callable(auth.get_current_active_reader)
assert callable(auth.require_role)
assert auth.require_role(RoleType.READER) is not auth.get_current_active_reader

app = FastAPI()

@app.get("/bare-thing")
def route(principal=Depends(auth.get_current_api_key_principal)):
    return {{}}

findings = fm8.audit_api_key_routes(
    app, bare_dependency=auth.get_current_api_key_principal
)
assert len(findings) == 1
assert findings[0].path == "/bare-thing"
assert isinstance(findings[0], fm8.BareApiKeyDependency)
print("OK")
"""
        result = subprocess.run(
            [sys.executable, "-c", probe],
            check=True,
            capture_output=True,
            text=True,
        )
        assert result.stdout.strip().endswith("OK"), result.stdout + result.stderr
