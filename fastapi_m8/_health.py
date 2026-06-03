"""
Health-check subsystem for fastapi-m8.

This module is intentionally **stateless**: readiness state lives on
``app.state`` (set by ``create_app``'s lifespan), so multiple FastAPI apps
in one process never share readiness (important for test harnesses).
"""

from __future__ import annotations

import logging
import re
import time
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

import anyio
from pydantic import BaseModel, computed_field, field_serializer

logger = logging.getLogger(__name__)

_SENSITIVE_KEY = re.compile(
    r"(^|_)(secret|password|passwd|token|api_key|access_key|"
    r"private_key|credential|dsn)($|_)",
    re.IGNORECASE,
)
_CRED_IN_URL = re.compile(r"://[^/\s:@]+:[^/\s@]+@")

DEFAULT_TIMEOUT: float = 0.5
STARTUP_GRACE_SECONDS: float = 30.0


def _scrub_text(text: str | None) -> str | None:
    """Mask embedded credentials in free text (driver errors echo DSNs)."""
    return _CRED_IN_URL.sub("://***:***@", text) if text else text


def _scrub_meta(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    if not meta:
        return meta
    return {
        k: (
            "REDACTED"
            if _SENSITIVE_KEY.search(k)
            else _scrub_text(v)
            if isinstance(v, str)
            else v
        )
        for k, v in meta.items()
    }


class HealthStatus(StrEnum):
    """Possible states for a single health check or aggregate."""

    OK = "ok"
    DEGRADED = "degraded"
    FAIL = "fail"
    UNKNOWN = "unknown"

    @classmethod
    def from_bool(cls, ok: bool) -> HealthStatus:
        """Convert a boolean check result to a ``HealthStatus``."""
        return cls.OK if ok else cls.FAIL


class HealthAggregatePolicy(StrEnum):
    """
    Policy for mapping individual check statuses to an HTTP status code.

    STRICT: FAIL or UNKNOWN → 503.
    LENIENT: only FAIL → 503 (UNKNOWN/DEGRADED stay at 200).
    """

    STRICT = "strict"
    LENIENT = "lenient"


@runtime_checkable
class HealthCheck(Protocol):
    """Protocol for health-check callables."""

    async def __call__(self) -> HealthCheckResult:
        """Run the check and return a result."""
        ...


class HealthCheckResult(BaseModel):
    """
    Result of a single health check.

    ``error`` and sensitive ``meta`` keys are scrubbed at serialisation time
    via Pydantic field_serializers — DSNs with embedded credentials are masked.
    """

    name: str
    status: HealthStatus
    latency_ms: float | None = None
    error: str | None = None
    meta: dict[str, Any] | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def ok(self) -> bool:
        """True when status is OK."""
        return self.status == HealthStatus.OK

    @field_serializer("error")
    def _ser_error(self, v: str | None) -> str | None:
        return _scrub_text(v)

    @field_serializer("meta")
    def _ser_meta(self, v: dict[str, Any] | None) -> dict[str, Any] | None:
        return _scrub_meta(v)

    @classmethod
    def from_bool(cls, name: str, ok: bool, **meta: Any) -> HealthCheckResult:
        """Convenience constructor from a boolean result."""
        return cls(
            name=name,
            status=HealthStatus.from_bool(ok),
            meta=meta or None,
        )


def is_in_grace(
    ready_since: float | None,
    grace: float = STARTUP_GRACE_SECONDS,
) -> bool:
    """Return True while within the post-ready startup grace window."""
    return ready_since is not None and (time.monotonic() - ready_since) < grace


def _check_name(check: HealthCheck) -> str:
    return getattr(check, "__name__", type(check).__name__)


async def run_check(
    check: HealthCheck,
    timeout: float = DEFAULT_TIMEOUT,
) -> HealthCheckResult:
    """
    Execute a single health check with a timeout.

    Never raises; timeout and exceptions are captured as FAIL results.
    Works with both asyncio and trio backends via anyio.
    """
    name = _check_name(check)
    t0 = time.monotonic()
    result: HealthCheckResult | None = None
    timed_out = False
    error_msg: str | None = None

    try:
        with anyio.move_on_after(timeout) as cancel_scope:
            try:
                result = await check()
            except Exception as exc:
                error_msg = str(exc)
        if cancel_scope.cancelled_caught:
            timed_out = True
    except Exception as exc:  # pragma: no cover — move_on_after itself never raises
        error_msg = str(exc)

    elapsed_ms = (time.monotonic() - t0) * 1000

    if timed_out:
        logger.debug("health check %s timed out (%.0fms)", name, timeout * 1000)
        return HealthCheckResult(
            name=name,
            status=HealthStatus.FAIL,
            error=f"timeout {timeout * 1000:.0f}ms",
        )
    if error_msg is not None:
        return HealthCheckResult(name=name, status=HealthStatus.FAIL, error=error_msg)
    if result is not None:
        result.latency_ms = elapsed_ms
        return result
    return HealthCheckResult(name=name, status=HealthStatus.UNKNOWN)  # pragma: no cover


def aggregate(
    results: list[HealthCheckResult],
    policy: HealthAggregatePolicy,
) -> HealthStatus:
    """Compute the overall status from a list of check results."""
    statuses = {r.status for r in results}
    if not statuses:
        return HealthStatus.OK
    if HealthStatus.FAIL in statuses:
        return HealthStatus.FAIL
    if policy is HealthAggregatePolicy.STRICT and HealthStatus.UNKNOWN in statuses:
        return HealthStatus.FAIL
    if HealthStatus.UNKNOWN in statuses:
        return HealthStatus.UNKNOWN
    if HealthStatus.DEGRADED in statuses:
        return HealthStatus.DEGRADED
    return HealthStatus.OK
