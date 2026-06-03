"""Tests for fastapi_m8._health."""

import pytest
from anyio import sleep as anyio_sleep

from fastapi_m8._health import (
    HealthAggregatePolicy,
    HealthCheckResult,
    HealthStatus,
    aggregate,
    run_check,
)

# ── HealthStatus ──────────────────────────────────────────────────────────────


def test_health_status_from_bool_ok() -> None:
    assert HealthStatus.from_bool(True) == HealthStatus.OK


def test_health_status_from_bool_fail() -> None:
    assert HealthStatus.from_bool(False) == HealthStatus.FAIL


# ── HealthCheckResult ─────────────────────────────────────────────────────────


def test_health_check_result_ok_property() -> None:
    r = HealthCheckResult(name="db", status=HealthStatus.OK)
    assert r.ok is True


def test_health_check_result_fail_property() -> None:
    r = HealthCheckResult(name="db", status=HealthStatus.FAIL)
    assert r.ok is False


def test_health_check_result_from_bool_true() -> None:
    r = HealthCheckResult.from_bool("db", True)
    assert r.ok is True
    assert r.meta is None


def test_health_check_result_from_bool_false() -> None:
    r = HealthCheckResult.from_bool("db", False)
    assert r.ok is False


def test_health_check_result_from_bool_with_meta() -> None:
    r = HealthCheckResult.from_bool("db", True, host="localhost")
    assert r.meta == {"host": "localhost"}


def test_error_scrubbed_dsn() -> None:
    r = HealthCheckResult(
        name="db",
        status=HealthStatus.FAIL,
        error="could not connect to postgres://user:password@db:5432/app",
    )
    dumped = r.model_dump()
    assert "password" not in dumped["error"]
    assert "***:***@" in dumped["error"]


def test_error_none_stays_none() -> None:
    r = HealthCheckResult(name="db", status=HealthStatus.OK)
    dumped = r.model_dump()
    assert dumped["error"] is None


def test_meta_sensitive_key_redacted() -> None:
    r = HealthCheckResult(
        name="s3",
        status=HealthStatus.OK,
        meta={"access_key": "AKID", "bucket": "my-bucket"},
    )
    dumped = r.model_dump()
    assert dumped["meta"]["access_key"] == "REDACTED"
    assert dumped["meta"]["bucket"] == "my-bucket"


def test_meta_dsn_key_redacted() -> None:
    r = HealthCheckResult(
        name="db",
        status=HealthStatus.OK,
        meta={"dsn": "postgres://u:p@host/db"},
    )
    assert r.model_dump()["meta"]["dsn"] == "REDACTED"


def test_meta_non_sensitive_not_redacted() -> None:
    r = HealthCheckResult(
        name="cache",
        status=HealthStatus.OK,
        meta={"monkey_count": 3, "host": "redis"},
    )
    dumped = r.model_dump()
    assert dumped["meta"]["monkey_count"] == 3
    assert dumped["meta"]["host"] == "redis"


def test_meta_string_value_dsn_scrubbed() -> None:
    r = HealthCheckResult(
        name="s3",
        status=HealthStatus.OK,
        meta={"endpoint": "https://user:pass@minio:9000"},
    )
    dumped = r.model_dump()
    assert "pass" not in dumped["meta"]["endpoint"]


# ── aggregate ─────────────────────────────────────────────────────────────────


def test_aggregate_empty() -> None:
    assert aggregate([], HealthAggregatePolicy.STRICT) == HealthStatus.OK


def test_aggregate_all_ok() -> None:
    results = [
        HealthCheckResult(name="a", status=HealthStatus.OK),
        HealthCheckResult(name="b", status=HealthStatus.OK),
    ]
    assert aggregate(results, HealthAggregatePolicy.LENIENT) == HealthStatus.OK


def test_aggregate_fail_dominates() -> None:
    results = [
        HealthCheckResult(name="a", status=HealthStatus.OK),
        HealthCheckResult(name="b", status=HealthStatus.FAIL),
    ]
    assert aggregate(results, HealthAggregatePolicy.LENIENT) == HealthStatus.FAIL


def test_aggregate_degraded_lenient_ok() -> None:
    results = [
        HealthCheckResult(name="a", status=HealthStatus.OK),
        HealthCheckResult(name="b", status=HealthStatus.DEGRADED),
    ]
    assert aggregate(results, HealthAggregatePolicy.LENIENT) == HealthStatus.DEGRADED


def test_aggregate_unknown_strict_is_fail() -> None:
    results = [HealthCheckResult(name="a", status=HealthStatus.UNKNOWN)]
    assert aggregate(results, HealthAggregatePolicy.STRICT) == HealthStatus.FAIL


def test_aggregate_unknown_lenient_is_unknown() -> None:
    results = [HealthCheckResult(name="a", status=HealthStatus.UNKNOWN)]
    assert aggregate(results, HealthAggregatePolicy.LENIENT) == HealthStatus.UNKNOWN


# ── run_check ─────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_run_check_success() -> None:
    async def good_check() -> HealthCheckResult:
        return HealthCheckResult(name="db", status=HealthStatus.OK)

    result = await run_check(good_check)
    assert result.status == HealthStatus.OK
    assert result.latency_ms is not None
    assert result.latency_ms >= 0


@pytest.mark.anyio
async def test_run_check_exception_captured() -> None:
    async def bad_check() -> HealthCheckResult:
        raise RuntimeError("connection refused")

    result = await run_check(bad_check)
    assert result.status == HealthStatus.FAIL
    assert "connection refused" in (result.error or "")


@pytest.mark.anyio
async def test_run_check_timeout() -> None:
    async def slow_check() -> HealthCheckResult:
        await anyio_sleep(10)
        return HealthCheckResult(name="slow", status=HealthStatus.OK)

    result = await run_check(slow_check, timeout=0.05)
    assert result.status == HealthStatus.FAIL
    assert "timeout" in (result.error or "")


@pytest.mark.anyio
async def test_run_check_names_class_check() -> None:
    """run_check uses __name__ fallback to type().__name__ for class-based checks."""

    class MyCheck:
        async def __call__(self) -> HealthCheckResult:
            return HealthCheckResult(name="MyCheck", status=HealthStatus.OK)

    result = await run_check(MyCheck())
    assert result.name == "MyCheck"
