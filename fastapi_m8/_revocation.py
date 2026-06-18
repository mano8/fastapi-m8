"""
Async HTTP revocation client — internal to fastapi-m8.

Checks JTI status via the auth service private introspection endpoint.
Instantiated only by ``build_auth_deps``; never import directly.
"""

from __future__ import annotations

import logging
import time

import httpx

_logger = logging.getLogger(__name__)


def _get_obs():
    """
    Return the auth-sdk-m8 observability ``metrics`` module, or ``None``.

    Observability is an optional extra (``auth-sdk-m8[observability]``); the
    revocation cache must keep working without it, so the import is guarded and
    metric emission is best-effort. Never raises.
    """
    try:
        from auth_sdk_m8.observability import metrics as obs  # noqa: PLC0415
    except ImportError:  # pragma: no cover — observability extra always installed
        return None
    return obs


class _CacheMetrics:
    """
    Consumer-side revocation-cache metrics, registered on the SDK registry.

    Carries no JTI, user ID, or secret as a label or value — only the
    ``result`` (``hit``/``miss``) dimension and the configured TTL — so the
    acceptance criterion "keys/secrets are never logged" holds for metrics too.
    """

    def __init__(self, lookups, ttl_seconds) -> None:  # noqa: ANN001
        self.lookups = lookups
        self.ttl_seconds = ttl_seconds


# (registry, metrics) — rebuilt when the SDK swaps its registry (tests do this).
# Holding the registry object (not its id) prevents id-reuse aliasing after GC.
_cache_metrics: tuple[object, _CacheMetrics] | None = None


def _get_cache_metrics() -> _CacheMetrics | None:
    """
    Return the revocation-cache metrics, registering them once on demand.

    Returns ``None`` when observability is unavailable (extra not installed) or
    disabled (``METRICS_ENABLED=false``) — so the cache has zero metric cost in
    that case, mirroring the SDK's best-effort emission. Never raises.
    """
    obs = _get_obs()
    if obs is None or obs.get() is None:
        return None
    registry = obs.REGISTRY
    global _cache_metrics
    if _cache_metrics is not None and _cache_metrics[0] is registry:
        return _cache_metrics[1]
    from prometheus_client import Counter, Gauge  # noqa: PLC0415

    metrics = _CacheMetrics(
        lookups=Counter(
            "revocation_cache_lookups_total",
            "JTI revocation-cache lookups by outcome (result: hit | miss)",
            ["result"],
            registry=registry,
        ),
        ttl_seconds=Gauge(
            "revocation_cache_ttl_seconds",
            "Configured revocation-cache stale-window TTL in seconds "
            "(0 = caching disabled)",
            registry=registry,
        ),
    )
    _cache_metrics = (registry, metrics)
    return metrics


class RevocationCheckError(Exception):
    """Raised when the revocation check fails in fail-closed mode."""


class JtiRevocationCache:
    """
    Short-TTL positive validation cache for JTI revocation checks.

    Caches ``active=True`` results keyed by JTI.  A cached entry means
    *not revoked* — on a cache hit, the HTTP round-trip is skipped.
    Entries are lazily expired on read.  Eviction methods are called by
    the auth event-stream consumer when push events arrive.

    Args:
        ttl_seconds: Seconds an ``active=True`` result is trusted without
            re-checking fa-auth.  Must be positive (enforced by the caller).

    """

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        # jti → (expires_at_monotonic, user_id)
        self._store: dict[str, tuple[float, str]] = {}

    def get(self, jti: str) -> bool | None:
        """Return False (not revoked) on a live hit; None on miss/expired."""
        entry = self._store.get(jti)
        if entry is None:
            return None
        expires_at, _ = entry
        if time.monotonic() >= expires_at:
            del self._store[jti]
            return None
        return False

    def put(self, jti: str, user_id: str) -> None:
        """Cache a JTI as active until TTL expires."""
        self._store[jti] = (time.monotonic() + self._ttl, user_id)

    def evict_jti(self, jti: str) -> None:
        """Remove one JTI (called on session.revoked stream event)."""
        self._store.pop(jti, None)

    def evict_user(self, user_id: str) -> None:
        """Remove all JTIs for a user (called on user.deleted stream event)."""
        to_remove = [k for k, (_, uid) in self._store.items() if uid == user_id]
        for k in to_remove:
            del self._store[k]

    def flush_all(self) -> None:
        """Clear the entire cache (called on unresumable stream gap)."""
        self._store.clear()


class RemoteRevocationClient:
    """
    Async HTTP client for JTI revocation checks.

    Fail-closed by default: an unreachable auth service rejects the token.
    Set ``fail_closed=False`` to accept tokens when the endpoint is unavailable.

    When ``cache_ttl > 0`` a short-lived positive validation cache is enabled:
    ``active=True`` results are cached for *cache_ttl* seconds, skipping the
    HTTP call on subsequent requests for the same JTI.  Set to ``0`` (default)
    to disable caching and always call fa-auth.
    """

    def __init__(
        self,
        *,
        introspection_url: str,
        private_api_secret: str,
        connect_timeout: float = 2.0,
        read_timeout: float = 3.0,
        fail_closed: bool = True,
        cache_ttl: int = 0,
    ) -> None:
        """Initialise the HTTP client with auth headers and timeouts."""
        self._url = introspection_url
        self._fail_closed = fail_closed
        self._cache_ttl = cache_ttl
        self._cache: JtiRevocationCache | None = (
            JtiRevocationCache(cache_ttl) if cache_ttl > 0 else None
        )
        if self._cache is not None:
            # TTL only — never the introspection URL host or any secret.
            _logger.info("revocation.cache enabled ttl_seconds=%d", cache_ttl)
        self._client = httpx.AsyncClient(
            headers={"X-Internal-Token": private_api_secret},
            timeout=httpx.Timeout(
                connect=connect_timeout,
                read=read_timeout,
                write=2.0,
                pool=2.0,
            ),
        )

    async def is_revoked(self, jti: str, user_id: str = "") -> bool:
        """
        Return True when the JTI has been revoked.

        Checks the local cache first (when enabled).  A cache hit on an
        ``active=True`` result returns False immediately.  On a cache miss
        the HTTP endpoint is called; if the response is ``active=True`` the
        result is cached for the configured TTL.

        On network/HTTP error: raises ``RevocationCheckError`` (fail-closed)
        unless ``fail_closed=False``, in which case returns False (fail-open).
        """
        if self._cache is not None:
            cached = self._cache.get(jti)
            if cached is not None:
                self._record_lookup("hit")
                return cached  # False = not revoked (active cached)
            self._record_lookup("miss")
        try:
            response = await self._client.post(self._url, json={"jti": jti})
            response.raise_for_status()
            active = response.json()["active"]
            if active and self._cache is not None:
                self._cache.put(jti, user_id)
            return not active
        except Exception as exc:
            _logger.warning("revocation.check_failed jti=%s error=%s", jti, exc)
            if self._fail_closed:
                raise RevocationCheckError(str(exc)) from exc
            return False

    def _record_lookup(self, result: str) -> None:
        """
        Record a cache lookup outcome (``hit``/``miss``); best-effort.

        Also (idempotently) publishes the configured stale-window TTL gauge —
        done here rather than in ``__init__`` because metrics setup runs after
        ``build_auth_deps``, so the gauge would otherwise be a no-op at boot.
        No JTI, user ID, or secret is ever passed as a label or value.
        """
        cache_metrics = _get_cache_metrics()
        if cache_metrics is None:
            return
        cache_metrics.lookups.labels(result=result).inc()
        cache_metrics.ttl_seconds.set(self._cache_ttl)

    def evict_jti(self, jti: str) -> None:
        """Remove one JTI from the cache (no-op when cache is disabled)."""
        if self._cache is not None:
            self._cache.evict_jti(jti)

    def evict_user(self, user_id: str) -> None:
        """Remove all JTIs for a user (no-op when cache is disabled)."""
        if self._cache is not None:
            self._cache.evict_user(user_id)

    def flush_cache(self) -> None:
        """Clear the entire cache (no-op when cache is disabled)."""
        if self._cache is not None:
            self._cache.flush_all()

    async def close(self) -> None:
        """Close the underlying httpx session."""
        await self._client.aclose()
