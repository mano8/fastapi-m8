"""
Async HTTP revocation client — internal to fastapi-m8.

Checks JTI status via the auth service private introspection endpoint, speaking
the **v2** subject-bound contract (3.5.2): the request asserts the subject the
consumer already read from the JWT it holds, and an active reply carries the
owner's ``auth_generation`` so cache entries can be tagged with the generation
that backs them. The SDK owns the schemas; the transport lives here.

The v2 decision never falls open. ``ACCESS_REVOCATION_FAILURE_MODE=fail_open``
is a transport-outage escape for the pre-2.0 blacklist accelerator only: an
answer this release cannot interpret as a valid v2 decision — malformed,
unknown schema version, or an active result for a subject the caller did not
assert — is refused regardless of the configured mode.

Instantiated only by ``build_auth_deps``; never import directly.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from typing import Any

import httpx
from auth_sdk_m8.schemas.jti_status import (
    JTI_STATUS_SCHEMA_VERSION,
    JtiStatusActiveResponse,
    JtiStatusResponse,
)
from auth_sdk_m8.schemas.user_events import SessionRevokedEvent
from auth_sdk_m8.security.guards import INTERNAL_TOKEN_HEADER
from pydantic import TypeAdapter, ValidationError

from fastapi_m8._internal_auth import InternalAuthProvider, _StaticInternalAuth

_logger = logging.getLogger(__name__)

_UNAUTHORIZED = 401

#: Ceiling on users tracked in the revocation watermark map. Watermarks outlive
#: the cache entries they protect (a revocation stays known after the entries it
#: evicted expire), so the map is bounded rather than left to grow for the life
#: of the process. Dropping the oldest is safe: a forgotten watermark only costs
#: the local staleness shortcut, and the issuer remains authoritative.
_MAX_TRACKED_WATERMARKS = 10_000

_RESPONSE_ADAPTER: TypeAdapter[JtiStatusResponse] = TypeAdapter(JtiStatusResponse)


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

    def __init__(self, lookups, ttl_seconds, check_failures) -> None:  # noqa: ANN001
        self.lookups = lookups
        self.ttl_seconds = ttl_seconds
        self.check_failures = check_failures


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
        check_failures=Counter(
            "revocation_check_failures_total",
            "JTI revocation-check failures by configured failure mode — a "
            "fail_open count is a conscious availability-over-safety opt-out "
            "(mode: fail_open | fail_closed)",
            ["mode"],
            registry=registry,
        ),
    )
    _cache_metrics = (registry, metrics)
    return metrics


class RevocationCheckError(Exception):
    """Raised when the revocation check fails in fail-closed mode."""


class RevocationDecisionError(RevocationCheckError):
    """
    Raised when the issuer answered but the v2 decision is uninterpretable.

    Separate from a transport failure: the call reached the issuer, so the
    ``fail_open`` escape does not apply (3.5.2 — the v2 generation decision
    never falls open). Carries a bounded, secret-free reason code only, so it is
    safe to log and to chain into the dependency's ``503``.
    """


class JtiRevocationCache:
    """
    Short-TTL positive validation cache for JTI revocation checks.

    Caches ``active=True`` results keyed by JTI, each **tagged with the
    ``auth_generation`` the issuer returned with it** (3.5.2). A cached entry
    means *not revoked* — on a cache hit, the HTTP round-trip is skipped.
    Entries are lazily expired on read. Eviction is driven by the auth
    event-stream consumer through :meth:`note_revocation`.

    The generation tag is what makes replayed and reordered events safe to act
    on: per user the cache keeps a *watermark* — the highest generation whose
    revocation it has applied — so an entry minted against a superseded
    generation is never stored, and a user-wide revocation evicts exactly the
    entries older than it while leaving sessions minted after it alone.

    Args:
        ttl_seconds: Seconds an ``active=True`` result is trusted without
            re-checking fa-auth.  Must be positive (enforced by the caller).

    """

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        # jti → (expires_at_monotonic, user_id, auth_generation)
        self._store: dict[str, tuple[float, str, int]] = {}
        # user_id → highest applied revocation generation (the watermark).
        self._watermarks: dict[str, int] = {}
        # user_id → durable event ids already applied *at* that watermark. Reset
        # whenever the watermark advances, which bounds it to one generation's
        # worth of events instead of the process's whole event history.
        self._applied_event_ids: dict[str, set[str]] = {}

    def get(self, jti: str) -> bool | None:
        """Return False (not revoked) on a live hit; None on miss/expired."""
        entry = self._store.get(jti)
        if entry is None:
            return None
        expires_at, _, _ = entry
        if time.monotonic() >= expires_at:
            del self._store[jti]
            return None
        return False

    def put(self, jti: str, user_id: str, auth_generation: int) -> None:
        """
        Cache a JTI as active until TTL expires, tagged with its generation.

        A result whose generation is below the user's watermark is **not**
        cached: a revocation at a later generation has already been applied, so
        the issuer's answer is a stale read of superseded authorization state.
        """
        if auth_generation < self._watermarks.get(user_id, 0):
            return
        self._store[jti] = (time.monotonic() + self._ttl, user_id, auth_generation)

    def is_superseded(self, user_id: str, auth_generation: int) -> bool:
        """Return whether *auth_generation* predates an applied revocation."""
        return auth_generation < self._watermarks.get(user_id, 0)

    def note_revocation(
        self, user_id: str, auth_generation: int, event_id: str | None
    ) -> bool:
        """
        Apply the watermark rule to one v2 revocation, returning whether to act.

        The exact rule of 3.5.2, and the reason "not newer ⇒ ignore" is wrong:
        an equal-generation event may name a different session that has not been
        evicted yet, so equality is a *dedup* question, not a staleness one.

        * ``auth_generation < watermark`` → stale; already superseded, ignore.
        * ``auth_generation == watermark`` → apply, unless this exact durable
          ``event_id`` was already applied at this generation. Several
          individual-JTI events share one generation and must stay
          distinguishable, which is why the durable id — never the SSE
          transport id, which resets on issuer restart — is the dedup key.
        * ``auth_generation > watermark`` → apply and advance the watermark,
          forgetting the previous generation's dedup ids.
        """
        watermark = self._watermarks.get(user_id)
        if watermark is not None and auth_generation < watermark:
            return False
        if watermark is not None and auth_generation == watermark:
            applied = self._applied_event_ids.setdefault(user_id, set())
            if event_id is None:
                return True
            if event_id in applied:
                return False
            applied.add(event_id)
            return True
        self._watermarks[user_id] = auth_generation
        self._applied_event_ids[user_id] = {event_id} if event_id else set()
        self._trim_watermarks()
        return True

    def _trim_watermarks(self) -> None:
        """Drop the oldest-tracked user once the watermark map is full."""
        while len(self._watermarks) > _MAX_TRACKED_WATERMARKS:
            oldest = next(iter(self._watermarks))
            del self._watermarks[oldest]
            self._applied_event_ids.pop(oldest, None)

    def evict_jti(self, jti: str) -> None:
        """Remove one JTI (called on session.revoked stream event)."""
        self._store.pop(jti, None)

    def evict_user(self, user_id: str) -> None:
        """Remove all JTIs for a user (called on user.deleted stream event)."""
        self.evict_user_below(user_id, None)

    def evict_user_below(self, user_id: str, auth_generation: int | None) -> None:
        """
        Remove a user's entries older than *auth_generation* (all when ``None``).

        A user-wide revocation at generation *g* invalidates the sessions that
        existed before it, not the ones minted against *g* or later by a login
        that has already re-authenticated.
        """
        to_remove = [
            k
            for k, (_, uid, gen) in self._store.items()
            if uid == user_id and (auth_generation is None or gen < auth_generation)
        ]
        for k in to_remove:
            del self._store[k]

    def flush_all(self) -> None:
        """
        Clear every cached entry (called on unresumable stream gap).

        Watermarks survive: they record revocations already applied, so keeping
        them can only keep the cache stricter, never staler.
        """
        self._store.clear()


class RemoteRevocationClient:
    """
    Async HTTP client for JTI revocation checks.

    Fail-closed by default: an unreachable auth service rejects the token.
    Set ``fail_closed=False`` to accept tokens when the endpoint is unavailable
    — an outage escape only. An issuer that *answers* unusably always denies,
    because a reply this client cannot interpret is not an availability problem.

    When ``cache_ttl > 0`` a short-lived positive validation cache is enabled:
    ``active=True`` results are cached for *cache_ttl* seconds, skipping the
    HTTP call on subsequent requests for the same JTI.  Set to ``0`` (default)
    to disable caching and always call fa-auth. Cached entries are tagged with
    the ``auth_generation`` backing them, so a revocation event evicts exactly
    what it supersedes (:meth:`apply_session_revoked_event`).

    Private-call authentication is delegated to an
    :class:`~fastapi_m8._internal_auth.InternalAuthProvider` (Phase 9.1): pass an
    ``auth_provider`` to use per-consumer credentials or short-TTL service
    tokens, or pass ``private_api_secret`` to keep the legacy single
    ``X-Internal-Token`` behaviour.  Exactly one must be supplied.
    """

    def __init__(
        self,
        *,
        introspection_url: str,
        private_api_secret: str | None = None,
        auth_provider: InternalAuthProvider | None = None,
        connect_timeout: float = 2.0,
        read_timeout: float = 3.0,
        fail_closed: bool = True,
        cache_ttl: int = 0,
        schema_version: str = JTI_STATUS_SCHEMA_VERSION,
    ) -> None:
        """Initialise the HTTP client, auth provider, and timeouts."""
        if (private_api_secret is None) == (auth_provider is None):
            raise ValueError(
                "provide exactly one of private_api_secret or auth_provider"
            )
        self._url = introspection_url
        self._schema_version = schema_version
        self._auth: InternalAuthProvider = auth_provider or _StaticInternalAuth(
            {INTERNAL_TOKEN_HEADER: private_api_secret}  # type: ignore[dict-item]
        )
        self._fail_closed = fail_closed
        self._cache_ttl = cache_ttl
        self._cache: JtiRevocationCache | None = (
            JtiRevocationCache(cache_ttl) if cache_ttl > 0 else None
        )
        if self._cache is not None:
            # TTL only — never the introspection URL host or any secret.
            _logger.info("revocation.cache enabled ttl_seconds=%d", cache_ttl)
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=connect_timeout,
                read=read_timeout,
                write=2.0,
                pool=2.0,
            ),
        )

    async def is_revoked(
        self, jti: str, user_id: str, *, bypass_cache: bool = False
    ) -> bool:
        """
        Return True when the JTI has been revoked.

        Checks the local cache first (when enabled and *bypass_cache* is
        False).  A cache hit on an ``active=True`` result returns False
        immediately.  On a cache miss — or when bypassed — the v2 endpoint is
        called with *user_id* as the asserted subject; an active reply is
        cached for the configured TTL, tagged with the generation the issuer
        returned, so a bypassed call still refreshes the entry for the general
        tier's benefit.

        An active reply whose generation the cache already knows to be
        superseded is a stale read of a session revoked at a later generation,
        so it denies rather than refreshing the entry.

        Args:
            jti: The access token's JTI.
            user_id: The subject the caller read from the token it holds. The
                v2 request is subject-bound, and an active reply for any other
                subject is refused (never accepted, never cached).
            bypass_cache: Skip the positive-cache lookup and always query the
                issuer. Role-sensitive JWT dependencies (writer/admin/
                superuser) pass this so the first such request after a
                revocation commit always observes the new state — the
                short-TTL positive cache applies only to the general
                authenticated tier (``REV-CACHE-01``, 3.5.4).

        Raises:
            RevocationDecisionError: The issuer answered unusably. Always
                fail-closed, whatever ``fail_closed`` is set to.
            RevocationCheckError: The issuer was unreachable and
                ``fail_closed`` is set; otherwise such a call returns False.

        """
        if self._cache is not None and not bypass_cache:
            cached = self._cache.get(jti)
            if cached is not None:
                self._record_lookup("hit")
                return cached  # False = not revoked (active cached)
            self._record_lookup("miss")
        try:
            result = await self._query_status(jti, user_id)
        except RevocationDecisionError:
            # The v2 decision never falls open: reaching the issuer and failing
            # to understand it is not the outage the fail_open knob covers.
            self._record_check_failure("fail_closed")
            raise
        except Exception as exc:
            mode = "fail_closed" if self._fail_closed else "fail_open"
            _logger.warning("revocation.check_failed mode=%s error=%s", mode, exc)
            self._record_check_failure(mode)
            if self._fail_closed:
                raise RevocationCheckError(str(exc)) from exc
            # Conscious availability-over-safety opt-out — surfaced loudly so it
            # never passes silently (logged here + counted in metrics above).
            _logger.warning(
                "security.revocation_fail_open token accepted despite "
                "unverifiable revocation (ACCESS_REVOCATION_FAILURE_MODE opt-out)"
            )
            return False
        if not isinstance(result, JtiStatusActiveResponse):
            return True
        if self._cache is not None:
            if self._cache.is_superseded(user_id, result.auth_generation):
                return True
            self._cache.put(jti, user_id, result.auth_generation)
        return False

    async def _query_status(self, jti: str, user_id: str) -> JtiStatusResponse:
        """
        POST the subject-bound v2 JTI-status check and return the parsed reply.

        On a ``401`` the auth provider is invalidated; if that signals a retry is
        worthwhile (service-token mode — the token was rejected), the credential
        is re-minted and the call is retried **once**.  Static modes (legacy /
        bootstrap) do not retry: a 401 there means a misconfigured secret.

        Raises:
            RevocationDecisionError: The reply is unusable — unparseable,
                schema-mismatched, or active for a subject other than the one
                asserted.

        """
        try:
            response = await self._post(jti, user_id)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != _UNAUTHORIZED or not (
                await self._auth.invalidate()
            ):
                raise
            response = await self._post(jti, user_id)
        result = self._parse(response)
        if isinstance(result, JtiStatusActiveResponse) and result.user_id != user_id:
            # Defense in depth: the issuer's own algorithm answers inactive on a
            # subject mismatch, so an active reply naming someone else means a
            # misrouted endpoint or a compromised issuer — never this token's
            # authorization. No identifier is logged.
            _logger.error("revocation.subject_mismatch active result refused")
            raise RevocationDecisionError("subject_mismatch")
        return result

    def _parse(self, response: httpx.Response) -> JtiStatusResponse:
        """
        Validate the issuer's reply against the SDK v2 contract, or fail closed.

        A reply this release cannot interpret is refused rather than read for
        whatever fields happen to parse — including a pre-2.0 issuer's bare
        ``{"active": true}``, which carries no generation to tag a cache entry
        with. The ``ValidationError`` embeds the raw input, so it is neither
        logged nor chained; only a bounded reason travels.
        """
        try:
            return _RESPONSE_ADAPTER.validate_python(response.json())
        # Both a non-JSON body and a ValidationError (which subclasses
        # ValueError) land here — neither is a decision this client may act on.
        except ValueError:
            _logger.warning("revocation.malformed_response")
            raise RevocationDecisionError("malformed_response") from None

    async def _post(self, jti: str, user_id: str) -> httpx.Response:
        """Send one authenticated v2 JTI-status request; raise on HTTP error."""
        response = await self._client.post(
            self._url,
            json={
                "jti": jti,
                "expected_user_id": user_id,
                "schema_version": self._schema_version,
            },
            headers=await self._auth.headers(),
        )
        response.raise_for_status()
        return response

    def apply_session_revoked_event(self, payload: Mapping[str, Any]) -> None:
        """
        Apply one ``session.revoked`` event to the cache (v1 **and** v2).

        Both schema versions are accepted for the rollout interval in which the
        issuer already emits v2 and consumers have not all upgraded (3.5.2):

        * **v2** (``auth_generation`` present) — the watermark rule decides
          whether to act, a durable ``event_id`` deduplicates within a
          generation, a JTI-scoped event evicts that session, and a user-wide
          event (``jti`` absent) evicts the user's entries older than the
          revoking generation.
        * **v1** (no generation) — nothing can be compared, so eviction is
          conservative: the whole user for a user-scoped event, and the whole
          cache when the payload is unusable enough that no user can be
          determined.

        Never raises: an event is an accelerator, and the issuer remains the
        authority for anything this drops.
        """
        if self._cache is None:
            return
        try:
            event = SessionRevokedEvent.model_validate(dict(payload))
        except ValidationError:
            # No determinable user — the one case the contract answers with a
            # full flush rather than a targeted eviction.
            _logger.warning("revocation.event_unparseable flushing cache")
            self._cache.flush_all()
            return
        if event.auth_generation is None:
            self._cache.evict_user(event.user_id)
            return
        if not self._cache.note_revocation(
            event.user_id, event.auth_generation, event.event_id
        ):
            return
        if event.jti is None:
            self._cache.evict_user_below(event.user_id, event.auth_generation)
        else:
            self._cache.evict_jti(event.jti)

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

    def _record_check_failure(self, mode: str) -> None:
        """
        Count a revocation-check failure by mode (``fail_open``/``fail_closed``).

        Best-effort and no-op without observability. Carries only the ``mode``
        dimension — never a JTI, user id, or secret — so the "no identifiers in
        metrics" acceptance criterion holds.
        """
        cache_metrics = _get_cache_metrics()
        if cache_metrics is None:
            return
        cache_metrics.check_failures.labels(mode=mode).inc()

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
        """Close the underlying httpx session and the auth provider."""
        await self._client.aclose()
        await self._auth.close()
