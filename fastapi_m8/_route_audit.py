"""
Static route audit for API-key dependency wiring (§3.3.1 / APIKEY-CAP-01).

A capability-bearing route must depend on a *capability* dependency — the
callable ``require_api_key_role(...)`` returns, i.e.
``AuthDeps.get_current_api_key_reader``/``_writer`` or an equivalent factory
result — never directly on the bare ``AuthDeps.get_current_api_key_principal``.
Depending on the bare dependency alone proves only that a key resolves to a
live owner; it grants no capability (:func:`fastapi_m8._deps.AuthDeps`), but a
route wired to it directly is a mistake worth catching at test time rather
than trusting every route's business logic to re-check the role correctly.

``audit_api_key_routes`` walks a *built* ``FastAPI`` app's routes rather than
parsing source, so it audits the wiring a service actually ships and needs no
AST/source coupling to any particular project layout.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from fastapi import FastAPI
from fastapi.routing import APIRoute


@dataclass(frozen=True)
class BareApiKeyDependency:
    """One route found depending directly on the bare API-key principal."""

    path: str
    methods: frozenset[str]


def audit_api_key_routes(
    app: FastAPI,
    *,
    bare_dependency: Callable,
    exempt_paths: Iterable[str] = (),
) -> list[BareApiKeyDependency]:
    """
    Return every route depending directly on *bare_dependency*.

    Only the route's **top-level** dependencies are inspected. A route wired
    through ``require_api_key_role(...)`` depends on that factory's returned
    closure, which itself depends on the bare principal as a *sub*-dependency
    — so it is correctly not flagged; only a route naming the bare dependency
    directly is.

    Args:
        app: A built FastAPI application (after route registration).
        bare_dependency: The service's own
            ``AuthDeps.get_current_api_key_principal`` — matched by identity,
            never a role-capped wrapper, so passing the wrong callable here
            would silently audit nothing.
        exempt_paths: Route paths explicitly allowed to depend on the bare
            dependency (e.g. a read-only ``/verify``-style route that grants
            no capability by design). Everything else still protected by the
            bare dependency alone is a finding.

    Returns:
        Findings, one per offending route. Empty means every route in *app*
        that uses the API-key family goes through a role-capped dependency.

    """
    exempt = set(exempt_paths)
    findings: list[BareApiKeyDependency] = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in exempt:
            continue
        if any(dep.call is bare_dependency for dep in route.dependant.dependencies):
            findings.append(
                BareApiKeyDependency(
                    path=route.path, methods=frozenset(route.methods or ())
                )
            )
    return findings
