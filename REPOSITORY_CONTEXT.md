# fastapi-m8

## Layer

Platform (FastAPI application framework).

## Purpose

Provide a minimal, reusable application-factory scaffold for FastAPI services.
The scaffold exposes integration points for the shared `auth-sdk-m8` primitives;
domain-service behavior and service-specific policy remain owned by each consumer.

## Repository boundaries

- Do not add business logic.
- Keep the package minimal and reusable across services.
- Keep authentication integration at reusable SDK interfaces; do not directly
  couple this framework to `fa-auth-m8` domain-service behavior.
- Do not add domain-specific service behavior to the framework scaffold.

## Standalone authority

This file, `pyproject.toml`, repository documentation, and existing CI are the
authoritative local context. A verified nearest workspace can optionally add
launcher-selected Python policies and tasks; its absence is a successful
standalone condition and does not make a parent workspace necessary.

When a task requires quality validation, follow the repository documentation and
CI together with the applicable selected Python policy.
