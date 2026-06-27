# Security

`fastapi-m8` is the FastAPI **consumer** framework for the m8 stack. Its runtime
security posture is inherited from `auth-sdk-m8` (RS256 + strict `iss`/`aud`
validation, signed events, fail-closed revocation, the response-hardening layer)
and wired in by `create_app` / `build_auth_deps`. This file documents only the
consumer-specific transport guidance; the canonical, fleet-wide controls live in
the **[`auth-sdk-m8` `SECURITY.md`](https://github.com/mano8/auth-sdk-m8/blob/main/SECURITY.md)**.

## Private calls a consumer makes

A `fastapi-m8` consumer reaches `fa-auth-m8` over the **private API** only:

- JTI-status / revocation introspection (`{issuer}/private/v1/jti-status`),
- the optional auth event stream (`{issuer}/private/v1/events/stream`),
- the optional short-TTL service-token exchange (`{issuer}/private/v1/service-token`).

These are authenticated at the **app layer** by the per-consumer credential model
(item 9.1): `X-Internal-Client` + `X-Internal-Token`, or an exchanged
`Authorization: Bearer` service token, with a legacy single `PRIVATE_API_SECRET`
fallback. See the README's *Per-consumer internal auth* section.

## Service identity and mTLS (multi-host deployments)

The app-layer token/credential check is always the **primary** control. For the
transport beneath it, follow the canonical
[**"Service identity and mTLS"**](https://github.com/mano8/auth-sdk-m8/blob/main/SECURITY.md#service-identity-and-mtls-multi-host-deployments)
section of `auth-sdk-m8`'s `SECURITY.md` — it carries the Traefik internal-entrypoint
client-cert reference config, the CA/cert generation steps, and the service-mesh
alternative. From the **consumer** side:

- **Single trusted Docker host.** Internal `http://` between the consumer and
  `fa-auth-m8` is acceptable — the Docker network is the isolation boundary. This is
  warned, not blocked, in production (`ALLOW_INTERNAL_HTTP`); `local` is unrestricted.
- **Multi-host / untrusted network.** The container network no longer provides
  kernel isolation, so add **mTLS** on the path to the issuer's private entrypoint:
  the consumer presents a client certificate that Traefik (or a service-mesh sidecar)
  verifies (`RequireAndVerifyClientCert`). Mount the consumer's client cert/key and
  the CA into the container per the auth-sdk-m8 reference config.
- **Defense in depth, not a replacement.** Keep the `X-Internal-Token` /
  `X-Internal-Client` / service-token app-layer check enabled alongside mTLS: if cert
  rotation lapses the token check still gates access, and if a token leaks over an
  unencrypted hop mTLS encrypts the channel. Internal HTTPS is **not** a blanket
  mandate — mTLS is the *multi-host* transport control.

## Reporting a vulnerability

Report security vulnerabilities privately through GitHub's **Security** tab on this repository —
**"Report a vulnerability"** — which opens a private security advisory visible only to the
maintainers. Do not open a public GitHub issue for vulnerabilities. Expected response within 48 h.
