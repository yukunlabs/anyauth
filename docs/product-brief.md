# AnyAuth Product Brief

## Positioning

AnyAuth is a local-first authentication hub that gives any app you own instant
SSO, mock identity, and protocol-compatible login for development and
self-hosted environments.

## Core User

- Solo builders creating multiple apps.
- Developers testing auth integrations locally.
- Self-hosters who want one local identity hub for their own tools.

## Core Scenario

The user starts AnyAuth locally, registers multiple apps, logs in once, and can
then access those apps through the same local identity session.

Example:

```text
app-a.localhost -> AnyAuth -> login once -> app-a logged in
app-b.localhost -> AnyAuth -> already logged in -> app-b logged in
```

If a local PIN is configured, AnyAuth requires that PIN before creating the SSO
session.

The user can also put AnyAuth in front of a local upstream app. The protected
proxy handles login and forwards authenticated requests with identity headers,
so the upstream app can receive a trusted local user without implementing OIDC
itself.

## Operating Modes

- `serve` starts only the local provider and is the default path for real apps
  the user owns.
- `protect` starts the provider plus a local reverse proxy in front of one
  upstream app.
- `demo` starts the provider plus two built-in demo apps for validating SSO
  behavior without creating a separate test application.

## Product Boundaries

AnyAuth works for apps the user owns or controls. It does not make arbitrary
third-party websites trust the user's local identity provider.

## Long-Term Directions

- Local OIDC Provider
- OAuth2 Authorization Server
- Forward Auth for reverse proxies
- Passkey / Touch ID local verification
- Mock users, claims, and tenant context
- Auth.js / Spring Security / Django integration exports
- SSO compatibility and security test lab
