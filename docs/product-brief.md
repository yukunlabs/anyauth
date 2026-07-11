# AnyAuth Product Brief

## Positioning

AnyAuth is a local-first authentication and authorization hub that gives apps
you own SSO, mock identity, and a local decision point for time-bound Agent
actions in development and self-hosted environments.

## Core User

- Solo builders creating multiple apps.
- Developers testing auth integrations locally.
- Self-hosters who want one local identity hub for their own tools.
- Developers who want an Agent to act on an application without treating the
  Agent as the Human or granting an unbounded semantic permission.

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

For agent actions that have application meaning beyond an HTTP path, an
application can declare semantic actions and resource types. A registered agent
requests one action on one resource for a task, the local user approves or
denies it, and a policy enforcement point asks AnyAuth for an allow/deny
decision. Approved grants are time-bound, revocable, and included in the local
audit timeline.

## Operating Modes

- `serve` starts only the local provider and is the default path for real apps
  the user owns.
- `protect` starts the provider plus a local reverse proxy in front of one
  upstream app.
- `demo` starts the provider plus two built-in demo apps for validating SSO
  behavior without creating a separate test application.
- The provider also serves the local semantic authorization request, approval,
  and decision endpoints in every operating mode.

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
