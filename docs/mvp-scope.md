# MVP Scope

## Goal

Build a runnable local provider that proves AnyAuth can act as an identity hub
for apps owned by the same developer, with a built-in demo mode for local SSO
validation.

## In Scope

- Provider-first `serve` mode on `127.0.0.1:7100`
- Demo mode with Demo App A on `127.0.0.1:7101`
- Demo mode with Demo App B on `127.0.0.1:7102`
- Authorization Code flow with PKCE
- One local user
- Optional local PIN verification before provider session creation
- Persistent local client registry
- In-memory authorization codes, access tokens, and sessions
- Discovery endpoint
- JWKS endpoint
- UserInfo endpoint
- RS256 ID token signing through a local RSA key
- Single Go binary entrypoint through `cmd/anyauth`
- `serve` and `demo` CLI commands
- `clients add` and `clients list` CLI commands
- `user show`, `user set-pin`, and `user clear-pin` CLI commands

## Out Of Scope

- Production persistence
- Production-grade password or passkey storage
- Passkeys / Touch ID
- Refresh tokens
- Client management UI
- Multi-user admin
- Multi-tenant support
- SAML / LDAP
- Upstream Google/GitHub login
- Arbitrary third-party website login

## Success Criteria

- In demo mode, a user can log in to Demo App A through AnyAuth.
- In demo mode, opening Demo App B reuses the AnyAuth provider session.
- The provider exposes standard-looking OIDC metadata and JWKS.
- The repo explains the security boundary clearly.
- The first implementation has no third-party Go dependencies.
