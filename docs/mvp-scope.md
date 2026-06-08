# MVP Scope

## Goal

Build a runnable local SSO demo that proves AnyAuth can act as an identity hub
for apps owned by the same developer.

## In Scope

- Local OIDC-style provider on `127.0.0.1:7100`
- Demo App A on `127.0.0.1:7101`
- Demo App B on `127.0.0.1:7102`
- Authorization Code flow with PKCE
- One local user
- Persistent local client registry
- In-memory authorization codes, access tokens, and sessions
- Discovery endpoint
- JWKS endpoint
- UserInfo endpoint
- RS256 ID token signing through a local RSA key
- Single Go binary entrypoint through `cmd/anyauth`
- `clients add` and `clients list` CLI commands

## Out Of Scope

- Production persistence
- Real password storage
- Passkeys / Touch ID
- Refresh tokens
- Client management UI
- Multi-user admin
- Multi-tenant support
- SAML / LDAP
- Upstream Google/GitHub login
- Arbitrary third-party website login

## Success Criteria

- A user can log in to Demo App A through AnyAuth.
- Opening Demo App B reuses the AnyAuth provider session.
- The provider exposes standard-looking OIDC metadata and JWKS.
- The repo explains the security boundary clearly.
- The first implementation has no third-party Go dependencies.
