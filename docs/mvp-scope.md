# MVP Scope

## Goal

Build a runnable local provider that proves AnyAuth can act as an identity hub
for apps owned by the same developer, a protected proxy mode for local apps, and
a built-in demo mode for local SSO validation. The MVP also proves a first
agent authorization path where a registered local agent can access a protected
upstream app through a short-lived delegation token.

## In Scope

- Provider-first `serve` mode on `127.0.0.1:7100`
- Demo mode with Demo App A on `127.0.0.1:7101`
- Demo mode with Demo App B on `127.0.0.1:7102`
- Protected proxy mode on `127.0.0.1:7200`
- Authorization Code flow with PKCE
- One local user
- Optional local PIN verification before provider session creation
- Persistent local client registry
- Persistent local agent registry
- Persistent local delegation records without storing token plaintext
- Task metadata on delegation records, delegation tokens, upstream headers, and
  audit events
- Persistent local proxy policy rules
- Local audit timeline for delegation and protected proxy decisions
- In-memory authorization codes, access tokens, and sessions
- Discovery endpoint
- JWKS endpoint
- UserInfo endpoint
- RS256 ID token signing through a local RSA key
- Reverse proxy to one local upstream app
- Identity headers for authenticated upstream requests
- Agent-aware identity and delegation headers for delegated upstream requests
- Task-aware headers for delegated upstream requests
- Method, path-prefix, agent, and scope policies for delegated upstream requests
- Single Go binary entrypoint through `cmd/anyauth`
- `serve`, `protect`, and `demo` CLI commands
- `clients add` and `clients list` CLI commands
- `agents add`, `agents list`, and `agents remove` CLI commands
- `delegate create`, `delegate list`, and `delegate revoke` CLI commands
- `policy add`, `policy list`, and `policy remove` CLI commands
- `audit list` CLI command
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
- Request body inspection and operation-level policy enforcement inside
  upstream apps
- Full interactive approval UI for agent actions

## Success Criteria

- In demo mode, a user can log in to Demo App A through AnyAuth.
- In demo mode, opening Demo App B reuses the AnyAuth provider session.
- In protect mode, an unauthenticated request is redirected to AnyAuth and then
  proxied to the upstream app with identity headers.
- In agent delegation mode, a request with a valid delegation Bearer token is
  proxied to the upstream app with human, agent, delegation, and scope headers.
- In agent delegation mode, a request without a valid delegation token returns
  `401`.
- In agent delegation mode, configured proxy policies can allow or deny
  delegated requests before the upstream app is reached.
- Delegation creation, proxy allow, proxy deny, and delegation revocation can be
  inspected through `audit list`.
- The provider exposes standard-looking OIDC metadata and JWKS.
- The repo explains the security boundary clearly.
- The first implementation has no third-party Go dependencies.
