# Stack Decision

## Decision

Use Go for the AnyAuth core.

For the first UI, use server-rendered HTML from the Go process. Do not introduce
a separate frontend build pipeline until the console needs richer interaction.

## Why Go

- The maintainer's primary language is Go.
- AnyAuth naturally wants a single local binary.
- CLI, local daemon, HTTP server, reverse proxy hooks, and self-hosted
  deployment are all comfortable in Go.
- Go's standard library is enough for a useful first local prototype.
- Future packaging through Homebrew, Docker, or direct binary downloads is
  straightforward.

## UI Strategy

### v0 / v1

- Go `net/http`
- Server-rendered HTML
- Minimal CSS
- No Node requirement

This covers:

- Login page
- Consent / continue page
- Client list
- Discovery and JWKS inspection
- Basic audit/session views

### Later

Introduce TypeScript + React only when the UI needs:

- Complex admin console
- Visual auth test reports
- Multi-client configuration workflows
- Tenant and permission visualization
- Rich local developer dashboard

The React app should compile to static assets and be embedded into the Go
binary.

## Protocol Library Direction

The current local demo uses a small standard-library implementation to keep the
first milestone understandable. It is not intended to become a hand-rolled
production identity server.

Before production use, evaluate:

- `github.com/zitadel/oidc` for a Go OIDC provider implementation.
- `github.com/ory/fosite` for a lower-level OAuth2/OIDC framework.

The likely path is:

1. Keep the v0 local demo small and readable.
2. Add tests around the observable OIDC behavior.
3. Replace or wrap the protocol core with a mature library once requirements are
   clearer.
