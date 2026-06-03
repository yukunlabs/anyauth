# AnyAuth

AnyAuth is a local-first authentication hub for developers and solo builders.

The first milestone is intentionally small: run a local OpenID Connect-style
provider and two demo apps to prove local SSO across apps you own.

## What This Is

- A local SSO hub for development and self-hosted environments.
- A protocol-compatible playground for apps you control.
- A foundation for future auth modes such as passkeys, forward-auth, upstream
  identity brokers, and auth integration tests.

## What This Is Not

- It is not a Google/GitHub/Apple login replacement.
- It cannot log you into arbitrary third-party websites.
- The current prototype is not production-grade security software.

## Run The Local Demo

Requirements:

- Go 1.22+

Start the provider and two demo apps:

```bash
go run ./cmd/anyauth serve
```

Open:

- Provider: http://127.0.0.1:7100
- Demo App A: http://127.0.0.1:7101
- Demo App B: http://127.0.0.1:7102

Try App A first, click login, continue as the local user, then open App B.
App B should complete login through the same provider session without asking
you to log in again.

## Initial Scope

The local demo includes:

- OIDC discovery metadata
- JWKS endpoint
- Authorization Code flow with PKCE
- Local provider session
- ID token signing with a locally generated RSA key
- UserInfo endpoint
- Two demo clients

See [docs/mvp-scope.md](docs/mvp-scope.md) and
[docs/security-boundaries.md](docs/security-boundaries.md).

## Stack Direction

AnyAuth starts with Go and server-rendered local UI:

- Go fits the long-term shape: CLI, local daemon, protocol server, reverse proxy
  integrations, and single-binary distribution.
- The first UI is intentionally server-rendered to avoid requiring Node for the
  local tool.
- A TypeScript/React console can be added later when the product needs complex
  dashboards, visual test reports, or workflow editing.

See [docs/stack-decision.md](docs/stack-decision.md).

## Development

```bash
go test ./...
go run ./cmd/anyauth serve
```

Build a local binary:

```bash
go build -o bin/anyauth ./cmd/anyauth
```

The repository starts as a local Git repository. Create the GitHub remote once
the first runnable Go version has been verified locally.
