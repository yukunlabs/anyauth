# AnyAuth

AnyAuth is a local-first authentication and agent authorization hub for
developers and solo builders.

Repository: https://github.com/yukunlabs/anyauth

The prototype runs a local OpenID Connect-style provider, protects apps you own
behind a local SSO gateway, and lets a local user approve semantic, time-bound
actions for registered agents.

## What This Is

- A local SSO hub for development and self-hosted environments.
- A protocol-compatible playground for apps you control.
- A local approval and authorization decision point for semantic Agent actions.
- A foundation for future auth modes such as passkeys, forward-auth, upstream
  identity brokers, and auth integration tests.

## What This Is Not

- It is not a Google/GitHub/Apple login replacement.
- It cannot log you into arbitrary third-party websites.
- The current prototype is not production-grade security software.
- The semantic decision API is not yet an authenticated remote enforcement
  boundary or action executor.

## Run The Local Provider

Requirements:

- Go 1.22+

Start the provider:

```bash
make run
```

Open:

- Provider: http://127.0.0.1:7100

`serve` is provider-first: it does not start the built-in demo apps. Use this
mode when connecting AnyAuth to apps you own.

## Protect A Local App

Start any local web app, then put AnyAuth in front of it:

```bash
make protect
```

Open:

- Protected app: http://127.0.0.1:7200
- Provider: http://127.0.0.1:7100

The protected proxy signs you in through AnyAuth before forwarding traffic to
the upstream app. Authenticated upstream requests receive:

```text
X-AnyAuth-Authenticated: true
X-AnyAuth-Sub: local-user
X-AnyAuth-Name: Local User
X-AnyAuth-Email: local.user@anyauth.local
```

Use this when you want to put SSO in front of a local app without wiring OIDC
into that app yet.

For a quick manual test, run the bundled upstream test app in one terminal:

```bash
make dev-upstream
```

Then run the protected proxy in another terminal:

```bash
make protect
```

Open `http://127.0.0.1:7200/hello?x=1`. After login, the upstream page should
show the request path and `X-AnyAuth-*` identity headers.

Override ports or upstream URL when needed:

```bash
make dev-upstream UPSTREAM_PORT=4000
make protect UPSTREAM=http://127.0.0.1:4000 PROTECT_PORT=7400
```

## Authorize An Agent For A Local App

AnyAuth can also protect an upstream app for agent traffic. A registered agent
gets a short-lived delegation token, then calls the protected proxy with
`Authorization: Bearer <token>`. The upstream app receives both the local human
identity and the explicit agent/delegation identity.

Terminal 1:

```bash
make dev-upstream
```

Terminal 2:

```bash
make protect-agent
```

Terminal 3:

```bash
make agent-add
make policy-allow-hello
make policy-deny-admin
TOKEN=$(make delegate-token)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7200/hello?x=1
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:7200/admin
make audit-list
```

If your local profile uses a custom PIN, pass it to the token target:

```bash
TOKEN=$(make delegate-token PIN=654321)
```

The upstream app should show headers such as:

```text
X-AnyAuth-Authenticated: true
X-AnyAuth-Actor-Type: agent
X-AnyAuth-Sub: local-user
X-AnyAuth-Human-Sub: local-user
X-AnyAuth-Agent-ID: codex
X-AnyAuth-Delegation-ID: del_...
X-AnyAuth-Task-ID: task_...
X-AnyAuth-Task-Name: Local demo task
X-AnyAuth-Scopes: app.read
```

Without a valid delegation token, `protect-agent` returns `401` instead of
redirecting to the browser login flow.

Once policies exist, `protect-agent` defaults to deny unless a matching allow
policy applies. `policy-allow-hello` allows `GET /hello*` for `app.read`, while
`policy-deny-admin` blocks `/admin*`.

`audit-list` shows local delegation and proxy allow/deny events without storing
the delegation token plaintext.

## Approve A Semantic Agent Action

AnyAuth can model application actions and resources independently from HTTP
paths. A registered agent submits a request, the local user reviews it in the
provider UI, and an approved grant can be checked through the local decision
API.

Register an agent and an application capability:

```bash
make agent-add
make application-add
```

An authorization application is a semantic action/resource catalog. It is
separate from an OIDC client registration.

Start the provider:

```bash
make run
```

In another terminal, request authority:

```bash
make authz-request
```

Open `http://127.0.0.1:7100/approvals`, review the requested action and
resource, then approve or deny it. If a local PIN is configured, approval
requires that PIN.

After approval, check the exact action:

```bash
make authz-check
make authz-requests
make authz-grants
make audit-list
```

Revoke an approved grant when it is no longer needed:

```bash
go run ./cmd/anyauth authz revoke --id grt_...
```

The default example asks whether `agent:codex`, acting for the local user, may
perform `issue.create` on `repository:yukunlabs/anyauth` for task
`local-authz-demo`.

The decision endpoint is:

```text
POST http://127.0.0.1:7100/access/v1/evaluation
```

Its `subject` / `action` / `resource` / `context` decision shape follows the
OpenID AuthZEN Authorization API model. AnyAuth currently adds required
`actor` and `application_id` fields and does not yet implement the complete
AuthZEN API or PEP authentication, so this is an AuthZEN-shaped local prototype
rather than a conformant deployment.

## Run The Local Demo

Start the provider and two demo apps:

```bash
make demo
```

Open:

- Provider: http://127.0.0.1:7100
- Demo App A: http://127.0.0.1:7101
- Demo App B: http://127.0.0.1:7102

Try App A first, click login, continue as the local user, then open App B.
App B should complete login through the same provider session without asking
you to log in again.

## Register Your Own Local App

Add a client:

```bash
go run ./cmd/anyauth clients add \
  --id my-app \
  --name "My App" \
  --redirect-uri http://127.0.0.1:3000/callback
```

List clients:

```bash
go run ./cmd/anyauth clients list
```

Then start AnyAuth with the same data directory:

```bash
make run
```

Use the generated client secret and this issuer in your app:

```text
Issuer: http://127.0.0.1:7100
Authorization endpoint: http://127.0.0.1:7100/authorize
Token endpoint: http://127.0.0.1:7100/token
JWKS URI: http://127.0.0.1:7100/jwks.json
UserInfo endpoint: http://127.0.0.1:7100/userinfo
```

## Configure Local PIN Verification

AnyAuth can require a local PIN before it creates the provider SSO session.

Show the local user profile:

```bash
make user-show
```

Set a PIN:

```bash
make set-pin PIN=123456
```

After a PIN is configured, the provider login page will require that PIN before
redirecting back to the client app.

Clear the PIN and return to the no-PIN development login:

```bash
make clear-pin
```

## Initial Scope

The current prototype includes:

- OIDC discovery metadata
- JWKS endpoint
- Authorization Code flow with PKCE
- Local provider session
- Optional local PIN verification
- Persistent local client registry
- Persistent local agent registry
- Short-lived agent delegation tokens
- Task-scoped delegation metadata in tokens, headers, and audit events
- Local path/method/scope policies for delegated agent requests
- Semantic application, action, resource, request, approval, and grant model
- Local approval page for semantic agent actions
- AuthZEN-shaped local access evaluation endpoint
- Local audit timeline for delegation and protected proxy events
- Client and user management CLI commands
- ID token signing with a locally generated RSA key
- UserInfo endpoint
- Protected reverse proxy mode with identity headers
- Agent-aware protected proxy mode with delegation headers
- Demo mode with two built-in clients

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

Use the full local verification gate before committing:

```bash
make verify
```

The main development commands are:

```bash
make fmt
make test
make build
make smoke-protect
make smoke-agent-protect
make smoke-policy-protect
make run
make demo
make protect
make protect-agent
make dev-upstream
make agent-add
make delegate-token
make policy-allow-hello
make policy-deny-admin
make policies-list
make audit-list
make clean
make clean-state
```

Build a local binary:

```bash
go build -o bin/anyauth ./cmd/anyauth
```

During the experimental phase, every commit should be a closed loop and release
tags should only be created when explicitly planned. See
[docs/development-process.md](docs/development-process.md).

See [docs/testing.md](docs/testing.md) for the product smoke test flow.

AI agents should start with [AGENTS.md](AGENTS.md).
