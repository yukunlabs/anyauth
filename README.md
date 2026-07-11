# AnyAuth

AnyAuth is a local identity and authorization hub for software and agents you
control.

It gives local apps one development identity, puts browser or agent traffic
behind an authentication proxy, and lets a human approve a specific agent
action on a specific resource for a limited time.

> **Project status:** experimental local prototype. AnyAuth binds to loopback
> by default and is not production identity infrastructure.

## Why AnyAuth

Authentication answers **who is this?** Agentic software adds a second
question: **what may this agent do, for which task, and for how long?**

AnyAuth explores both questions in one local system:

```text
Browser ── OIDC / session ───────────────┐
                                         ├──> AnyAuth ──> apps you control
Agent ─── delegation token ──> proxy ────┤
                                         │
Agent ─── action request ──> approval ───┘──> grant + allow/deny decision
```

The current prototype supports four practical development workflows:

| Need | AnyAuth capability |
| --- | --- |
| Test login across local apps | Local OIDC-style provider and two-app SSO demo |
| Add login in front of an existing app | Reverse proxy with trusted identity headers |
| Let an agent call a local HTTP service | Short-lived delegation token plus method/path/scope policy |
| Approve an application-level agent action | Typed action request, browser approval, expiring grant, and decision API |

The last workflow is the main product direction. It models authority as
`actor + human + application + action + resource + task + lifetime`, rather
than treating an agent as the human or granting it an unbounded credential.

## Quick Start

Requirements: Go 1.22 or later.

Start the built-in provider and two demo apps:

```bash
make demo
```

Then open:

- Provider: <http://127.0.0.1:7100>
- Demo App A: <http://127.0.0.1:7101>
- Demo App B: <http://127.0.0.1:7102>

Log in to App A, then open App B. The second app should reuse the provider
session without asking you to log in again.

AnyAuth keeps development identity state in `.anyauth/`. To start again with a
fresh local identity and key, stop the process and run:

```bash
make clean-state
```

## Try Semantic Agent Authorization

This flow demonstrates the part of AnyAuth that goes beyond local SSO.

Register the example agent and application capability, then start the provider:

```bash
make agent-add
make application-add
make run
```

In another terminal, submit an authorization request:

```bash
make authz-request
```

Open <http://127.0.0.1:7100/approvals>. The page shows the agent, human,
application, action, resource, task, and requested lifetime. Approve or deny the
request; if you configured a local PIN, the decision requires it.

After approval, evaluate the exact action and inspect the resulting state:

```bash
make authz-check
make authz-requests
make authz-grants
make audit-list
```

The default example asks whether `agent:codex`, acting for the local user, may
perform `issue.create` on `repository:yukunlabs/anyauth` for the task
`local-authz-demo`. AnyAuth records and evaluates that authority; it does not
execute the GitHub action.

Revoke a grant with:

```bash
go run ./cmd/anyauth authz revoke --id grt_...
```

The local decision endpoint is:

```text
POST http://127.0.0.1:7100/access/v1/evaluation
```

Its subject/action/resource/context shape is inspired by the OpenID AuthZEN
Authorization API. The prototype adds explicit actor and application fields and
is not a complete or conformant AuthZEN deployment.

## Protect A Local App

AnyAuth can add browser login in front of an app that does not implement OIDC.

Start the bundled upstream test app:

```bash
make dev-upstream
```

In another terminal, start the protected proxy:

```bash
make protect
```

Open <http://127.0.0.1:7200/hello?x=1>. AnyAuth signs in the local user and
forwards the request with `X-AnyAuth-*` identity headers.

Point the proxy at another local service when needed:

```bash
make protect UPSTREAM=http://127.0.0.1:4000 PROTECT_PORT=7400
```

The upstream must only trust `X-AnyAuth-*` headers on traffic that actually
arrived through the AnyAuth proxy.

## Delegate Local HTTP Access To An Agent

The protected proxy can require a short-lived agent delegation token instead
of a browser session. The upstream receives both the human identity and the
agent, task, delegation, and scope context.

Start the upstream and agent-aware proxy in separate terminals:

```bash
make dev-upstream
```

```bash
make protect-agent
```

Then create the local policy and token:

```bash
make agent-add
make policy-allow-hello
make policy-deny-admin
TOKEN=$(make delegate-token)

curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:7200/hello?x=1"

curl -i -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:7200/admin"

make audit-list
```

The `/hello` request is allowed for the `app.read` scope. The `/admin` request
is denied by policy. Once any proxy policies exist, unmatched delegated agent
requests default to deny.

If the local profile uses a different PIN, pass it while creating the token:

```bash
TOKEN=$(make delegate-token PIN=654321)
```

## Connect An OIDC Client

Register an app you own:

```bash
go run ./cmd/anyauth clients add \
  --id my-app \
  --name "My App" \
  --redirect-uri http://127.0.0.1:3000/callback

make run
```

Use the generated development client secret with these endpoints:

```text
Issuer:                http://127.0.0.1:7100
Authorization:         http://127.0.0.1:7100/authorize
Token:                 http://127.0.0.1:7100/token
JWKS:                  http://127.0.0.1:7100/jwks.json
UserInfo:              http://127.0.0.1:7100/userinfo
Discovery:             http://127.0.0.1:7100/.well-known/openid-configuration
```

The prototype implements a deliberately small Authorization Code + PKCE path.
Evaluate a mature OAuth/OIDC library and conformance coverage before using this
protocol core beyond local development.

## Local PIN

A local PIN can gate creation of the provider session and approval of semantic
agent actions:

```bash
make user-show
make set-pin PIN=123456
make clear-pin
```

The PIN is optional and is stored as a salted PBKDF2-SHA256 verifier. It is a
local development safeguard, not phishing-resistant authentication.

## Security Boundary

AnyAuth is currently designed for one local operator and apps bound to or
reachable through the local machine. In particular:

- it cannot make arbitrary third-party websites trust your local identity;
- local JSON state, client secrets, agent metadata, and audit records are not a
  production persistence or key-management system;
- delegation tokens are Bearer tokens until they expire or are revoked;
- protected apps remain reachable directly unless you separately restrict
  their listening address or network path;
- the semantic request and decision APIs are local prototype interfaces, not
  authenticated remote policy-enforcement boundaries;
- approving an action creates authority data—it does not execute the action.

Read [docs/security-boundaries.md](docs/security-boundaries.md) before using
AnyAuth for anything beyond local experimentation.

## Current Scope

Implemented today:

- local provider session, discovery, JWKS, UserInfo, and Authorization Code flow
  with PKCE;
- optional local PIN verification and persistent local client/user state;
- browser and agent-aware protected proxy modes;
- registered agents, short-lived task-scoped delegation tokens, revocation,
  proxy policy, and audit events;
- semantic applications, typed actions/resources, authorization requests,
  browser approval, expiring and revocable grants, parent/child attenuation,
  and default-deny evaluation;
- a single Go process with server-rendered local UI and no third-party Go
  dependencies.

Not implemented includes production storage or key management, passkeys,
refresh tokens, multi-user or multi-tenant administration, upstream social
login, complete OIDC/AuthZEN conformance, remote approval workflows, and
automatic execution of approved actions.

See [docs/mvp-scope.md](docs/mvp-scope.md) for the complete scope.

## Development

Run the full local verification gate:

```bash
make verify
```

Common targets:

```bash
make fmt
make test
make build
make smoke-protect
make smoke-agent-protect
make smoke-policy-protect
make smoke-authz
make clean
make clean-state
```

Further reading:

- [Product brief](docs/product-brief.md)
- [MVP scope](docs/mvp-scope.md)
- [Security boundaries](docs/security-boundaries.md)
- [Testing workflow](docs/testing.md)
- [Stack decision](docs/stack-decision.md)
- [Development process](docs/development-process.md)

AI agents should start with [AGENTS.md](AGENTS.md).
