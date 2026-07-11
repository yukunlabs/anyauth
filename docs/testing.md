# Testing Workflow

AnyAuth uses a small product-oriented test ladder. Each level answers a
different question.

## 1. Commit Gate

Run this before committing:

```bash
make verify
```

This formats Go code, runs the full Go test suite, builds the CLI, runs the
protected-proxy smoke tests, and checks helper scripts.

CI uses the non-mutating equivalent:

```bash
make ci
```

## 2. Product Smoke Test

Use this when validating the core protected-proxy experience manually.

Terminal 1:

```bash
make dev-upstream
```

Terminal 2:

```bash
make protect
```

Open:

```text
http://127.0.0.1:7200/hello?x=1
```

Expected result:

- The first request redirects to the AnyAuth login page.
- After login, the browser returns to `/hello?x=1`.
- The upstream app shows `X-AnyAuth-Authenticated: true`.
- The upstream app shows the local user headers: `X-AnyAuth-Sub`,
  `X-AnyAuth-Name`, and `X-AnyAuth-Email`.

Override ports when needed:

```bash
make dev-upstream UPSTREAM_PORT=4000
make protect UPSTREAM=http://127.0.0.1:4000 PROTECT_PORT=7400
```

## 3. Agent Delegation Smoke Test

Use this when validating the agent delegation path manually.

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

If the local profile has a non-default PIN, use:

```bash
TOKEN=$(make delegate-token PIN=654321)
```

Expected result:

- Requests without `Authorization: Bearer <token>` return `401`.
- Requests with a valid token reach the upstream app.
- The upstream app shows `X-AnyAuth-Actor-Type: agent`.
- The upstream app shows `X-AnyAuth-Agent-ID`, `X-AnyAuth-Delegation-ID`,
  `X-AnyAuth-Task-Name`, and `X-AnyAuth-Scopes`.
- The upstream app still receives the delegated local user through
  `X-AnyAuth-Sub`, `X-AnyAuth-Name`, and `X-AnyAuth-Email`.
- `/admin` returns `403` because `policy-deny-admin` blocks it.
- `audit-list` shows delegation creation and proxy allow/deny events.

Automated smoke coverage:

```bash
make smoke-agent-protect
make smoke-policy-protect
```

## 4. Semantic Authorization Approval

Use this when changing application actions, authorization requests, approvals,
grants, or the local decision API.

```bash
make agent-add
make application-add
make run
```

In another terminal:

```bash
make authz-request
```

Open `http://127.0.0.1:7100/approvals`, approve the request, then run:

```bash
make authz-check
make authz-requests
make authz-grants
make audit-list
```

Copy the grant id from `authz-grants`, revoke it, and repeat the check:

```bash
go run ./cmd/anyauth authz revoke --id grt_...
make authz-check
```

Expected result:

- The request shows the Agent, Human, Application, Action, Resource, Task, and
  requested lifetime.
- A configured PIN is required before approval or denial.
- The exact approved action returns `Decision: true`.
- A different action, resource, task, actor, or application returns a deny
  decision or validation error.
- Revoking the grant changes the same check to `Decision: false`.
- Request, approval, and access decisions appear in the audit timeline.

Automated smoke coverage:

```bash
make smoke-authz
```

## 5. Policy Behavior

Use this when changing delegated-agent authorization policy behavior.

Rules are stored in local `policies.json`. When no policies are configured,
delegated agent requests are allowed after token validation. Once at least one
policy exists, the proxy defaults to deny unless a matching allow policy applies.
Deny policies take priority.

Useful commands:

```bash
make policy-allow-hello
make policy-deny-admin
make policies-list
```

Expected result:

- `GET /hello...` is allowed for a token with `app.read`.
- `/admin...` is denied.
- Any unmatched path is denied once policies exist.
- Policy decisions appear in `audit-list`.

## 6. Protocol Demo Smoke Test

Use this when changing OAuth/OIDC flow behavior.

```bash
make demo
```

Open:

```text
http://127.0.0.1:7101
```

Expected result:

- Demo App A can log in through AnyAuth.
- Demo App B reuses the provider SSO session.
- PIN verification is required if a PIN is configured.

## 7. Local State Checks

Show the local user:

```bash
make user-show
```

Set a PIN:

```bash
make set-pin PIN=123456
```

Clear the PIN:

```bash
make clear-pin
```

## Cleanup

Remove build outputs and Python bytecode:

```bash
make clean
```

Remove local AnyAuth state, including the generated development key and local
user profile:

```bash
make clean-state
```

`make clean-state` is useful before testing first-run behavior. It is separate
from `make clean` because local identity state can matter while debugging.
