# AGENTS.md

This file is the entry point for AI agents working on AnyAuth.

## Project Intent

AnyAuth is an experimental local-first authentication and authorization hub for
apps owned by the developer. In addition to local SSO, it explores minimal,
time-bound, revocable, and auditable authority for agents acting on behalf of
the local user. It is currently a local development prototype, not production
identity or authorization infrastructure.

Read these files before changing behavior:

- `docs/development-process.md`
- `docs/product-brief.md`
- `docs/security-boundaries.md`
- `docs/stack-decision.md`
- `docs/mvp-scope.md`
- `docs/testing.md`

## Working Rules

- Keep every commit a closed loop: one clear capability, fix, or documentation
  update.
- Do not leave `main` broken.
- Do not create release tags or GitHub Releases during the experimental phase
  unless the user explicitly asks for one.
- Keep changes small and reversible.
- Update docs when behavior, workflow, security boundaries, or project scope
  change.
- Do not commit local runtime state such as `.anyauth/`, `bin/`, scratch files,
  or private notes.

## Verification

Before committing, run:

```bash
make verify
```

For protocol or UI-flow changes, also run the affected product flow manually.
Examples:

```bash
make run
make demo
make dev-upstream
make protect
make protect-agent
make agent-add
make delegate-token
make policy-allow-hello
make policy-deny-admin
make policies-list
make audit-list
make user-show
make set-pin PIN=123456
make clear-pin
```

Use `make clean` for build outputs and `make clean-state` for local AnyAuth
runtime state. Keep them separate because `.anyauth/` contains local identity
state used during debugging.

## Stack Direction

- Core language: Go.
- First UI: server-rendered HTML from the Go process.
- Avoid adding a Node/React frontend until the console needs richer interaction.
- Prefer the Go standard library while the prototype is small.
- Evaluate mature OIDC/OAuth libraries before treating the protocol core as
  production-ready.

## Documentation Policy

Public project docs belong in `docs/` and should be committed.

Use ignored local notes for private ideation, rough market research, credentials,
or personal operating notes. Do not put private research or secrets in `docs/`.

## Security Posture

Be explicit about what is and is not secure. If a feature improves local safety
but is still not production-grade, say so in `docs/security-boundaries.md`.
