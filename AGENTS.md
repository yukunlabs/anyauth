# AGENTS.md

This file is the entry point for AI agents working on AnyAuth.

## Project Intent

AnyAuth is an experimental local-first authentication hub for apps owned by the
developer. It is currently a local development prototype, not production
identity infrastructure.

Read these files before changing behavior:

- `docs/development-process.md`
- `docs/product-brief.md`
- `docs/security-boundaries.md`
- `docs/stack-decision.md`
- `docs/mvp-scope.md`

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
make fmt
make test
make build
```

For protocol or UI-flow changes, also run a focused smoke test for the affected
path. Examples:

```bash
go run ./cmd/anyauth user show
printf "123456\n" | go run ./cmd/anyauth user set-pin --pin-stdin
go run ./cmd/anyauth user clear-pin
```

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
