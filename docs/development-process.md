# Development Process

AnyAuth is still experimental. During this phase, progress should stay
incremental and every commit must leave the project in a coherent state.

## Commit Standard

Every commit should be a closed loop:

- It introduces one clear capability, fix, or documentation/process update.
- It keeps the repository buildable and testable.
- It updates docs when behavior or workflow changes.
- It avoids mixing unrelated refactors with product changes.
- It includes verification before commit, usually:

```bash
make fmt
make test
make build
```

For UI or protocol-flow changes, also run a local smoke test against the
affected path.

## Experimental Release Policy

Do not create release tags during the experimental phase.

Use normal commits on `main` for iteration. Create a tag or GitHub Release only
when we explicitly decide a milestone is stable enough to name and preserve.

## Suggested Commit Shape

Prefer small commits that can be described as:

```text
Add <capability>
Fix <specific behavior>
Document <decision/process>
```

Avoid commits that can only be described as broad buckets such as:

```text
WIP
misc changes
big refactor
```
