# Security Boundaries

This repository currently contains a local development prototype. It should not
be treated as production identity infrastructure.

## Current Assumptions

- The provider binds to `127.0.0.1`.
- The protected proxy binds to `127.0.0.1` when enabled.
- The only user is the local operator.
- Protected upstream apps are assumed to be local apps controlled by the user.
- Client registry is stored as local JSON in the AnyAuth data directory.
- Agent registry is stored as local JSON in the AnyAuth data directory.
- Agent delegation records are stored as local JSON in the AnyAuth data
  directory.
- Proxy policy rules are stored as local JSON in the AnyAuth data directory.
- Audit events are stored as local JSON Lines in the AnyAuth data directory.
- Semantic authorization applications, requests, and grants are stored in one
  local JSON file in the AnyAuth data directory.
- Local user profile is stored as local JSON in the AnyAuth data directory.
- Sessions, codes, and tokens are in-memory.
- When configured, the login screen requires a local PIN before creating the
  provider session.
- Agent delegation tokens are short-lived Bearer JWTs minted by the local
  operator.

## Current Protections

- Authorization Code flow uses PKCE.
- Redirect URIs are matched exactly.
- Authorization codes are one-time use.
- ID tokens are signed with RS256.
- Demo clients verify RS256 ID token signatures.
- Demo clients validate issuer, audience, expiration, and nonce.
- Protected proxy sessions validate issuer, audience, expiration, and nonce.
- The protected proxy strips incoming `X-AnyAuth-*` identity headers before
  injecting the authenticated local identity.
- The protected proxy can require agent delegation Bearer tokens instead of
  browser SSO redirects.
- Delegation tokens are signed with RS256 and validated for issuer, audience,
  expiration, not-before, token type, token id, token hash, registered agent,
  and revocation state.
- Delegation tokens use an explicit actor claim plus AnyAuth-specific
  delegation metadata, so upstream apps can distinguish human browser traffic
  from agent traffic.
- Delegation tokens can carry task metadata so upstream apps and audit logs can
  tie agent requests back to the local task context.
- In agent delegation mode, the protected proxy removes the incoming
  `Authorization` header before forwarding to the upstream app.
- In agent delegation mode, the protected proxy can enforce local method,
  path-prefix, agent, and scope policies before forwarding to the upstream app.
- When policy rules exist, deny rules take priority and unmatched delegated
  agent requests are denied.
- Delegation creation, revocation, protected proxy allow, and protected proxy
  deny events are appended to a local audit timeline.
- Access tokens must be presented as Bearer tokens for UserInfo.
- PINs are stored as salted PBKDF2-SHA256 verifiers, not plaintext.
- PIN verification is optional and can be disabled with `user clear-pin`.
- Semantic grants are scoped to one actor, human subject, application, action,
  resource selector, optional task, and validity window.
- Semantic authorization is default-deny and validates the complete parent
  grant chain. A child grant cannot broaden its parent's action, resource,
  application, subject, task binding, or lifetime.
- Semantic access decisions are audited with a decision id and determining
  grant ids. A decision fails closed if its grant source or decision audit write
  fails.
- Browser approval POSTs reject a mismatched `Origin` or `Referer`, and require
  the local PIN when one is configured.

## Known Gaps

- No general CSRF token framework. Semantic approval POSTs perform local
  origin/referrer validation, while the OAuth flow relies on `state`.
- No session persistence or secure local key management.
- No refresh-token rotation.
- No key rotation.
- No phishing-resistant local user verification.
- No conformance test suite.
- Client secrets are stored in local plaintext JSON.
- Agent metadata, delegation records, and policy rules are stored in local
  plaintext JSON.
- Audit events are stored in local plaintext JSON Lines.
- Delegation tokens are Bearer tokens. Anyone who obtains one can use it until
  it expires or is revoked.
- Delegation token creation is a local CLI action, not a full interactive
  consent workflow.
- Proxy policies currently cover HTTP method, path prefix, agent id, and
  delegation scopes. They do not inspect request bodies or enforce
  operation-level policy inside the upstream app.
- Protected upstream apps can still be reached directly if they listen on an
  accessible port; the proxy only protects traffic that enters through AnyAuth.
- Protected upstream apps must treat `X-AnyAuth-*` headers as trusted only when
  the request comes from the AnyAuth proxy.
- The protected proxy reserves `__anyauth/*` paths for its own login, callback,
  and logout routes.
- A local PIN is weaker than passkeys or OS-backed biometric verification.
- ID token claim validation handles only the simple v0 shape, not all OIDC edge
  cases such as array audiences, `azp`, or clock skew policy.
- The semantic authorization request and evaluation APIs bind only to the local
  provider and do not yet authenticate the requesting agent or policy
  enforcement point. Caller-supplied actor identity is suitable only for this
  local development prototype.
- When no PIN is configured, semantic approval relies on an explicit action in
  the local browser plus same-origin request checks; it is not strong user
  verification.
- Approved semantic grants are server-side decision records. AnyAuth does not
  yet project them into a holder-bound credential or execute the approved
  upstream action.
- The JSON authorization store is atomic per write but does not provide
  cross-process transactions or production concurrency guarantees.

## Intended Next Security Milestones

1. Authenticate agents and policy enforcement points for semantic requests and
   decisions.
2. Project approved grants into sender-constrained or holder-bound credentials.
3. Add passkey or OS credential prompt verification.
4. Replace local plaintext secrets and in-memory state with an encrypted store.
5. Add structured protocol tests and negative cases.
6. Add refresh token rotation.
7. Evaluate replacing the prototype core with a mature OIDC library.
