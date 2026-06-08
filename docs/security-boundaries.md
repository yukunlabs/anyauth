# Security Boundaries

This repository currently contains a local development prototype. It should not
be treated as production identity infrastructure.

## Current Assumptions

- The provider binds to `127.0.0.1`.
- The protected proxy binds to `127.0.0.1` when enabled.
- The only user is the local operator.
- Protected upstream apps are assumed to be local apps controlled by the user.
- Client registry is stored as local JSON in the AnyAuth data directory.
- Local user profile is stored as local JSON in the AnyAuth data directory.
- Sessions, codes, and tokens are in-memory.
- When configured, the login screen requires a local PIN before creating the
  provider session.

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
- Access tokens must be presented as Bearer tokens for UserInfo.
- PINs are stored as salted PBKDF2-SHA256 verifiers, not plaintext.
- PIN verification is optional and can be disabled with `user clear-pin`.

## Known Gaps

- No CSRF hardening beyond OAuth `state`.
- No session persistence or secure local key management.
- No refresh-token rotation.
- No key rotation.
- No phishing-resistant local user verification.
- No conformance test suite.
- Client secrets are stored in local plaintext JSON.
- Protected upstream apps can still be reached directly if they listen on an
  accessible port; the proxy only protects traffic that enters through AnyAuth.
- Protected upstream apps must treat `X-AnyAuth-*` headers as trusted only when
  the request comes from the AnyAuth proxy.
- The protected proxy reserves `__anyauth/*` paths for its own login, callback,
  and logout routes.
- A local PIN is weaker than passkeys or OS-backed biometric verification.
- ID token claim validation handles only the simple v0 shape, not all OIDC edge
  cases such as array audiences, `azp`, or clock skew policy.

## Intended Next Security Milestones

1. Add passkey or OS credential prompt verification.
2. Replace local plaintext secrets and in-memory state with an encrypted store.
3. Add structured protocol tests and negative cases.
4. Add refresh token rotation.
5. Evaluate replacing the prototype core with a mature OIDC library.
