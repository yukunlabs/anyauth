# Security Boundaries

This repository currently contains a local development prototype. It should not
be treated as production identity infrastructure.

## Current Assumptions

- The provider binds to `127.0.0.1`.
- The only user is the local operator.
- Client registry is static and in-memory.
- Sessions, codes, and tokens are in-memory.
- The login screen has no real password or biometric verification yet.

## Current Protections

- Authorization Code flow uses PKCE.
- Redirect URIs are matched exactly.
- Authorization codes are one-time use.
- ID tokens are signed with RS256.
- Demo clients verify RS256 ID token signatures.
- Demo clients validate issuer, audience, expiration, and nonce.
- Access tokens must be presented as Bearer tokens for UserInfo.

## Known Gaps

- No CSRF hardening beyond OAuth `state`.
- No session persistence or secure local key management.
- No refresh-token rotation.
- No key rotation.
- No phishing-resistant local user verification.
- No conformance test suite.
- Demo claim validation handles only the simple v0 shape, not all OIDC edge
  cases such as array audiences, `azp`, or clock skew policy.

## Intended Next Security Milestones

1. Add real local user verification with passkey or OS credential prompt.
2. Replace in-memory state with a local encrypted store.
3. Add structured protocol tests and negative cases.
4. Add refresh token rotation.
5. Evaluate replacing the prototype core with a mature OIDC library.
