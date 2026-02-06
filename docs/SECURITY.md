# goauth Security Model

This document explains the security guarantees and threat model of **goauth v1**.

---

## Core principles

- JWTs are **identity assertions**, not session storage
- All sensitive state lives in the token store
- Cookies are assumed to be HTTP-only
- No implicit trust of client input

---

## JWT security

- Signed using HMAC (HS256)
- Secret must be provided at startup
- JWT payload contains:
  - No passwords
  - No emails
  - No PII beyond user ID and role
- Tokens are rejected if:
  - Signature is invalid
  - Expired
  - Token type mismatch

---

## Refresh token rotation

Refresh tokens are **single-use**.

On refresh:
1. Refresh JTI is deleted
2. Linked access JTI is revoked
3. New refresh + access JTIs are issued
4. Old tokens become invalid immediately

This protects against:
- Replay attacks
- Token theft
- Parallel refresh attempts

---

## JTI enforcement

All non-anonymous tokens must pass:

```go
TokenExists(jti)
```

This ensures:

- Logout invalidates sessions immediately

- Stolen tokens cannot be reused

- Token revocation is centralized

- CSRF protection

- CSRF tokens are:

- Automatically created on login and refresh

- Stored in a readable cookie

- Enforcement is explicit, not implicit.

Why:

- APIs must not require CSRF

- Browsers must

- Consumers choose:

- Protected → no CSRF

- ProtectedCsrfActive → CSRF enforced

- This prevents:

- CSRF on browser forms

- False positives on API clients

- Anonymous sessions

Anonymous users:

- Receive a valid JWT

- Have RoleAnonymous

- Cannot refresh tokens

- Cannot access protected routes

Benefits:

- Unified middleware logic

- No special-case handling

- Safe default behavior

- Session termination

Logout performs:

- Cookie expiration

- Refresh + access JTI revocation

- session_killed cookie set

This prevents:

- Refresh after logout

- Session resurrection

- Error handling

- No redirects in authorization logic

- API-safe JSON responses

- No information leaks

- Same error for invalid / expired tokens

What goauth does NOT do

- Password hashing

- User storage

- Account lockouts

- Rate limiting (planned)

- OAuth / SSO (future)

These are intentionally left to the host application.

Security guarantees (v1)

- Replay-safe refresh tokens

- Immediate session revocation

- CSRF-safe browser flows

- Stateless access tokens

- Explicit trust boundaries