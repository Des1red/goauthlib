# goauth Architecture

This document describes the internal architecture of **goauth v1**.

## High-level overview

goauth is structured as a **facade package** with isolated internal components.

goauth/ → Public API (what users import)

internal/

├─ auth/ → Authentication & authorization middleware

├─ tokens/ → JWT creation, validation, rotation, persistence

├─ csrf/ → CSRF token generation and enforcement

├─ uuid/ → UUID generation

└─ ratelimit/ → (reserved for future use)


Only the `goauth` package is intended for direct use.
All logic lives behind stable public helpers.

---

## Design goals

- Stateless authentication (JWT-based)
- Stateful revocation (store-backed JTI validation)
- Anonymous-first flow
- Explicit CSRF enforcement
- No framework assumptions
- No redirects inside authorization logic
- Safe for APIs and browsers

---

## Token model

### Access token
- Short-lived
- Stored in `auth_token` cookie
- Contains:
  - UUID (session identifier)
  - Role
  - JTI
  - Expiration
  - UserID

### Refresh token
- Long-lived
- One-time use
- Stored in `refresh_token` cookie
- Linked to access token via `AccessJTI`
- Always validated against the store

### Anonymous token
- Issued automatically if no auth cookie exists
- Role = `anonymous`
- Never persisted
- Short expiration
- Used to unify middleware behavior

---

## Token persistence

goauth does **not** know about databases.

It relies on a user-provided implementation of:

```go
type TokenStore interface {
    SaveToken(uuid, jti, tokenType string, exp int64) error
    DeleteToken(jti string) error
    TokenExists(jti string) (bool, error)
}
```
#### Supported backends:

- SQLite

- Redis

- PostgreSQL

- In-memory (for testing)

The store is injected once at startup.
### Middleware flow
#### Auth middleware

- Read auth_token

- If missing → issue anonymous token

- Verify JWT signature & expiration

- Attach payload to request context

- Enforce JTI via store (if present)

No redirects. No assumptions.
#### Role middleware

- Reads payload from context
- Verifies role membership
- Returns:
  401 Unauthorized if unauthenticated
  403 Forbidden if role mismatch

#### CSRF middleware

- Enforced only when explicitly wrapped

- Checks:

        Cookie csrf_token

        Header X-CSRF-Token or form field

- Applied only to state-changing methods

### Facade API (goauth)

The goauth package exposes:

- Setup:

        JWTSecret(...)

        UseStore(...)

        Cookies(...)

- Auth helpers:

        Auth

        Protected

        ProtectedCsrfActive

        Admin

        AdminCsrfActive

- Session control:

        Login

        Logout

- Context access:

        FromContext

This allows consumers to use goauth without touching internals.