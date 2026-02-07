### goauth — minimal usage guide
What this library does

#### goauth provides:

- JWT-based authentication

- Anonymous sessions

- Access + refresh tokens (rotation-ready)

- Pluggable token storage (SQLite, Redis, etc.)

- HTTP middleware for Go servers

You do not modify internal code.
You configure once, then call high-level helpers.

#### Installation
```
go get github.com/Des1red/goauthlib
```

Initialization (required)

You must configure JWT secret and token store once at startup.
```go
import (
    "os"
    "github.com/Des1red/goauthlib"
)


func main() {
goauth.JWTSecret([]byte(os.Getenv("JWT_SECRET")))
goauth.UseStore(myTokenStore) // sqlite / redis / etc
}
```
Optional:
```go
goauth.Cookies(goauth.CookieConfig{
    Secure: true,
    SameSite: http.SameSiteStrictMode,
})
```

#### Token store interface

Your database must implement:
```go
type TokenStore interface {
    SaveToken(uuid, jti, tokenType string, exp int64) error
    DeleteToken(jti string) error
    TokenExists(jti string) (bool, error)
}
```

Example (SQLite / Redis / in-memory all work).
The library calls this interface internally via a thin wrapper; your implementation is never accessed directly.
#### Middleware usage
Basic auth (anonymous + logged-in users)
```go
http.HandleFunc("/",
    goauth.Auth(handler),
)
```


Protected route (authenticated, role-based, API-safe)
Note: CSRF is NOT enforced here. Use ProtectedCsrfActive for browser state-changing routes.

```go
http.HandleFunc("/home",
    goauth.Protected(handler),
)
```
Equivalent to:
```go
Auth(
    RequireRole(RoleUser, RoleAdmin)(
        handler,
    ),
)
```

For admin-only routes, use:
```go
http.HandleFunc("/dashboard",
    goauth.Admin(handler),
)
```
#### CSRF protection

goauth automatically **creates CSRF tokens** when a user session is created
(login, refresh).

However, **CSRF protection is enforced only when you opt in**.

Why:
- CSRF applies only to browser-based, cookie-authenticated, state-changing requests
- API clients (mobile, CLI, services) must not be forced to send CSRF tokens

For this reason, goauth provides two variants:

Browser-safe protected route (CSRF enforced)
```go
http.HandleFunc("/profile/update",
    goauth.ProtectedCsrfActive(handler),
)
```

Rule of thumb:
- Use ProtectedCsrfActive for browser POST/PUT/DELETE routes
- Use Protected for APIs and read-only routes

#### Login (issue tokens)

Call this after you validate credentials:
```go
goauth.Login(w, goauth.RoleUser, userID)
```

This will:

- Issue access token

- Issue refresh token

- Store JTIs

- Set cookies

- Create CSRF token

- Must be called only after credentials are verified by your application.

#### Logout
```go
goauth.Logout(w, r)
```

This will:

- Expire cookies

- Revoke refresh + access JTIs

- Block refresh via session_killed

#### Accessing auth info in handlers
```go
payload := goauth.FromContext(r.Context())
if payload == nil {
    // not authenticated
}

fmt.Println(payload.UserID)
fmt.Println(payload.Role)
```

#### Anonymous users

If no auth cookie is present:

- An anonymous JWT is issued automatically

- RoleAnonymous is set

- No database entry is created

#### Notes / guarantees

- JWTs contain no sensitive user data

- Refresh tokens are one-time use

- Token validation always checks the store

- No redirects inside role middleware

- CSRF tokens are issued automatically but enforced only via CsrfActive middleware

- API-safe (JSON errors only)