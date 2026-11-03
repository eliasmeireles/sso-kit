# sso-kit

Small, reusable building blocks to put applications behind an OpenID Connect
provider (built and tested against Keycloak) using the **Authorization Code
flow with PKCE (S256)**, without rewriting the same login code in every app.

| Package | Use it when |
|---|---|
| [`sso`](./sso) (Go) | You need the OIDC client: start the login, complete the callback, verify ID tokens and apply an access policy (realm role and/or allowed subjects). |
| [`@eliasmeireles/sso-kit`](./js) (TypeScript) | Your Next.js BFF completes confidential login, or your browser/extension starts a public PKCE flow for a Go backend to complete. |
| [`ssohttp`](./ssohttp) (Go) | Your Go server owns the login: ready `net/http` handlers for login, callback and logout; you only plug your session. |

## Security model

- Authorization Code + PKCE S256 on every login; `state` and `nonce` are
  random per attempt and kept in an HTTP-only, `SameSite=Lax`, short-lived
  cookie (stateless, so it works with several replicas).
- The ID token is verified (signature via JWKS, issuer, audience, expiry and
  nonce) before any claim is trusted.
- `Policy` enforces a realm role (`realm_access.roles`) and, optionally, an
  allow list of subjects (`sub`). Identities without a verified e-mail are
  refused. Keep the same rule in the identity provider (e.g. Keycloak
  authentication flow per client) for defense in depth.
- Discovery is lazy and retried: an application starts even when the
  identity provider is down; only new logins fail until it is back.
- Tokens from the provider are never stored by the library; your
  application opens its own session after a successful callback.

## Go

```sh
go get github.com/eliasmeireles/sso-kit@latest
```

```go
client, err := sso.New(sso.Config{
	Issuer:       "https://sso.example.com/realms/main",
	ClientID:     "my-app",
	ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
	RedirectURL:  "https://app.example.com/auth/callback",
	Policy:       sso.Policy{RequiredRole: "my-app-users"},
})
if err != nil {
	slog.Error("sso disabled", "error", err) // keep serving; login reports "unavailable"
}

h := ssohttp.New(ssohttp.Options{
	Flow:          client,     // may be nil
	Sessions:      sessions,   // your ssohttp.Sessions implementation
	Secure:        true,
	PostLogoutURL: "https://app.example.com/login",
})
mux.HandleFunc("GET /auth/login", h.Login)
mux.HandleFunc("GET /auth/callback", h.Callback)
mux.HandleFunc("POST /api/auth/logout", h.Logout) // JSON {"logoutUrl": "..."}
```

Failures redirect to `/login?error=<code>` with `unavailable`, `denied`,
`expired`, `forbidden` or `failed`.

### Public clients handing the code to a backend

Browser extensions and mobile apps can run the login as a public client and
send `code`, `code_verifier`, `nonce` and their `redirect_uri` to the
backend, which completes the exchange itself:

```go
client, _ := sso.New(sso.Config{Issuer: issuer, ClientID: "my-public-app", Public: true,
	RedirectURL: "https://app.example.com/callback", Policy: policy})
identity, err := client.Complete(ctx, code, sso.Pending{Nonce: nonce, Verifier: verifier},
	sso.WithRedirectURL(redirectURI))
```

### Verifying an ID token received from a trusted component

```go
verifier, _ := sso.NewVerifier(sso.VerifierConfig{Issuer: issuer, ClientIDs: []string{"my-bff"}, Policy: policy})
identity, err := verifier.Verify(ctx, rawIDToken)
```

## Keycloak client checklist

- Standard flow only (no direct access grants, no implicit flow).
- `pkce.code.challenge.method = S256`.
- Exact redirect URIs (no wildcards) and exact post-logout redirect URIs.
- Realm roles in the ID token (`roles` client scope → "realm roles" mapper
  with *Add to ID token* on).

## Development

```sh
go test -race ./...
```
