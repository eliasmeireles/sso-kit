package sso

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrUnavailable is returned when the identity provider cannot be reached.
	ErrUnavailable = errors.New("sso: identity provider unavailable")
	// ErrInvalidToken is returned when the code exchange or ID token is invalid.
	ErrInvalidToken = errors.New("sso: invalid token response")
)

const httpTimeout = 10 * time.Second

// Client runs the Authorization Code + PKCE flow. Provider discovery is
// lazy and retried on failure, so applications start even while the
// identity provider is down; only logins fail until it is back.
//
// Typical use:
//
//	client, _ := sso.New(sso.Config{Issuer: issuer, ClientID: "app", ClientSecret: secret,
//		RedirectURL: "https://app.example.com/auth/callback", Policy: sso.Policy{RequiredRole: "app-users"}})
//	pending, _ := sso.NewPending()
//	target, _ := client.AuthURL(ctx, pending)             // redirect the browser here
//	identity, err := client.Complete(ctx, code, pending)  // in the callback
type Client struct {
	cfg        Config
	httpClient *http.Client
	disc       discovery
}

// CompleteOption customizes a single Complete call.
type CompleteOption func(*completeOptions)

type completeOptions struct {
	redirectURL string
}

// WithRedirectURL overrides the redirect URL sent in the code exchange. It
// must equal the one used to start the login (e.g. a browser extension or
// mobile app callback registered for the same public client).
func WithRedirectURL(redirectURL string) CompleteOption {
	return func(o *completeOptions) { o.redirectURL = redirectURL }
}

// New builds a client for cfg.
func New(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	httpClient := &http.Client{Timeout: httpTimeout}
	return &Client{cfg: cfg, httpClient: httpClient, disc: discovery{issuer: cfg.Issuer, httpClient: httpClient}}, nil
}

// AuthURL returns the identity provider URL that starts the login for p.
func (c *Client) AuthURL(_ context.Context, p Pending) (string, error) {
	oauth, _, err := c.oauthConfig()
	if err != nil {
		return "", err
	}
	return oauth.AuthCodeURL(p.State, oidc.Nonce(p.Nonce), oauth2.S256ChallengeOption(p.Verifier)), nil
}

// Complete exchanges the authorization code, verifies the ID token
// (signature, issuer, audience, expiry and nonce) and applies the policy.
// It returns ErrForbidden, together with the identity, for valid identities
// without access.
func (c *Client) Complete(ctx context.Context, code string, p Pending, opts ...CompleteOption) (*Identity, error) {
	oauth, prov, err := c.oauthConfig()
	if err != nil {
		return nil, err
	}
	var options completeOptions
	for _, opt := range opts {
		opt(&options)
	}
	if options.redirectURL != "" {
		oauth.RedirectURL = options.redirectURL
	}
	ctx = oidc.ClientContext(ctx, c.httpClient)
	token, err := oauth.Exchange(ctx, code, oauth2.VerifierOption(p.Verifier))
	if err != nil {
		return nil, fmt.Errorf("%w: exchanging code: %v", ErrInvalidToken, err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("%w: missing id_token", ErrInvalidToken)
	}
	idToken, err := prov.verifier(c.cfg.ClientID).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: verifying id_token: %v", ErrInvalidToken, err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(p.Nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidToken)
	}
	return identityFrom(idToken, c.cfg.Policy)
}

// LogoutURL returns the provider end-session URL that ends the SSO session
// and returns to postLogoutRedirect, or postLogoutRedirect itself when the
// provider is unreachable or exposes no end-session endpoint.
func (c *Client) LogoutURL(_ context.Context, postLogoutRedirect string) string {
	prov, err := c.disc.get()
	if err != nil || prov.endSession == "" {
		return postLogoutRedirect
	}
	query := url.Values{"client_id": {c.cfg.ClientID}, "post_logout_redirect_uri": {postLogoutRedirect}}
	return prov.endSession + "?" + query.Encode()
}

func (c *Client) oauthConfig() (oauth2.Config, *provider, error) {
	prov, err := c.disc.get()
	if err != nil {
		return oauth2.Config{}, nil, err
	}
	endpoint := prov.oidc.Endpoint()
	if c.cfg.Public {
		endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	return oauth2.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  c.cfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}, prov, nil
}

// identityFrom parses the claims of a verified token and applies policy.
func identityFrom(idToken *oidc.IDToken, policy Policy) (*Identity, error) {
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: parsing claims: %v", ErrInvalidToken, err)
	}
	identity := claims.toIdentity(idToken.Subject)
	if err := authorize(policy, identity); err != nil {
		return identity, err
	}
	return identity, nil
}

// discovery performs provider discovery once it succeeds and caches it.
type discovery struct {
	issuer     string
	httpClient *http.Client

	mu   sync.Mutex
	prov *provider
}

type provider struct {
	oidc       *oidc.Provider
	endSession string
}

func (p *provider) verifier(clientID string) *oidc.IDTokenVerifier {
	return p.oidc.Verifier(&oidc.Config{ClientID: clientID})
}

// get returns the cached provider or runs discovery. The background context
// is deliberate: go-oidc keeps it for later signing key fetches.
func (d *discovery) get() (*provider, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.prov != nil {
		return d.prov, nil
	}
	ctx := oidc.ClientContext(context.Background(), d.httpClient)
	discovered, err := oidc.NewProvider(ctx, d.issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var metadata struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = discovered.Claims(&metadata)
	d.prov = &provider{oidc: discovered, endSession: metadata.EndSession}
	return d.prov, nil
}
