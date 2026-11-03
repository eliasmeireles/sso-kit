package sso

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

const (
	testClientID     = "app"
	testClientSecret = "secret"
	testRedirectURL  = "https://app.example.com/auth/callback"
	testSubject      = "subject-1"
)

type fakeProvider struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	down        atomic.Bool
	challenge   string
	nonce       string
	audience    string
	roles       []string
	emailVerify bool
	redirect    string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	fp := &fakeProvider{key: key, audience: testClientID, roles: []string{"app-admin"}, emailVerify: true, redirect: testRedirectURL}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", fp.discovery)
	mux.HandleFunc("GET /jwks", fp.jwks)
	mux.HandleFunc("POST /token", fp.token)
	fp.server = httptest.NewServer(mux)
	t.Cleanup(fp.server.Close)
	return fp
}

func (fp *fakeProvider) config() Config {
	return Config{Issuer: fp.server.URL, ClientID: testClientID, ClientSecret: testClientSecret, RedirectURL: testRedirectURL, Policy: Policy{RequiredRole: "app-admin"}}
}

func (fp *fakeProvider) discovery(w http.ResponseWriter, _ *http.Request) {
	if fp.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                fp.server.URL,
		"authorization_endpoint":                fp.server.URL + "/auth",
		"token_endpoint":                        fp.server.URL + "/token",
		"jwks_uri":                              fp.server.URL + "/jwks",
		"end_session_endpoint":                  fp.server.URL + "/logout",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (fp *fakeProvider) jwks(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &fp.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

func (fp *fakeProvider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	validChallenge := base64.RawURLEncoding.EncodeToString(sum[:]) == fp.challenge
	validClient := r.PostForm.Get("client_id") == testClientID || basicAuthMatches(r)
	validRedirect := r.PostForm.Get("redirect_uri") == fp.redirect
	if r.PostForm.Get("code") != "good-code" || !validChallenge || !validClient || !validRedirect {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": fp.idToken()})
}

func basicAuthMatches(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == testClientID && pass == testClientSecret
}

func (fp *fakeProvider) rawIDToken(t *testing.T, audience string, expiresIn time.Duration) string {
	t.Helper()
	fp.audience = audience
	token := fp.idTokenExpiring(expiresIn)
	require.NotEmpty(t, token)
	return token
}

func (fp *fakeProvider) idToken() string {
	return fp.idTokenExpiring(time.Minute)
}

func (fp *fakeProvider) idTokenExpiring(expiresIn time.Duration) string {
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: fp.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	now := time.Now()
	claims := map[string]any{
		"iss": fp.server.URL, "sub": testSubject, "aud": fp.audience, "exp": now.Add(expiresIn).Unix(), "iat": now.Unix(),
		"nonce": fp.nonce, "email": "alex@example.com", "email_verified": fp.emailVerify, "name": "Alex Example",
		"preferred_username": "alex", "realm_access": map[string]any{"roles": fp.roles},
	}
	raw, _ := jwt.Signed(signer).Claims(claims).Serialize()
	return raw
}

func (fp *fakeProvider) expect(p Pending) {
	sum := sha256.Sum256([]byte(p.Verifier))
	fp.challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	fp.nonce = p.Nonce
}
