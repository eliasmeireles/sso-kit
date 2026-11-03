package sso

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	client, err := New(cfg)
	require.NoError(t, err)
	return client
}

func newPending(t *testing.T) Pending {
	t.Helper()
	p, err := NewPending()
	require.NoError(t, err)
	return p
}

func TestNew(t *testing.T) {
	t.Run("given incomplete config then ErrNotConfigured", func(t *testing.T) {
		_, err := New(Config{Issuer: "https://sso.example.com"})
		require.ErrorIs(t, err, ErrNotConfigured)
	})

	t.Run("given confidential client without secret then ErrNotConfigured", func(t *testing.T) {
		_, err := New(Config{Issuer: "https://sso.example.com", ClientID: "app", RedirectURL: testRedirectURL})
		require.ErrorIs(t, err, ErrNotConfigured)
	})

	t.Run("given public client without secret then valid", func(t *testing.T) {
		_, err := New(Config{Issuer: "https://sso.example.com", ClientID: "app", RedirectURL: testRedirectURL, Public: true})
		require.NoError(t, err)
	})
}

func TestAuthURL(t *testing.T) {
	t.Run("must carry state, nonce and S256 challenge", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)

		raw, err := newTestClient(t, fp.config()).AuthURL(context.Background(), p)
		require.NoError(t, err)

		parsed, err := url.Parse(raw)
		require.NoError(t, err)
		query := parsed.Query()
		assert.Equal(t, fp.server.URL+"/auth", parsed.Scheme+"://"+parsed.Host+parsed.Path)
		assert.Equal(t, p.State, query.Get("state"))
		assert.Equal(t, p.Nonce, query.Get("nonce"))
		assert.Equal(t, "S256", query.Get("code_challenge_method"))
		assert.NotEmpty(t, query.Get("code_challenge"))
		assert.Equal(t, testClientID, query.Get("client_id"))
		assert.Equal(t, testRedirectURL, query.Get("redirect_uri"))
		assert.Contains(t, query.Get("scope"), "openid")
	})

	t.Run("given provider down then ErrUnavailable and retries later", func(t *testing.T) {
		fp := newFakeProvider(t)
		fp.down.Store(true)
		client := newTestClient(t, fp.config())

		_, err := client.AuthURL(context.Background(), newPending(t))
		require.ErrorIs(t, err, ErrUnavailable)

		fp.down.Store(false)
		_, err = client.AuthURL(context.Background(), newPending(t))
		require.NoError(t, err)
	})
}

func TestComplete(t *testing.T) {
	t.Run("given valid code then identity with roles", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)

		identity, err := newTestClient(t, fp.config()).Complete(context.Background(), "good-code", p)
		require.NoError(t, err)
		assert.Equal(t, testSubject, identity.Subject)
		assert.Equal(t, "alex@example.com", identity.Email)
		assert.Equal(t, "Alex Example", identity.Name)
		assert.Equal(t, []string{"app-admin"}, identity.Roles)
	})

	t.Run("given public client then exchanges without secret", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		cfg := fp.config()
		cfg.ClientSecret, cfg.Public = "", true

		identity, err := newTestClient(t, cfg).Complete(context.Background(), "good-code", p)
		require.NoError(t, err)
		assert.Equal(t, testSubject, identity.Subject)
	})

	t.Run("given redirect override then sends it in the exchange", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		fp.redirect = "https://extension.example.com/"

		_, err := newTestClient(t, fp.config()).Complete(context.Background(), "good-code", p, WithRedirectURL("https://extension.example.com/"))
		require.NoError(t, err)
	})

	t.Run("given redirect different from the login one then ErrInvalidToken", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		fp.redirect = "https://extension.example.com/"

		_, err := newTestClient(t, fp.config()).Complete(context.Background(), "good-code", p)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("given wrong code verifier then ErrInvalidToken", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		p.Verifier = newPending(t).Verifier

		_, err := newTestClient(t, fp.config()).Complete(context.Background(), "good-code", p)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("given nonce mismatch then ErrInvalidToken", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		fp.nonce = "other"

		_, err := newTestClient(t, fp.config()).Complete(context.Background(), "good-code", p)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("given token for another audience then ErrInvalidToken", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		fp.audience = "other-client"

		_, err := newTestClient(t, fp.config()).Complete(context.Background(), "good-code", p)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("given identity without the required role then ErrForbidden with the identity", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		fp.roles = []string{"other-role"}

		identity, err := newTestClient(t, fp.config()).Complete(context.Background(), "good-code", p)
		require.ErrorIs(t, err, ErrForbidden)
		assert.Equal(t, testSubject, identity.Subject)
	})

	t.Run("given subject outside the allow list then ErrForbidden", func(t *testing.T) {
		fp := newFakeProvider(t)
		p := newPending(t)
		fp.expect(p)
		cfg := fp.config()
		cfg.AllowedSubjects = []string{"someone-else"}

		_, err := newTestClient(t, cfg).Complete(context.Background(), "good-code", p)
		require.ErrorIs(t, err, ErrForbidden)
	})
}

func TestLogoutURL(t *testing.T) {
	t.Run("must point to the end session endpoint with client id", func(t *testing.T) {
		fp := newFakeProvider(t)

		raw := newTestClient(t, fp.config()).LogoutURL(context.Background(), "https://app.example.com/login")

		parsed, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Equal(t, "/logout", parsed.Path)
		assert.Equal(t, testClientID, parsed.Query().Get("client_id"))
		assert.Equal(t, "https://app.example.com/login", parsed.Query().Get("post_logout_redirect_uri"))
	})

	t.Run("given provider down then falls back to the local page", func(t *testing.T) {
		fp := newFakeProvider(t)
		fp.down.Store(true)

		raw := newTestClient(t, fp.config()).LogoutURL(context.Background(), "https://app.example.com/login")
		assert.Equal(t, "https://app.example.com/login", raw)
	})
}
