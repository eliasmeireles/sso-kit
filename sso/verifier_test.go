package sso

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestVerifier(t *testing.T, fp *fakeProvider, policy Policy) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(VerifierConfig{Issuer: fp.server.URL, ClientIDs: []string{"bff", testClientID}, Policy: policy})
	require.NoError(t, err)
	return verifier
}

func TestNewVerifier(t *testing.T) {
	t.Run("given no client ids then ErrVerifierNotConfigured", func(t *testing.T) {
		_, err := NewVerifier(VerifierConfig{Issuer: "https://sso.example.com"})
		require.ErrorIs(t, err, ErrVerifierNotConfigured)
	})
}

func TestVerify(t *testing.T) {
	t.Run("given token for an accepted audience then identity", func(t *testing.T) {
		fp := newFakeProvider(t)
		raw := fp.rawIDToken(t, "bff", time.Minute)

		identity, err := newTestVerifier(t, fp, Policy{RequiredRole: "app-admin"}).Verify(context.Background(), raw)
		require.NoError(t, err)
		assert.Equal(t, testSubject, identity.Subject)
		assert.True(t, identity.HasRole("app-admin"))
	})

	t.Run("given token for another audience then ErrInvalidToken", func(t *testing.T) {
		fp := newFakeProvider(t)
		raw := fp.rawIDToken(t, "someone-else", time.Minute)

		_, err := newTestVerifier(t, fp, Policy{}).Verify(context.Background(), raw)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("given expired token then ErrInvalidToken", func(t *testing.T) {
		fp := newFakeProvider(t)
		raw := fp.rawIDToken(t, "bff", -time.Minute)

		_, err := newTestVerifier(t, fp, Policy{}).Verify(context.Background(), raw)
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("given tampered token then ErrInvalidToken", func(t *testing.T) {
		fp := newFakeProvider(t)
		raw := fp.rawIDToken(t, "bff", time.Minute)

		_, err := newTestVerifier(t, fp, Policy{}).Verify(context.Background(), raw[:len(raw)-4]+"AAAA")
		require.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("given token without the required role then ErrForbidden", func(t *testing.T) {
		fp := newFakeProvider(t)
		fp.roles = []string{"other"}
		raw := fp.rawIDToken(t, "bff", time.Minute)

		_, err := newTestVerifier(t, fp, Policy{RequiredRole: "app-admin"}).Verify(context.Background(), raw)
		require.ErrorIs(t, err, ErrForbidden)
	})

	t.Run("given provider down then ErrUnavailable", func(t *testing.T) {
		fp := newFakeProvider(t)
		fp.down.Store(true)

		_, err := newTestVerifier(t, fp, Policy{}).Verify(context.Background(), "x.y.z")
		require.ErrorIs(t, err, ErrUnavailable)
	})
}
