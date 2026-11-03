package sso

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthorize(t *testing.T) {
	allowed := func() *Identity {
		return &Identity{Subject: "s1", Email: "alex@example.com", EmailVerified: true, Roles: []string{"app-admin"}}
	}
	cfg := Policy{RequiredRole: "app-admin", AllowedSubjects: []string{"s1"}}

	t.Run("given role and allowed subject then nil", func(t *testing.T) {
		require.NoError(t, authorize(cfg, allowed()))
	})

	t.Run("given missing role then ErrForbidden", func(t *testing.T) {
		identity := allowed()
		identity.Roles = nil
		require.ErrorIs(t, authorize(cfg, identity), ErrForbidden)
	})

	t.Run("given unverified e-mail then ErrForbidden", func(t *testing.T) {
		identity := allowed()
		identity.EmailVerified = false
		require.ErrorIs(t, authorize(cfg, identity), ErrForbidden)
	})

	t.Run("given subject outside the list then ErrForbidden", func(t *testing.T) {
		identity := allowed()
		identity.Subject = "s2"
		require.ErrorIs(t, authorize(cfg, identity), ErrForbidden)
	})

	t.Run("given no subject list then role is enough", func(t *testing.T) {
		identity := allowed()
		identity.Subject = "s2"
		require.NoError(t, authorize(Policy{RequiredRole: "app-admin"}, identity))
	})
}

func TestToIdentity(t *testing.T) {
	t.Run("given no name then falls back to username", func(t *testing.T) {
		claims := idTokenClaims{Username: "alex"}
		require.Equal(t, "alex", claims.toIdentity("s1").Name)
	})
}

func TestHasRole(t *testing.T) {
	t.Run("must report the presence of a realm role", func(t *testing.T) {
		identity := &Identity{Roles: []string{"a", "b"}}
		require.True(t, identity.HasRole("b"))
		require.False(t, identity.HasRole("c"))
	})
}
