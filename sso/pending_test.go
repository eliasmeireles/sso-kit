package sso

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPending(t *testing.T) {
	t.Run("must generate distinct random values", func(t *testing.T) {
		first, err := NewPending()
		require.NoError(t, err)
		second, err := NewPending()
		require.NoError(t, err)
		assert.NotEqual(t, first.State, second.State)
		assert.NotEqual(t, first.Nonce, second.Nonce)
		assert.NotEqual(t, first.Verifier, second.Verifier)
	})

	t.Run("must round trip through Encode and DecodePending", func(t *testing.T) {
		p, err := NewPending()
		require.NoError(t, err)
		decoded, err := DecodePending(p.Encode())
		require.NoError(t, err)
		assert.Equal(t, p, decoded)
	})

	t.Run("given malformed value then ErrInvalidPending", func(t *testing.T) {
		for _, value := range []string{"", "a.b", "a..c", "a.b.c.d"} {
			_, err := DecodePending(value)
			require.ErrorIs(t, err, ErrInvalidPending, value)
		}
	})
}
