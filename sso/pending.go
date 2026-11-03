package sso

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/oauth2"
)

// ErrInvalidPending is returned when a pending login value cannot be decoded.
var ErrInvalidPending = errors.New("sso: invalid pending login")

// Pending carries the per-login secrets that must survive the round trip
// to the identity provider: the CSRF state, the ID token nonce and the PKCE
// code verifier.
type Pending struct {
	State    string
	Nonce    string
	Verifier string
}

// NewPending generates fresh random values for a login attempt.
func NewPending() (Pending, error) {
	state, err := randomValue()
	if err != nil {
		return Pending{}, err
	}
	nonce, err := randomValue()
	if err != nil {
		return Pending{}, err
	}
	return Pending{State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier()}, nil
}

// Encode serializes the pending login for an HTTP-only cookie.
func (p Pending) Encode() string {
	return strings.Join([]string{p.State, p.Nonce, p.Verifier}, ".")
}

// DecodePending parses a value produced by Pending.Encode.
func DecodePending(value string) (Pending, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Pending{}, ErrInvalidPending
	}
	return Pending{State: parts[0], Nonce: parts[1], Verifier: parts[2]}, nil
}

func randomValue() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
