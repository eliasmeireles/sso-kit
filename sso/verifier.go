package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrVerifierNotConfigured is returned when the verifier settings are incomplete.
var ErrVerifierNotConfigured = errors.New("sso: verifier needs an issuer and at least one client id")

// VerifierConfig holds the settings of a Verifier.
type VerifierConfig struct {
	// Issuer is the realm URL.
	Issuer string
	// ClientIDs lists the accepted audiences (the client the ID token was
	// issued to, e.g. a backend-for-frontend).
	ClientIDs []string
	// Policy is applied to every verified identity.
	Policy
}

// Verifier validates raw ID tokens received from a trusted component that
// already completed the login (for instance a backend-for-frontend calling a
// private API). Nonce checks are the responsibility of the component that
// started the login.
type Verifier struct {
	cfg  VerifierConfig
	disc discovery
}

// NewVerifier builds a verifier for cfg; discovery is lazy.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" || len(cfg.ClientIDs) == 0 {
		return nil, ErrVerifierNotConfigured
	}
	return &Verifier{cfg: cfg, disc: discovery{issuer: cfg.Issuer, httpClient: &http.Client{Timeout: httpTimeout}}}, nil
}

// Verify checks signature, issuer, expiry and audience of rawIDToken and
// applies the policy. It returns ErrForbidden, with the identity, for valid
// tokens without access.
func (v *Verifier) Verify(ctx context.Context, rawIDToken string) (*Identity, error) {
	prov, err := v.disc.get()
	if err != nil {
		return nil, err
	}
	verifier := prov.oidc.Verifier(&oidc.Config{SkipClientIDCheck: true})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !v.acceptsAudience(idToken.Audience) {
		return nil, fmt.Errorf("%w: unexpected audience", ErrInvalidToken)
	}
	return identityFrom(idToken, v.cfg.Policy)
}

func (v *Verifier) acceptsAudience(audience []string) bool {
	for _, aud := range audience {
		if slices.Contains(v.cfg.ClientIDs, aud) {
			return true
		}
	}
	return false
}
