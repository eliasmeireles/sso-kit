package sso

import (
	"errors"
	"slices"
)

// ErrForbidden is returned when a valid identity lacks the required role,
// is not an allowed subject, or has no verified e-mail.
var ErrForbidden = errors.New("sso: identity is not allowed to access this application")

// Identity is the authenticated person extracted from a verified ID token.
type Identity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Username      string
	Roles         []string
}

// idTokenClaims mirrors the Keycloak ID token claims this package reads.
type idTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Username      string `json:"preferred_username"`
	RealmAccess   struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// toIdentity converts the parsed claims into an Identity for subject.
func (c idTokenClaims) toIdentity(subject string) *Identity {
	name := c.Name
	if name == "" {
		name = c.Username
	}
	return &Identity{
		Subject:       subject,
		Email:         c.Email,
		EmailVerified: c.EmailVerified,
		Name:          name,
		Username:      c.Username,
		Roles:         c.RealmAccess.Roles,
	}
}

// HasRole reports whether the identity carries the realm role.
func (i *Identity) HasRole(role string) bool {
	return slices.Contains(i.Roles, role)
}

// authorize applies the access policy to identity.
func authorize(cfg Policy, identity *Identity) error {
	if identity.Subject == "" || identity.Email == "" || !identity.EmailVerified {
		return ErrForbidden
	}
	if cfg.RequiredRole != "" && !slices.Contains(identity.Roles, cfg.RequiredRole) {
		return ErrForbidden
	}
	if len(cfg.AllowedSubjects) > 0 && !slices.Contains(cfg.AllowedSubjects, identity.Subject) {
		return ErrForbidden
	}
	return nil
}
