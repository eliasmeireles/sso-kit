// Package sso implements the OpenID Connect Authorization Code flow with
// PKCE against the central Keycloak realm and the verification of raw ID
// tokens, authorizing people by realm role and, optionally, by an explicit
// list of allowed subjects.
package sso

import "errors"

// ErrNotConfigured is returned when mandatory OIDC settings are missing.
var ErrNotConfigured = errors.New("sso: issuer, client id, redirect url and (for confidential clients) client secret are required")

// Policy restricts which authenticated identities may access an application.
type Policy struct {
	// RequiredRole, when set, must appear in the realm_access.roles claim.
	RequiredRole string
	// AllowedSubjects, when not empty, restricts access to these `sub` values.
	AllowedSubjects []string
}

// Config holds the OIDC client settings.
type Config struct {
	// Issuer is the realm URL, e.g. https://sso.example.com/realms/main.
	Issuer string
	// ClientID identifies the client registered in the realm.
	ClientID string
	// ClientSecret authenticates a confidential client; empty when Public.
	ClientSecret string
	// Public marks a client without secret (browser, extension or mobile app
	// handing the code to a backend); PKCE protects the exchange.
	Public bool
	// RedirectURL is the default registered callback URL.
	RedirectURL string
	// Policy is applied to every authenticated identity.
	Policy
}

// Validate reports whether the mandatory settings are present.
func (c Config) Validate() error {
	if c.Issuer == "" || c.ClientID == "" || c.RedirectURL == "" || (!c.Public && c.ClientSecret == "") {
		return ErrNotConfigured
	}
	return nil
}
