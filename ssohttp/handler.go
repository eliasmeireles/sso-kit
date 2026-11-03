// Package ssohttp provides net/http handlers for the SSO login, callback
// and logout. The application keeps full control of its own session through
// the Sessions interface; the handlers only run the OIDC round trip.
//
// Typical wiring:
//
//	client, err := sso.New(cfg)          // nil client => login reports "unavailable"
//	h := ssohttp.New(ssohttp.Options{Flow: client, Sessions: mySessions, Secure: true,
//		PostLogoutURL: "https://app.example.com/login"})
//	mux.HandleFunc("GET /auth/login", h.Login)
//	mux.HandleFunc("GET /auth/callback", h.Callback)
//	mux.HandleFunc("POST /api/auth/logout", h.Logout)
package ssohttp

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/eliasmeireles/sso-kit/sso"
)

// Error codes appended as ?error=<code> to the login page.
const (
	ErrorUnavailable = "unavailable"
	ErrorDenied      = "denied"
	ErrorExpired     = "expired"
	ErrorForbidden   = "forbidden"
	ErrorFailed      = "failed"
)

const (
	defaultPendingCookie = "sso_pending"
	defaultPendingPath   = "/"
	defaultLoginPage     = "/login"
	defaultAfterLogin    = "/"
	pendingMaxAge        = 600
)

// Flow is the OIDC client contract; *sso.Client implements it.
type Flow interface {
	AuthURL(ctx context.Context, p sso.Pending) (string, error)
	Complete(ctx context.Context, code string, p sso.Pending, opts ...sso.CompleteOption) (*sso.Identity, error)
	LogoutURL(ctx context.Context, postLogoutRedirect string) string
}

// Sessions opens and closes the application session.
type Sessions interface {
	// Start opens the session of an authenticated and authorized identity,
	// writing the application cookie on w.
	Start(w http.ResponseWriter, r *http.Request, identity *sso.Identity) error
	// End closes the current session and clears the application cookie.
	End(w http.ResponseWriter, r *http.Request) error
}

// Options configures the handlers. Zero values fall back to defaults.
type Options struct {
	// Flow may be nil when SSO is not configured: login then redirects to
	// the login page with ErrorUnavailable instead of failing hard.
	Flow     Flow
	Sessions Sessions
	// Secure sets the Secure flag on the pending-login cookie (production).
	Secure bool
	// PendingCookie and PendingPath name and scope the short-lived cookie
	// holding state, nonce and PKCE verifier (default "sso_pending", "/").
	PendingCookie string
	PendingPath   string
	// LoginPage receives ?error=<code> on failures (default "/login").
	LoginPage string
	// AfterLogin is the landing page after a successful login (default "/").
	AfterLogin string
	// PostLogoutURL is the absolute URL registered as post-logout redirect.
	PostLogoutURL string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Handler serves the SSO endpoints.
type Handler struct {
	opts Options
}

// New builds the handlers, applying defaults.
func New(opts Options) *Handler {
	opts.PendingCookie = orDefault(opts.PendingCookie, defaultPendingCookie)
	opts.PendingPath = orDefault(opts.PendingPath, defaultPendingPath)
	opts.LoginPage = orDefault(opts.LoginPage, defaultLoginPage)
	opts.AfterLogin = orDefault(opts.AfterLogin, defaultAfterLogin)
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &Handler{opts: opts}
}

// Login starts the Authorization Code + PKCE flow.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if h.opts.Flow == nil {
		h.fail(w, r, ErrorUnavailable)
		return
	}
	pending, err := sso.NewPending()
	if err != nil {
		h.fail(w, r, ErrorFailed)
		return
	}
	target, err := h.opts.Flow.AuthURL(r.Context(), pending)
	if err != nil {
		h.opts.Logger.Error("sso login unavailable", "error", err)
		h.fail(w, r, ErrorUnavailable)
		return
	}
	h.setPending(w, pending.Encode(), pendingMaxAge)
	http.Redirect(w, r, target, http.StatusFound)
}

// Callback validates the state, completes the exchange and starts the
// application session.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	pending, pendingErr := h.readPending(r)
	h.setPending(w, "", -1)
	query := r.URL.Query()
	switch {
	case h.opts.Flow == nil:
		h.fail(w, r, ErrorUnavailable)
		return
	case query.Get("error") != "":
		h.opts.Logger.Warn("sso callback error", "error", query.Get("error"))
		h.fail(w, r, ErrorDenied)
		return
	case pendingErr != nil || subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(pending.State)) != 1:
		h.opts.Logger.Warn("sso callback refused", "reason", "missing or mismatched state")
		h.fail(w, r, ErrorExpired)
		return
	}
	identity, err := h.opts.Flow.Complete(r.Context(), query.Get("code"), pending)
	if errors.Is(err, sso.ErrForbidden) {
		h.opts.Logger.Warn("sso access denied", "subject", subjectOf(identity))
		h.fail(w, r, ErrorForbidden)
		return
	}
	if err != nil {
		h.opts.Logger.Error("sso callback failed", "error", err)
		h.fail(w, r, ErrorFailed)
		return
	}
	if err := h.opts.Sessions.Start(w, r, identity); err != nil {
		h.opts.Logger.Error("opening session failed", "subject", identity.Subject, "error", err)
		h.fail(w, r, ErrorFailed)
		return
	}
	h.opts.Logger.Info("sso login succeeded", "subject", identity.Subject, "email", identity.Email)
	http.Redirect(w, r, h.opts.AfterLogin, http.StatusFound)
}

// Logout ends the application session and answers JSON with the URL that
// also ends the SSO session: {"logoutUrl": "..."}. Meant for fetch/XHR.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	target := h.endSession(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"logoutUrl":` + quoteJSON(target) + `}`))
}

// LogoutRedirect ends the application session and redirects the browser to
// the SSO logout. Meant for plain links or forms.
func (h *Handler) LogoutRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, h.endSession(w, r), http.StatusFound)
}

func (h *Handler) endSession(w http.ResponseWriter, r *http.Request) string {
	if err := h.opts.Sessions.End(w, r); err != nil {
		h.opts.Logger.Warn("closing session failed", "error", err)
	}
	if h.opts.Flow == nil {
		return h.opts.PostLogoutURL
	}
	return h.opts.Flow.LogoutURL(r.Context(), h.opts.PostLogoutURL)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, h.opts.LoginPage+"?error="+url.QueryEscape(code), http.StatusFound)
}

func (h *Handler) setPending(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.opts.PendingCookie,
		Value:    value,
		Path:     h.opts.PendingPath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) readPending(r *http.Request) (sso.Pending, error) {
	cookie, err := r.Cookie(h.opts.PendingCookie)
	if err != nil {
		return sso.Pending{}, err
	}
	return sso.DecodePending(cookie.Value)
}

func subjectOf(identity *sso.Identity) string {
	if identity == nil {
		return ""
	}
	return identity.Subject
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
