package ssohttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eliasmeireles/sso-kit/sso"
)

type stubFlow struct {
	authURLErr  error
	identity    *sso.Identity
	completeErr error
	gotCode     string
	gotPending  sso.Pending
}

func (s *stubFlow) AuthURL(_ context.Context, p sso.Pending) (string, error) {
	return "https://sso.example.com/auth?state=" + p.State, s.authURLErr
}

func (s *stubFlow) Complete(_ context.Context, code string, p sso.Pending, _ ...sso.CompleteOption) (*sso.Identity, error) {
	s.gotCode, s.gotPending = code, p
	return s.identity, s.completeErr
}

func (s *stubFlow) LogoutURL(_ context.Context, postLogoutRedirect string) string {
	return "https://sso.example.com/logout?post_logout_redirect_uri=" + url.QueryEscape(postLogoutRedirect)
}

type stubSessions struct {
	started  *sso.Identity
	startErr error
	ended    bool
}

func (s *stubSessions) Start(w http.ResponseWriter, _ *http.Request, identity *sso.Identity) error {
	if s.startErr != nil {
		return s.startErr
	}
	s.started = identity
	http.SetCookie(w, &http.Cookie{Name: "app_session", Value: "tok123"})
	return nil
}

func (s *stubSessions) End(_ http.ResponseWriter, _ *http.Request) error {
	s.ended = true
	return nil
}

func newMux(flow Flow, sessions Sessions) *http.ServeMux {
	h := New(Options{Flow: flow, Sessions: sessions, PostLogoutURL: "https://app.example.com/login"})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", h.Login)
	mux.HandleFunc("GET /auth/callback", h.Callback)
	mux.HandleFunc("POST /auth/logout", h.Logout)
	mux.HandleFunc("GET /auth/logout", h.LogoutRedirect)
	return mux
}

func serve(mux http.Handler, method, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, target, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	return recorder
}

func cookieNamed(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func startLogin(t *testing.T, mux http.Handler) (*http.Cookie, string) {
	t.Helper()
	recorder := serve(mux, http.MethodGet, "/auth/login")
	require.Equal(t, http.StatusFound, recorder.Code)
	cookie := cookieNamed(recorder, defaultPendingCookie)
	require.NotNil(t, cookie)
	pending, err := sso.DecodePending(cookie.Value)
	require.NoError(t, err)
	return cookie, pending.State
}

func allowed() *sso.Identity {
	return &sso.Identity{Subject: "s1", Email: "alex@example.com", EmailVerified: true}
}

func TestLogin(t *testing.T) {
	t.Run("must redirect to the provider with an http-only lax pending cookie", func(t *testing.T) {
		recorder := serve(newMux(&stubFlow{}, &stubSessions{}), http.MethodGet, "/auth/login")

		require.Equal(t, http.StatusFound, recorder.Code)
		cookie := cookieNamed(recorder, defaultPendingCookie)
		require.NotNil(t, cookie)
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
		assert.Equal(t, pendingMaxAge, cookie.MaxAge)
		pending, err := sso.DecodePending(cookie.Value)
		require.NoError(t, err)
		assert.Equal(t, "https://sso.example.com/auth?state="+pending.State, recorder.Header().Get("Location"))
	})

	t.Run("given provider unavailable then login page with error", func(t *testing.T) {
		recorder := serve(newMux(&stubFlow{authURLErr: sso.ErrUnavailable}, &stubSessions{}), http.MethodGet, "/auth/login")
		assert.Equal(t, "/login?error=unavailable", recorder.Header().Get("Location"))
	})

	t.Run("given no flow then login page with error", func(t *testing.T) {
		recorder := serve(newMux(nil, &stubSessions{}), http.MethodGet, "/auth/login")
		assert.Equal(t, "/login?error=unavailable", recorder.Header().Get("Location"))
	})
}

func TestCallback(t *testing.T) {
	t.Run("given valid state then starts the session and lands on the app", func(t *testing.T) {
		flow, sessions := &stubFlow{identity: allowed()}, &stubSessions{}
		mux := newMux(flow, sessions)
		cookie, state := startLogin(t, mux)

		recorder := serve(mux, http.MethodGet, "/auth/callback?code=abc&state="+state, cookie)

		assert.Equal(t, "/", recorder.Header().Get("Location"))
		assert.Equal(t, "abc", flow.gotCode)
		assert.Equal(t, state, flow.gotPending.State)
		assert.Equal(t, "s1", sessions.started.Subject)
		assert.Equal(t, "tok123", cookieNamed(recorder, "app_session").Value)
		assert.Equal(t, -1, cookieNamed(recorder, defaultPendingCookie).MaxAge)
	})

	t.Run("given mismatched state then refuses without exchanging", func(t *testing.T) {
		flow, sessions := &stubFlow{identity: allowed()}, &stubSessions{}
		mux := newMux(flow, sessions)
		cookie, _ := startLogin(t, mux)

		recorder := serve(mux, http.MethodGet, "/auth/callback?code=abc&state=forged", cookie)

		assert.Equal(t, "/login?error=expired", recorder.Header().Get("Location"))
		assert.Empty(t, flow.gotCode)
		assert.Nil(t, sessions.started)
	})

	t.Run("given no pending cookie then refuses", func(t *testing.T) {
		flow := &stubFlow{identity: allowed()}
		recorder := serve(newMux(flow, &stubSessions{}), http.MethodGet, "/auth/callback?code=abc&state=x")

		assert.Equal(t, "/login?error=expired", recorder.Header().Get("Location"))
		assert.Empty(t, flow.gotCode)
	})

	t.Run("given provider error then denied", func(t *testing.T) {
		mux := newMux(&stubFlow{}, &stubSessions{})
		cookie, state := startLogin(t, mux)

		recorder := serve(mux, http.MethodGet, "/auth/callback?error=access_denied&state="+state, cookie)
		assert.Equal(t, "/login?error=denied", recorder.Header().Get("Location"))
	})

	t.Run("given forbidden identity then forbidden and no session", func(t *testing.T) {
		sessions := &stubSessions{}
		mux := newMux(&stubFlow{identity: allowed(), completeErr: sso.ErrForbidden}, sessions)
		cookie, state := startLogin(t, mux)

		recorder := serve(mux, http.MethodGet, "/auth/callback?code=abc&state="+state, cookie)

		assert.Equal(t, "/login?error=forbidden", recorder.Header().Get("Location"))
		assert.Nil(t, sessions.started)
	})

	t.Run("given invalid token then failed", func(t *testing.T) {
		mux := newMux(&stubFlow{completeErr: sso.ErrInvalidToken}, &stubSessions{})
		cookie, state := startLogin(t, mux)

		recorder := serve(mux, http.MethodGet, "/auth/callback?code=abc&state="+state, cookie)
		assert.Equal(t, "/login?error=failed", recorder.Header().Get("Location"))
	})

	t.Run("given session start failure then failed", func(t *testing.T) {
		mux := newMux(&stubFlow{identity: allowed()}, &stubSessions{startErr: errors.New("db down")})
		cookie, state := startLogin(t, mux)

		recorder := serve(mux, http.MethodGet, "/auth/callback?code=abc&state="+state, cookie)
		assert.Equal(t, "/login?error=failed", recorder.Header().Get("Location"))
	})
}

func TestLogout(t *testing.T) {
	t.Run("must end the session and return the provider logout url as json", func(t *testing.T) {
		sessions := &stubSessions{}
		recorder := serve(newMux(&stubFlow{}, sessions), http.MethodPost, "/auth/logout")

		require.Equal(t, http.StatusOK, recorder.Code)
		assert.True(t, sessions.ended)
		var body map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&body))
		assert.Equal(t, "https://sso.example.com/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Flogin", body["logoutUrl"])
	})

	t.Run("must redirect to the provider logout", func(t *testing.T) {
		sessions := &stubSessions{}
		recorder := serve(newMux(&stubFlow{}, sessions), http.MethodGet, "/auth/logout")

		assert.True(t, sessions.ended)
		assert.Equal(t, "https://sso.example.com/logout?post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Flogin", recorder.Header().Get("Location"))
	})

	t.Run("given no flow then returns the post logout url", func(t *testing.T) {
		recorder := serve(newMux(nil, &stubSessions{}), http.MethodGet, "/auth/logout")
		assert.Equal(t, "https://app.example.com/login", recorder.Header().Get("Location"))
	})
}
