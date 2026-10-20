// Package ui is the web UI for managing environments and signing in. It also
// keeps the multi-environment proxy router in step with the store.
package ui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/check"
	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
	"github.com/tlmanz/mcp-grafana-proxy/internal/store"
	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

//go:embed assets
var assets embed.FS

const (
	// CallbackPath is where Google redirects after sign-in.
	CallbackPath = "/oauth/callback"
	csrfHeader   = "X-CSRF-Token"
	signInTTL    = 10 * time.Minute
	testTimeout  = 30 * time.Second
	failureHint  = "Use Test in the mcp-grafana-proxy UI to check the sign-in."
	csp          = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

// Options configures New.
type Options struct {
	Store    *store.Store
	Router   *proxy.Router
	UIURL    string // how the browser reaches the UI; the redirect URI is UIURL + CallbackPath
	ProxyURL string // how mcp-grafana reaches the proxy
	Logger   *slog.Logger

	// Overrides for tests.
	AuthURL, TokenURL, RevokeURL string
	HTTPClient                   *http.Client
	Transport                    http.RoundTripper
}

// Server serves the UI.
type Server struct {
	opts  Options
	log   *slog.Logger
	csrf  string
	index *template.Template
	mux   *http.ServeMux

	mu      sync.Mutex
	pending map[string]pendingSignIn // by OAuth state
	caches  map[cacheKey]*token.Cache
}

type pendingSignIn struct {
	env     string
	pkce    token.PKCE
	expires time.Time
}

// cacheKey changes whenever a cached token would no longer be right.
type cacheKey struct {
	name, clientID, clientSecret, refreshToken string
}

// New returns the UI server and starts keeping opts.Router in step with the
// store.
func New(opts Options) (*Server, error) {
	index, err := template.ParseFS(assets, "assets/index.html")
	if err != nil {
		return nil, err
	}
	static, err := fs.Sub(assets, "assets/static")
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:    opts,
		log:     opts.Logger,
		csrf:    token.RandomString(32),
		index:   index,
		mux:     http.NewServeMux(),
		pending: map[string]pendingSignIn{},
		caches:  map[cacheKey]*token.Cache{},
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	s.mux.HandleFunc("GET /api/environments", s.handleList)
	s.mux.HandleFunc("PUT /api/environments/{name}", s.handlePut)
	s.mux.HandleFunc("DELETE /api/environments/{name}", s.handleDelete)
	s.mux.HandleFunc("POST /api/environments/{name}/test", s.handleTest)
	s.mux.HandleFunc("POST /api/environments/{name}/signout", s.handleSignOut)
	s.mux.HandleFunc("GET /oauth/start", s.handleSignInStart)
	s.mux.HandleFunc("GET "+CallbackPath, s.handleCallback)

	opts.Store.OnChange(s.syncRouter)
	s.syncRouter()
	return s, nil
}

// RedirectURI is the address to register on each OAuth client.
func (s *Server) RedirectURI() string {
	return strings.TrimRight(s.opts.UIURL, "/") + CallbackPath
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A loopback Host defeats DNS rebinding; the rest stops other sites from
	// framing the UI or acting through it.
	if !proxy.IsLoopbackHost(r.Host) {
		http.Error(w, "the mcp-grafana-proxy UI only answers on a loopback address", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if origin := r.Header.Get("Origin"); origin != "" && origin != "http://"+r.Host {
			writeJSONError(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		if !s.validCSRF(r.Header.Get(csrfHeader)) {
			writeJSONError(w, http.StatusForbidden, "missing or invalid CSRF token; reload the page")
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) validCSRF(got string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.csrf)) == 1
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := s.index.Execute(w, map[string]string{
		"CSRF":        s.csrf,
		"ProxyURL":    s.opts.ProxyURL,
		"RedirectURI": s.RedirectURI(),
	})
	if err != nil {
		s.log.Warn("render UI", "error", err)
	}
}

type envView struct {
	Name            string     `json:"name"`
	Upstream        string     `json:"upstream"`
	ClientID        string     `json:"client_id"`
	Account         string     `json:"account,omitempty"`
	HasGrafanaToken bool       `json:"has_grafana_token"`
	SignedInAs      string     `json:"signed_in_as,omitempty"`
	SignedInAt      *time.Time `json:"signed_in_at,omitempty"`
	GrafanaURL      string     `json:"grafana_url"` // GRAFANA_URL for mcp-grafana
}

func (s *Server) view(env store.Environment) envView {
	v := envView{
		Name:            env.Name,
		Upstream:        env.Upstream,
		ClientID:        env.ClientID,
		Account:         env.Account,
		HasGrafanaToken: env.GrafanaToken != "",
		GrafanaURL:      strings.TrimRight(s.opts.ProxyURL, "/") + "/" + env.Name,
	}
	if env.RefreshToken != "" {
		v.SignedInAs = env.SignedInAs
		at := env.SignedInAt
		v.SignedInAt = &at
	}
	return v
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	envs := s.opts.Store.List()
	views := make([]envView, len(envs))
	for i, env := range envs {
		views[i] = s.view(env)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"proxy_url":    s.opts.ProxyURL,
		"redirect_uri": s.RedirectURI(),
		"environments": views,
	})
}

type envInput struct {
	Upstream          string `json:"upstream"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"` // empty keeps the saved one
	Account           string `json:"account"`
	GrafanaToken      string `json:"grafana_token"` // empty keeps the saved one
	ClearGrafanaToken bool   `json:"clear_grafana_token"`
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in envInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	err := s.opts.Store.Update(name, true, func(env *store.Environment) error {
		clientID := strings.TrimSpace(in.ClientID)
		if env.ClientID != "" && env.ClientID != clientID {
			// The saved sign-in belongs to the old client.
			env.RefreshToken, env.SignedInAs, env.SignedInAt = "", "", time.Time{}
		}
		env.Upstream, env.ClientID, env.Account = in.Upstream, clientID, strings.TrimSpace(in.Account)
		if in.ClientSecret != "" {
			env.ClientSecret = strings.TrimSpace(in.ClientSecret)
		}
		switch {
		case in.ClearGrafanaToken:
			env.GrafanaToken = ""
		case in.GrafanaToken != "":
			env.GrafanaToken = strings.TrimSpace(in.GrafanaToken)
		}
		return nil
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	env, _ := s.opts.Store.Get(name)
	writeJSON(w, http.StatusOK, s.view(env))
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	env, ok := s.opts.Store.Get(name)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no environment named "+name)
		return
	}
	if err := s.opts.Store.Delete(name); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.revoke(r.Context(), env)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	env, ok := s.opts.Store.Get(name)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no environment named "+name)
		return
	}
	err := s.opts.Store.Update(name, false, func(env *store.Environment) error {
		env.RefreshToken, env.SignedInAs, env.SignedInAt = "", "", time.Time{}
		return nil
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.revoke(r.Context(), env)
	updated, _ := s.opts.Store.Get(name)
	writeJSON(w, http.StatusOK, s.view(updated))
}

// revoke invalidates env's refresh token at Google. It is best effort: the
// token is already gone from the store.
func (s *Server) revoke(ctx context.Context, env store.Environment) {
	if env.RefreshToken == "" {
		return
	}
	if err := s.oauthClient(env).Revoke(ctx, env.RefreshToken); err != nil {
		s.log.Warn("could not revoke the sign-in at Google", "env", env.Name, "error", err)
	}
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	env, ok := s.opts.Store.Get(r.PathValue("name"))
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no environment named "+r.PathValue("name"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), testTimeout)
	defer cancel()
	results := check.Run(ctx, check.Target{
		Upstream:     env.Upstream,
		Mode:         token.ModeOAuthClient,
		Tokens:       s.oauthClient(env),
		GrafanaToken: env.GrafanaToken,
	})
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "ok": !check.Failed(results)})
}

// handleSignInStart sends the browser to Google. It is a GET (the browser
// navigates to it), so it carries the CSRF token in the query.
func (s *Server) handleSignInStart(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r.URL.Query().Get("csrf")) {
		http.Error(w, "missing or invalid CSRF token; go back and reload the page", http.StatusForbidden)
		return
	}
	env, ok := s.opts.Store.Get(r.URL.Query().Get("env"))
	if !ok {
		http.Error(w, "no such environment", http.StatusNotFound)
		return
	}
	state, pkce := token.RandomString(16), token.NewPKCE()
	s.mu.Lock()
	now := time.Now()
	for k, p := range s.pending {
		if now.After(p.expires) {
			delete(s.pending, k)
		}
	}
	s.pending[state] = pendingSignIn{env: env.Name, pkce: pkce, expires: now.Add(signInTTL)}
	s.mu.Unlock()
	http.Redirect(w, r, s.oauthClient(env).AuthCodeURL(s.RedirectURI(), state, pkce), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	s.mu.Lock()
	pending, ok := s.pending[state]
	delete(s.pending, state)
	s.mu.Unlock()
	if !ok || time.Now().After(pending.expires) {
		s.finishSignIn(w, r, "", errors.New("this sign-in attempt expired or was already used; start it again"))
		return
	}
	code, err := token.CallbackCode(q, state)
	if err != nil {
		s.finishSignIn(w, r, pending.env, err)
		return
	}
	env, ok := s.opts.Store.Get(pending.env)
	if !ok {
		s.finishSignIn(w, r, pending.env, errors.New("the environment was deleted during sign-in"))
		return
	}
	claims, err := s.oauthClient(env).Exchange(r.Context(), code, s.RedirectURI(), pending.pkce)
	if err == nil {
		s.log.Info("signed in", "env", env.Name, "identity", claims.Identity())
	}
	s.finishSignIn(w, r, env.Name, err)
}

func (s *Server) finishSignIn(w http.ResponseWriter, r *http.Request, env string, err error) {
	q := url.Values{}
	if err != nil {
		s.log.Warn("sign-in failed", "env", env, "error", err)
		q.Set("error", err.Error())
	} else {
		q.Set("signed_in", env)
	}
	http.Redirect(w, r, "/?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) oauthClient(env store.Environment) *token.OAuthClient {
	return &token.OAuthClient{
		ClientID:     env.ClientID,
		ClientSecret: env.ClientSecret,
		Credentials:  s.opts.Store.Credentials(env.Name),
		LoginHint:    env.Account,
		AuthURL:      s.opts.AuthURL,
		TokenURL:     s.opts.TokenURL,
		RevokeURL:    s.opts.RevokeURL,
		HTTPClient:   s.opts.HTTPClient,
	}
}

// syncRouter rebuilds the proxy's environments from the store, keeping token
// caches whose environment did not change in a way that matters.
func (s *Server) syncRouter() {
	envs := s.opts.Store.List()
	s.mu.Lock()
	defer s.mu.Unlock()
	handlers := make(map[string]http.Handler, len(envs))
	caches := make(map[cacheKey]*token.Cache, len(envs))
	for _, env := range envs {
		upstream, err := url.Parse(env.Upstream)
		if err != nil {
			s.log.Warn("skipping environment with an invalid URL", "env", env.Name, "error", err)
			continue
		}
		key := cacheKey{env.Name, env.ClientID, env.ClientSecret, env.RefreshToken}
		cache := s.caches[key]
		if cache == nil {
			cache = token.NewCache(s.oauthClient(env))
		}
		caches[key] = cache
		handlers[env.Name] = proxy.New(proxy.Options{
			Upstream:     upstream,
			Tokens:       cache,
			Prefix:       "/" + env.Name,
			GrafanaToken: env.GrafanaToken,
			FailureHint:  failureHint,
			Transport:    s.opts.Transport,
			Logger:       s.log.With("env", env.Name),
		})
	}
	s.caches = caches
	s.opts.Router.Set(handlers)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
