package ui

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
	"github.com/tlmanz/mcp-grafana-proxy/internal/store"
)

const uiURL = "http://127.0.0.1:8090"

func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

// fakeGoogle implements the token and revoke endpoints.
type fakeGoogle struct {
	*httptest.Server
	mu        sync.Mutex
	challenge string
	revoked   []string
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	g := &fakeGoogle{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g.mu.Lock()
		defer g.mu.Unlock()
		if r.URL.Path == "/revoke" {
			g.revoked = append(g.revoked, r.PostForm.Get("token"))
			return
		}
		if r.PostForm.Get("client_id") != "cid" || r.PostForm.Get("client_secret") != "csecret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
			return
		}
		idToken := makeJWT(t, map[string]any{"email": "me@example.com", "aud": "cid", "exp": time.Now().Add(time.Hour).Unix()})
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if r.PostForm.Get("code") != "the-code" || r.PostForm.Get("redirect_uri") != uiURL+CallbackPath ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": "rt-1", "id_token": idToken})
		case "refresh_token":
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
		}
	}))
	t.Cleanup(g.Close)
	return g
}

type harness struct {
	t        *testing.T
	ui       *httptest.Server
	proxy    *httptest.Server
	store    *store.Store
	google   *fakeGoogle
	upstream *httptest.Server
	csrf     string

	mu   sync.Mutex
	seen []*http.Request
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, _ := base64.StdEncoding.DecodeString(store.NewKey())
	st, err := store.Open(filepath.Join(t.TempDir(), "store.enc"), key)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, store: st, google: newFakeGoogle(t)}
	h.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.seen = append(h.seen, r.Clone(r.Context()))
		h.mu.Unlock()
		switch r.URL.Path {
		case "/api/health":
			_, _ = io.WriteString(w, `{"version":"12.0.0"}`)
		case "/api/org":
			_, _ = io.WriteString(w, `{"name":"Main Org."}`)
		}
	}))
	t.Cleanup(h.upstream.Close)

	router := &proxy.Router{}
	srv, err := New(Options{
		Store: st, Router: router, UIURL: uiURL, ProxyURL: "http://127.0.0.1:18080",
		AuthURL: "https://accounts.example/auth", TokenURL: h.google.URL + "/token", RevokeURL: h.google.URL + "/revoke",
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ui = httptest.NewServer(srv)
	h.proxy = httptest.NewServer(router)
	t.Cleanup(h.ui.Close)
	t.Cleanup(h.proxy.Close)

	_, body := h.do(http.MethodGet, "/", nil, nil)
	m := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("index page has no CSRF token")
	}
	h.csrf = m[1]
	return h
}

var noRedirects = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (h *harness) do(method, path string, body any, headers map[string]string) (*http.Response, string) {
	h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, h.ui.URL+path, r)
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := noRedirects.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (h *harness) api(method, path string, body any) (*http.Response, string) {
	h.t.Helper()
	return h.do(method, path, body, map[string]string{"X-CSRF-Token": h.csrf, "Content-Type": "application/json"})
}

var devInput = map[string]any{
	"upstream":      "", // filled in per test
	"client_id":     "cid",
	"client_secret": "csecret",
	"grafana_token": "glsa_store",
}

func (h *harness) createDev() {
	h.t.Helper()
	in := map[string]any{}
	for k, v := range devInput {
		in[k] = v
	}
	in["upstream"] = h.upstream.URL
	if resp, body := h.api(http.MethodPut, "/api/environments/dev", in); resp.StatusCode != http.StatusOK {
		h.t.Fatalf("create dev: %d %s", resp.StatusCode, body)
	}
}

func (h *harness) signIn() {
	h.t.Helper()
	resp, _ := h.do(http.MethodGet, "/oauth/start?env=dev&csrf="+url.QueryEscape(h.csrf), nil, nil)
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("oauth start: %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if loc.Host != "accounts.example" || q.Get("redirect_uri") != uiURL+CallbackPath || q.Get("client_id") != "cid" {
		h.t.Fatalf("sign-in URL %s", loc)
	}
	h.google.mu.Lock()
	h.google.challenge = q.Get("code_challenge")
	h.google.mu.Unlock()

	resp, _ = h.do(http.MethodGet, CallbackPath+"?code=the-code&state="+url.QueryEscape(q.Get("state")), nil, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?signed_in=dev" {
		h.t.Fatalf("callback: %d -> %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestIndexAndGuards(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(http.MethodGet, "/", nil, nil)
	if !strings.Contains(body, uiURL+CallbackPath) {
		t.Error("index does not show the redirect URI")
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("security headers missing: %v", resp.Header)
	}
	if resp, _ := h.do(http.MethodGet, "/static/app.js", nil, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("app.js: %d", resp.StatusCode)
	}

	tests := []struct {
		name    string
		method  string
		path    string
		headers map[string]string
	}{
		{"rebinding Host", http.MethodGet, "/", map[string]string{"Host": "attacker.example.com"}},
		{"no CSRF token", http.MethodPut, "/api/environments/dev", nil},
		{"wrong CSRF token", http.MethodDelete, "/api/environments/dev", map[string]string{"X-CSRF-Token": "nope"}},
		{"cross-origin", http.MethodPut, "/api/environments/dev", map[string]string{"X-CSRF-Token": h.csrf, "Origin": "https://attacker.example.com"}},
		{"sign-in without CSRF", http.MethodGet, "/oauth/start?env=dev", nil},
	}
	for _, tt := range tests {
		if resp, _ := h.do(tt.method, tt.path, devInput, tt.headers); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", tt.name, resp.StatusCode)
		}
	}
	if len(h.store.List()) != 0 {
		t.Error("a refused request changed the store")
	}
}

func TestEnvironmentCRUD(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.api(http.MethodPut, "/api/environments/dev", map[string]any{"upstream": "https://g.example.com", "client_id": "cid"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("create without a secret: %d", resp.StatusCode)
	}
	h.createDev()

	_, body := h.api(http.MethodGet, "/api/environments", nil)
	for _, secret := range []string{"csecret", "glsa_store"} {
		if strings.Contains(body, secret) {
			t.Errorf("environment list leaks %q", secret)
		}
	}
	var list struct {
		Environments []envView `json:"environments"`
	}
	_ = json.Unmarshal([]byte(body), &list)
	if len(list.Environments) != 1 || list.Environments[0].GrafanaURL != "http://127.0.0.1:18080/dev" || !list.Environments[0].HasGrafanaToken {
		t.Fatalf("list = %+v", list.Environments)
	}

	// Empty secrets keep the saved ones.
	h.api(http.MethodPut, "/api/environments/dev", map[string]any{"upstream": h.upstream.URL, "client_id": "cid", "account": "me@example.com"})
	if env, _ := h.store.Get("dev"); env.ClientSecret != "csecret" || env.GrafanaToken != "glsa_store" || env.Account != "me@example.com" {
		t.Errorf("update lost secrets or account: %+v", env)
	}

	// A new client ID drops the sign-in, which belonged to the old client.
	_ = h.store.Credentials("dev").SaveRefreshToken("rt-old", "me@example.com")
	h.api(http.MethodPut, "/api/environments/dev", map[string]any{"upstream": h.upstream.URL, "client_id": "other-cid", "clear_grafana_token": true})
	if env, _ := h.store.Get("dev"); env.RefreshToken != "" || env.GrafanaToken != "" {
		t.Errorf("client change kept the sign-in or token was not cleared: %+v", env)
	}

	if resp, _ := h.api(http.MethodDelete, "/api/environments/dev", nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: %d", resp.StatusCode)
	}
	if _, ok := h.store.Get("dev"); ok {
		t.Error("environment still present after delete")
	}
}

func TestSignInProxyAndSignOut(t *testing.T) {
	h := newHarness(t)
	h.createDev()

	// Before sign-in the proxy explains what to do.
	resp, err := http.Get(h.proxy.URL + "/dev/api/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), `sign in to environment \"dev\"`) {
		t.Fatalf("before sign-in: %d %s", resp.StatusCode, body)
	}

	h.signIn()
	env, _ := h.store.Get("dev")
	if env.RefreshToken != "rt-1" || env.SignedInAs != "me@example.com" {
		t.Fatalf("after sign-in: %+v", env)
	}

	resp, err = http.Get(h.proxy.URL + "/dev/api/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxied request: %d", resp.StatusCode)
	}
	h.mu.Lock()
	got := h.seen[len(h.seen)-1]
	h.mu.Unlock()
	if got.URL.Path != "/api/health" || got.Header.Get("Authorization") != "Bearer glsa_store" ||
		!strings.HasPrefix(got.Header.Get("Proxy-Authorization"), "Bearer ey") {
		t.Errorf("upstream got %s with Authorization %q, Proxy-Authorization %q",
			got.URL.Path, got.Header.Get("Authorization"), got.Header.Get("Proxy-Authorization"))
	}

	_, body2 := h.api(http.MethodPost, "/api/environments/dev/test", nil)
	var test struct {
		OK bool `json:"ok"`
	}
	if _ = json.Unmarshal([]byte(body2), &test); !test.OK {
		t.Errorf("test endpoint: %s", body2)
	}

	if resp, _ := h.api(http.MethodPost, "/api/environments/dev/signout", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("sign out: %d", resp.StatusCode)
	}
	if env, _ := h.store.Get("dev"); env.RefreshToken != "" {
		t.Error("sign out kept the refresh token")
	}
	h.google.mu.Lock()
	revoked := h.google.revoked
	h.google.mu.Unlock()
	if len(revoked) != 1 || revoked[0] != "rt-1" {
		t.Errorf("revoked = %v, want [rt-1]", revoked)
	}
}

func TestCallbackRejectsUnknownState(t *testing.T) {
	h := newHarness(t)
	h.createDev()
	resp, _ := h.do(http.MethodGet, CallbackPath+"?code=the-code&state=forged", nil, nil)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(loc.Query().Get("error"), "expired or was already used") {
		t.Fatalf("forged state: %d -> %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if env, _ := h.store.Get("dev"); env.RefreshToken != "" {
		t.Error("forged callback saved a sign-in")
	}
}
