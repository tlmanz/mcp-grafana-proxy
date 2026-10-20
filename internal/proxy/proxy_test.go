package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

type fakeTokens struct {
	tok string
	err error

	mu          sync.Mutex
	invalidated []string
}

func (f *fakeTokens) Token(context.Context) (string, error) { return f.tok, f.err }

func (f *fakeTokens) Invalidate(tok string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invalidated = append(f.invalidated, tok)
}

// upstream records the requests it receives and answers with respond.
type upstream struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
}

func newUpstream(t *testing.T, respond http.HandlerFunc) *upstream {
	t.Helper()
	u := &upstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.reqs = append(u.reqs, r.Clone(context.Background()))
		u.mu.Unlock()
		if respond != nil {
			respond(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) requests() []*http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.reqs
}

func startProxy(t *testing.T, upstreamURL string, tokens TokenSource, secret string, transport http.RoundTripper) *httptest.Server {
	t.Helper()
	target, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Options{Upstream: target, Tokens: tokens, Secret: secret, Transport: transport}))
	t.Cleanup(srv.Close)
	return srv
}

var noRedirects = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := noRedirects.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func errorMessage(t *testing.T, body string) string {
	t.Helper()
	var e errorBody
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("body %q is not a JSON error: %v", body, err)
	}
	return e.Message
}

func TestForwardsWithIAPToken(t *testing.T) {
	up := newUpstream(t, nil)
	p := startProxy(t, up.URL+"/grafana", &fakeTokens{tok: "iap-token"}, "s3cret", nil)

	req, _ := http.NewRequest(http.MethodGet, p.URL+"/api/search?query=cpu", nil)
	req.Header.Set("Authorization", "Bearer glsa_grafana")
	req.Header.Set("Proxy-Authorization", "Bearer from-client")
	req.Header.Set(SecretHeader, "s3cret")
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}

	got := up.requests()[0]
	upHost := strings.TrimPrefix(up.URL, "http://")
	checks := map[string][2]string{
		"path":                {got.URL.Path, "/grafana/api/search"},
		"query":               {got.URL.RawQuery, "query=cpu"},
		"host":                {got.Host, upHost},
		"Authorization":       {got.Header.Get("Authorization"), "Bearer glsa_grafana"},
		"Proxy-Authorization": {got.Header.Get("Proxy-Authorization"), "Bearer iap-token"},
		SecretHeader:          {got.Header.Get(SecretHeader), ""},
		"X-Forwarded-For":     {got.Header.Get("X-Forwarded-For"), ""},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
}

// IAP is reached over HTTP/2 in practice; make sure the header survives it.
func TestForwardsOverHTTP2(t *testing.T) {
	var proto, proxyAuth string
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto, proxyAuth = r.Proto, r.Header.Get("Proxy-Authorization")
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)

	p := startProxy(t, up.URL, &fakeTokens{tok: "iap-token"}, "", up.Client().Transport)
	req, _ := http.NewRequest(http.MethodGet, p.URL+"/api/health", nil)
	if resp, _ := do(t, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if proto != "HTTP/2.0" || proxyAuth != "Bearer iap-token" {
		t.Fatalf("upstream saw proto %q, Proxy-Authorization %q", proto, proxyAuth)
	}
}

func TestGuards(t *testing.T) {
	up := newUpstream(t, nil)
	p := startProxy(t, up.URL, &fakeTokens{tok: "iap-token"}, "s3cret", nil)

	tests := []struct {
		name   string
		modify func(*http.Request)
		status int
	}{
		{"non-loopback Host", func(r *http.Request) { r.Host = "attacker.example.com" }, http.StatusForbidden},
		{"Origin header", func(r *http.Request) { r.Header.Set("Origin", "https://attacker.example.com") }, http.StatusForbidden},
		{"Sec-Fetch-Site header", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"missing secret", func(r *http.Request) { r.Header.Del(SecretHeader) }, http.StatusUnauthorized},
		{"wrong secret", func(r *http.Request) { r.Header.Set(SecretHeader, "nope") }, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, p.URL+"/api/dashboards/db", strings.NewReader("{}"))
			req.Header.Set(SecretHeader, "s3cret")
			tt.modify(req)
			resp, body := do(t, req)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d (%s)", resp.StatusCode, tt.status, body)
			}
			errorMessage(t, body)
		})
	}
	if n := len(up.requests()); n != 0 {
		t.Fatalf("upstream received %d requests, want 0", n)
	}
}

func TestTokenFailure(t *testing.T) {
	up := newUpstream(t, nil)
	p := startProxy(t, up.URL, &fakeTokens{err: errors.New("gcloud auth print-identity-token failed: reauth")}, "", nil)

	req, _ := http.NewRequest(http.MethodGet, p.URL+"/api/health", nil)
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if msg := errorMessage(t, body); !strings.Contains(msg, "could not obtain a Google IAP token") || !strings.Contains(msg, "reauth") {
		t.Fatalf("message %q", msg)
	}
	if len(up.requests()) != 0 {
		t.Fatal("request forwarded without a token")
	}
}

func TestIAPRejections(t *testing.T) {
	tests := []struct {
		name            string
		respond         http.HandlerFunc
		status          int
		wantInMsg       string
		wantInvalidated bool
	}{
		{
			name: "401 from IAP",
			respond: func(w http.ResponseWriter, r *http.Request) {
				// Real IAP labels its plain-text reasons text/html.
				w.Header().Set(iapGeneratedHeader, "true")
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, "Invalid IAP credentials: empty token")
			},
			status:          http.StatusUnauthorized,
			wantInMsg:       "Invalid IAP credentials: empty token",
			wantInvalidated: true,
		},
		{
			name: "403 from IAP",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(iapGeneratedHeader, "true")
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "<html>You don't have access</html>")
			},
			status:    http.StatusForbidden,
			wantInMsg: "IAP-secured Web App User",
		},
		{
			name: "redirect to Google sign-in",
			respond: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Set-Cookie", "GCP_IAP_XSRF_NONCE=x")
				http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?client_id=x", http.StatusFound)
			},
			status:          http.StatusUnauthorized,
			wantInMsg:       "redirected to Google sign-in",
			wantInvalidated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := newUpstream(t, tt.respond)
			tokens := &fakeTokens{tok: "iap-token"}
			p := startProxy(t, up.URL, tokens, "", nil)

			req, _ := http.NewRequest(http.MethodGet, p.URL+"/api/search", nil)
			resp, body := do(t, req)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.status)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type %q", ct)
			}
			if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("Location") != "" {
				t.Error("IAP headers leaked into the replaced response")
			}
			if msg := errorMessage(t, body); !strings.Contains(msg, tt.wantInMsg) {
				t.Errorf("message %q does not contain %q", msg, tt.wantInMsg)
			}
			if invalidated := len(tokens.invalidated) == 1 && tokens.invalidated[0] == "iap-token"; invalidated != tt.wantInvalidated {
				t.Errorf("invalidated = %v, want %v", tokens.invalidated, tt.wantInvalidated)
			}
		})
	}
}

func TestGrafanaErrorsPassThrough(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"invalid API key"}`)
	})
	tokens := &fakeTokens{tok: "iap-token"}
	p := startProxy(t, up.URL, tokens, "", nil)

	req, _ := http.NewRequest(http.MethodGet, p.URL+"/api/search", nil)
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusUnauthorized || body != `{"message":"invalid API key"}` {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if len(tokens.invalidated) != 0 {
		t.Fatal("a Grafana 401 invalidated the IAP token")
	}
}

func TestLocationRewrittenThroughProxy(t *testing.T) {
	var up *upstream
	up = newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, up.URL+"/grafana/login?redirect=x", http.StatusFound)
	})
	p := startProxy(t, up.URL+"/grafana", &fakeTokens{tok: "iap-token"}, "", nil)

	req, _ := http.NewRequest(http.MethodGet, p.URL+"/", nil)
	resp, _ := do(t, req)
	if loc := resp.Header.Get("Location"); loc != "/login?redirect=x" {
		t.Fatalf("Location = %q", loc)
	}
}

func TestRewriteLocation(t *testing.T) {
	tests := []struct {
		upstream, in, want string
	}{
		{"https://grafana.example.com/grafana", "https://grafana.example.com/grafana/login?x=1", "/login?x=1"},
		{"https://grafana.example.com/grafana", "/grafana/d/abc#panel", "/d/abc#panel"},
		{"https://grafana.example.com/grafana", "/grafana", "/"},
		{"https://grafana.example.com/grafana", "//grafana.example.com/grafana/x", "/x"},
		{"https://grafana.example.com/grafana", "/elsewhere", "/elsewhere"},
		{"https://grafana.example.com/grafana", "https://other.example.com/grafana/x", "https://other.example.com/grafana/x"},
		{"https://grafana.example.com/grafana", "http://grafana.example.com/grafana/x", "http://grafana.example.com/grafana/x"},
		{"https://grafana.example.com/grafana", "relative/path", "relative/path"},
		{"https://grafana.example.com", "https://GRAFANA.example.com/login", "/login"},
		{"https://grafana.example.com", "/login", "/login"},
	}
	for _, tt := range tests {
		u, _ := url.Parse(tt.upstream)
		h := &handler{upstream: u}
		if got := h.rewriteLocation(tt.in); got != tt.want {
			t.Errorf("upstream %s: rewriteLocation(%q) = %q, want %q", tt.upstream, tt.in, got, tt.want)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:8080":       true,
		"127.0.0.1":            true,
		"localhost:1234":       true,
		"LOCALHOST":            true,
		"[::1]:80":             true,
		"[::1]":                true,
		"::1":                  true,
		"example.com":          false,
		"127.0.0.1.nip.io:80":  false,
		"localhost.evil.com:1": false,
		"10.0.0.1:80":          false,
		"":                     false,
	}
	for host, want := range tests {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestRouterWithPrefixAndGrafanaToken(t *testing.T) {
	var up *upstream
	up = newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/grafana/redirect" {
			http.Redirect(w, r, up.URL+"/grafana/login", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	target, _ := url.Parse(up.URL + "/grafana")
	rt := &Router{}
	rt.Set(map[string]http.Handler{
		"dev": New(Options{Upstream: target, Tokens: &fakeTokens{tok: "iap-token"}, Prefix: "/dev", GrafanaToken: "glsa_from_store"}),
	})
	p := httptest.NewServer(rt)
	t.Cleanup(p.Close)

	req, _ := http.NewRequest(http.MethodGet, p.URL+"/dev/api/search?query=cpu", nil)
	if resp, body := do(t, req); resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	got := up.requests()[0]
	if got.URL.Path != "/grafana/api/search" || got.URL.RawQuery != "query=cpu" {
		t.Errorf("upstream got %s?%s", got.URL.Path, got.URL.RawQuery)
	}
	if got.Header.Get("Authorization") != "Bearer glsa_from_store" || got.Header.Get("Proxy-Authorization") != "Bearer iap-token" {
		t.Errorf("upstream headers: Authorization %q, Proxy-Authorization %q", got.Header.Get("Authorization"), got.Header.Get("Proxy-Authorization"))
	}

	// mcp-grafana's own token wins over the stored one.
	req, _ = http.NewRequest(http.MethodGet, p.URL+"/dev/api/health", nil)
	req.Header.Set("Authorization", "Bearer glsa_from_client")
	do(t, req)
	if got := up.requests()[1].Header.Get("Authorization"); got != "Bearer glsa_from_client" {
		t.Errorf("Authorization = %q, want the client's", got)
	}

	// Redirects come back under the environment's prefix.
	req, _ = http.NewRequest(http.MethodGet, p.URL+"/dev/redirect", nil)
	if resp, _ := do(t, req); resp.Header.Get("Location") != "/dev/login" {
		t.Errorf("Location = %q, want /dev/login", resp.Header.Get("Location"))
	}

	req, _ = http.NewRequest(http.MethodGet, p.URL+"/prod/api/health", nil)
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(errorMessage(t, body), `no environment "prod"`) {
		t.Errorf("unknown environment: %d %s", resp.StatusCode, body)
	}

	req, _ = http.NewRequest(http.MethodGet, p.URL+"/dev/api/health", nil)
	req.Header.Set("Origin", "https://attacker.example.com")
	if resp, _ := do(t, req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("browser request through the router: %d", resp.StatusCode)
	}
	if n := len(up.requests()); n != 3 {
		t.Errorf("upstream saw %d requests, want 3", n)
	}
}
