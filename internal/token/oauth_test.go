package token

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadClientSecret(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	tests := []struct {
		name, content, want string
	}{
		{"bare", "  s3cret\n", "s3cret"},
		{"web.json", `{"web":{"client_id":"cid","client_secret":"s3cret"}}`, "s3cret"},
		{"installed.json", `{"installed":{"client_secret":"s3cret"}}`, "s3cret"},
	}
	for _, tt := range tests {
		got, err := ReadClientSecret(write(tt.name, tt.content), "cid")
		if err != nil || got != tt.want {
			t.Errorf("%s: got %q, %v; want %q", tt.name, got, err, tt.want)
		}
	}

	for name, content := range map[string]string{
		"empty":       "\n",
		"other.json":  `{"web":{"client_id":"other","client_secret":"s3cret"}}`,
		"nosecret.js": `{"web":{"client_id":"cid"}}`,
		"broken.json": `{"web":`,
	} {
		if _, err := ReadClientSecret(write(name, content), "cid"); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
	if _, err := ReadClientSecret(filepath.Join(dir, "missing"), "cid"); err == nil {
		t.Error("missing file accepted")
	}
}

// fakeGoogle stands in for Google's token endpoint.
type fakeGoogle struct {
	*httptest.Server
	t *testing.T

	mu         sync.Mutex
	challenge  string // code_challenge the "browser" saw
	refreshErr string // error to return for refresh grants
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	g := &fakeGoogle{t: t}
	g.Server = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGoogle) set(f func(g *fakeGoogle)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	f(g)
}

func (g *fakeGoogle) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fail := func(status int, code string) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "fake " + code})
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != "cid" || r.PostForm.Get("client_secret") != "csecret" {
		fail(http.StatusUnauthorized, "invalid_client")
		return
	}
	idToken := makeJWT(g.t, map[string]any{"email": "me@example.com", "aud": "cid", "exp": time.Now().Add(time.Hour).Unix()})
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("code") != "the-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			fail(http.StatusBadRequest, "invalid_grant")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": "rt-1", "id_token": idToken})
	case "refresh_token":
		if g.refreshErr != "" {
			fail(http.StatusBadRequest, g.refreshErr)
			return
		}
		if r.PostForm.Get("refresh_token") != "rt-1" {
			fail(http.StatusBadRequest, "invalid_grant")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idToken})
	default:
		fail(http.StatusBadRequest, "unsupported_grant_type")
	}
}

func newTestClient(t *testing.T, g *fakeGoogle) *OAuthClient {
	return &OAuthClient{
		ClientID:     "cid",
		ClientSecret: "csecret",
		Credentials:  &FileCredentials{Path: filepath.Join(t.TempDir(), "credentials", "cid.json")},
		LoginHint:    "me@example.com",
		AuthURL:      "https://accounts.example/auth",
		TokenURL:     g.URL,
	}
}

// browser returns an open func that checks the sign-in URL and then follows
// the redirect back with query (state is filled in unless given).
func browser(t *testing.T, g *fakeGoogle, query url.Values) func(string) error {
	return func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		for k, want := range map[string]string{
			"client_id": "cid", "response_type": "code", "scope": "openid email", "access_type": "offline",
			"prompt": "consent", "code_challenge_method": "S256", "login_hint": "me@example.com",
		} {
			if got := q.Get(k); got != want {
				t.Errorf("sign-in URL %s = %q, want %q", k, got, want)
			}
		}
		g.set(func(g *fakeGoogle) { g.challenge = q.Get("code_challenge") })
		if !query.Has("state") {
			query.Set("state", q.Get("state"))
		}
		resp, err := http.Get(q.Get("redirect_uri") + "?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return nil
	}
}

func TestLoginThenToken(t *testing.T) {
	g := newFakeGoogle(t)
	o := newTestClient(t, g)
	ctx := context.Background()

	if _, err := o.Token(ctx); !errors.Is(err, ErrNotSignedIn) {
		t.Fatalf("Token before login: %v, want ErrNotSignedIn", err)
	}

	claims, err := o.Login(ctx, browser(t, g, url.Values{"code": {"the-code"}}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Identity() != "me@example.com" {
		t.Errorf("signed in as %q", claims.Identity())
	}

	path := o.Credentials.(*FileCredentials).Path
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential file mode %o, want 600", perm)
	}
	if dirInfo, _ := os.Stat(filepath.Dir(path)); dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("credentials dir mode %o, want 700", dirInfo.Mode().Perm())
	}

	tok, err := o.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := ParseClaims(tok); c.Audience.String() != "cid" {
		t.Errorf("token audience %q, want cid", c.Audience)
	}

	g.set(func(g *fakeGoogle) { g.refreshErr = "invalid_grant" })
	if _, err := o.Token(ctx); !errors.Is(err, ErrNotSignedIn) || !strings.Contains(err.Error(), "sign in again") {
		t.Errorf("revoked sign-in: %v", err)
	}
}

func TestLoginFailures(t *testing.T) {
	g := newFakeGoogle(t)
	tests := []struct {
		name  string
		query url.Values
		want  string
	}{
		{"wrong state", url.Values{"code": {"the-code"}, "state": {"forged"}}, "did not match"},
		{"user declined", url.Values{"error": {"access_denied"}}, "sign-in failed: access_denied"},
		{"no code", url.Values{}, "no authorization code"},
		{"code rejected", url.Values{"code": {"stale-code"}}, "invalid_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := newTestClient(t, g)
			_, err := o.Login(context.Background(), browser(t, g, tt.query), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want error containing %q", err, tt.want)
			}
			if _, err := os.Stat(o.Credentials.(*FileCredentials).Path); !errors.Is(err, os.ErrNotExist) {
				t.Error("a failed login saved a credential")
			}
		})
	}

	o := newTestClient(t, g)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := o.Login(ctx, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "waiting for sign-in") {
		t.Fatalf("abandoned login: %v", err)
	}
}

func TestLoginUsesFixedRedirectPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	g := newFakeGoogle(t)
	o := newTestClient(t, g)
	o.RedirectPort = port
	var redirect string
	open := func(authURL string) error {
		u, _ := url.Parse(authURL)
		redirect = u.Query().Get("redirect_uri")
		return browser(t, g, url.Values{"code": {"the-code"}})(authURL)
	}
	if _, err := o.Login(context.Background(), open, io.Discard); err != nil {
		t.Fatal(err)
	}
	if want := "http://127.0.0.1:" + strconv.Itoa(port) + "/"; redirect != want {
		t.Fatalf("redirect_uri = %q, want %q", redirect, want)
	}
}
