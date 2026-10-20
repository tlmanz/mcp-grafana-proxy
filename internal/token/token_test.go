package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

func TestParseClaims(t *testing.T) {
	tok := makeJWT(t, map[string]any{"email": "me@example.com", "aud": "client-id", "exp": 1700000000})
	c, err := ParseClaims(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity() != "me@example.com" || c.Audience.String() != "client-id" || c.Expiry != 1700000000 {
		t.Fatalf("unexpected claims %+v", c)
	}

	c, err = ParseClaims(makeJWT(t, map[string]any{"sub": "sa@x", "aud": []string{"a", "b"}, "exp": 1}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Identity() != "sa@x" || c.Audience.String() != "a,b" {
		t.Fatalf("unexpected claims %+v", c)
	}

	for _, bad := range []string{"", "a.b", "a.!!!.c", makeJWT(t, map[string]any{"aud": "x"})} {
		if _, err := ParseClaims(bad); err == nil {
			t.Errorf("ParseClaims(%q) succeeded, want error", bad)
		}
	}
}

// fakeSource mints JWTs whose expiry is chosen by expiry(callNumber).
type fakeSource struct {
	t      *testing.T
	expiry func(n int) time.Time
	delay  time.Duration
	err    error

	mu    sync.Mutex
	calls int
	ctxs  []context.Context
}

func (f *fakeSource) Token(ctx context.Context) (string, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.ctxs = append(f.ctxs, ctx)
	f.mu.Unlock()
	time.Sleep(f.delay)
	if f.err != nil {
		return "", f.err
	}
	return makeJWT(f.t, map[string]any{"exp": f.expiry(n).Unix(), "n": n}), nil
}

func (f *fakeSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newTestCache(src Source, clk *clock) *Cache {
	c := NewCache(src)
	c.now = clk.Now
	return c
}

func TestCacheReusesUntilMargin(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	clk := &clock{now: t0}
	src := &fakeSource{t: t, expiry: func(int) time.Time { return clk.now.Add(time.Hour) }}
	c := newTestCache(src, clk)

	first, err := c.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	clk.now = t0.Add(57 * time.Minute)
	if tok, _ := c.Token(context.Background()); tok != first || src.callCount() != 1 {
		t.Fatalf("token not reused before the margin (calls=%d)", src.callCount())
	}
	clk.now = t0.Add(58*time.Minute + time.Second)
	if tok, _ := c.Token(context.Background()); tok == first || src.callCount() != 2 {
		t.Fatalf("token not refreshed inside the margin (calls=%d)", src.callCount())
	}
}

func TestCacheBacksOffWhenSourceReturnsNearExpiryToken(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	clk := &clock{now: t0}
	// Always 90s left, which is already inside the 2m margin.
	src := &fakeSource{t: t, expiry: func(int) time.Time { return clk.now.Add(90 * time.Second) }}
	c := newTestCache(src, clk)

	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.now = t0.Add(10 * time.Second)
	_, _ = c.Token(context.Background())
	if src.callCount() != 1 {
		t.Fatalf("source called %d times within the reuse floor, want 1", src.callCount())
	}
	clk.now = t0.Add(31 * time.Second)
	_, _ = c.Token(context.Background())
	if src.callCount() != 2 {
		t.Fatalf("source called %d times after the reuse floor, want 2", src.callCount())
	}
}

func TestCacheInvalidate(t *testing.T) {
	clk := &clock{now: time.Unix(1_700_000_000, 0)}
	src := &fakeSource{t: t, expiry: func(int) time.Time { return clk.now.Add(time.Hour) }}
	c := newTestCache(src, clk)

	tok, _ := c.Token(context.Background())
	c.Invalidate("some-other-token")
	_, _ = c.Token(context.Background())
	if src.callCount() != 1 {
		t.Fatal("invalidating a different token dropped the cached one")
	}
	c.Invalidate(tok)
	_, _ = c.Token(context.Background())
	if src.callCount() != 2 {
		t.Fatal("invalidated token was reused")
	}
}

func TestCacheConcurrentCallersShareOneRefresh(t *testing.T) {
	src := &fakeSource{t: t, delay: 50 * time.Millisecond, expiry: func(int) time.Time { return time.Now().Add(time.Hour) }}
	c := NewCache(src)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Token(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if src.callCount() != 1 {
		t.Fatalf("source called %d times, want 1", src.callCount())
	}
}

func TestCacheErrors(t *testing.T) {
	clk := &clock{now: time.Unix(1_700_000_000, 0)}

	failing := &fakeSource{t: t, err: errors.New("boom")}
	c := newTestCache(failing, clk)
	if _, err := c.Token(context.Background()); err == nil || err.Error() != "boom" {
		t.Fatalf("got %v, want boom", err)
	}
	_, _ = c.Token(context.Background())
	if failing.callCount() != 2 {
		t.Fatal("a failed refresh was cached")
	}

	expired := &fakeSource{t: t, expiry: func(int) time.Time { return clk.now.Add(-time.Second) }}
	if _, err := newTestCache(expired, clk).Token(context.Background()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("got %v, want expired-token error", err)
	}
}

func TestCacheRefreshIgnoresCallerCancellation(t *testing.T) {
	src := &fakeSource{t: t, expiry: func(int) time.Time { return time.Now().Add(time.Hour) }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewCache(src).Token(ctx); err != nil {
		t.Fatal(err)
	}
	if err := src.ctxs[0].Err(); err != nil {
		t.Fatalf("source saw a canceled context: %v", err)
	}
}

// fakeGcloud writes a gcloud stand-in that records its arguments and
// environment, then runs body.
func fakeGcloud(t *testing.T, body string) (bin string, record func() (args []string, env string)) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake gcloud is a shell script")
	}
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	envFile := filepath.Join(dir, "env")
	t.Setenv("FAKE_GCLOUD_ARGS", argsFile)
	t.Setenv("FAKE_GCLOUD_ENV", envFile)
	bin = filepath.Join(dir, "gcloud")
	script := "#!/bin/sh\n" +
		`printf '%s\n' "$@" > "$FAKE_GCLOUD_ARGS"` + "\n" +
		`echo "config=$CLOUDSDK_ACTIVE_CONFIG_NAME prompts=$CLOUDSDK_CORE_DISABLE_PROMPTS" > "$FAKE_GCLOUD_ENV"` + "\n" +
		body + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, func() ([]string, string) {
		a, _ := os.ReadFile(argsFile)
		e, _ := os.ReadFile(envFile)
		return strings.Fields(string(a)), strings.TrimSpace(string(e))
	}
}

func TestGcloudUserMode(t *testing.T) {
	bin, record := fakeGcloud(t, `echo "  header.payload.sig  "`)
	g := &Gcloud{Mode: ModeUser, Account: "me@example.com", Configuration: "prod", Bin: bin}
	tok, err := g.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "header.payload.sig" {
		t.Fatalf("token %q not trimmed", tok)
	}
	args, env := record()
	if got, want := strings.Join(args, " "), "auth print-identity-token --account=me@example.com"; got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
	if env != "config=prod prompts=1" {
		t.Errorf("env = %q", env)
	}
}

func TestGcloudImpersonateIDTokenMode(t *testing.T) {
	bin, record := fakeGcloud(t, `echo tok`)
	g := &Gcloud{Mode: ModeImpersonateIDToken, ServiceAccount: "sa@p.iam.gserviceaccount.com", Audience: "123.apps.googleusercontent.com", Bin: bin}
	if _, err := g.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	args, _ := record()
	want := "auth print-identity-token --impersonate-service-account=sa@p.iam.gserviceaccount.com --audiences=123.apps.googleusercontent.com --include-email"
	if got := strings.Join(args, " "); got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

func TestGcloudImpersonateJWTMode(t *testing.T) {
	// Sign by base64url-encoding the claims file into the output file.
	bin, record := fakeGcloud(t, `eval "claims=\${$(($# - 1))}"; eval "out=\${$#}"
printf 'h.%s.s' "$(base64 < "$claims" | tr -d '\n=' | tr '+/' '-_')" > "$out"`)
	g := &Gcloud{Mode: ModeImpersonateJWT, ServiceAccount: "sa@p.iam.gserviceaccount.com", Audience: "https://grafana.example.com/*", Bin: bin}
	tok, err := g.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseClaims(tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != g.ServiceAccount || c.Subject != g.ServiceAccount || c.Audience.String() != g.Audience {
		t.Errorf("unexpected claims %+v", c)
	}
	if c.Expiry-c.IssuedAt != int64(jwtLifetime/time.Second) {
		t.Errorf("lifetime = %ds, want %s", c.Expiry-c.IssuedAt, jwtLifetime)
	}
	args, _ := record()
	if len(args) < 4 || strings.Join(args[:4], " ") != "iam service-accounts sign-jwt --iam-account=sa@p.iam.gserviceaccount.com" {
		t.Errorf("args = %q", args)
	}
}

func TestGcloudErrors(t *testing.T) {
	bin, _ := fakeGcloud(t, `echo "ERROR: Reauthentication required." >&2; exit 1`)
	_, err := (&Gcloud{Mode: ModeUser, Bin: bin}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "gcloud auth print-identity-token failed: ERROR: Reauthentication required.") {
		t.Errorf("got %v", err)
	}

	bin, _ = fakeGcloud(t, `true`)
	_, err = (&Gcloud{Mode: ModeUser, Bin: bin}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "printed no token") {
		t.Errorf("got %v", err)
	}

	_, err = (&Gcloud{Mode: ModeUser, Bin: "gcloud-that-does-not-exist"}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found on PATH") {
		t.Errorf("got %v", err)
	}

	bin, _ = fakeGcloud(t, `exec sleep 5`)
	_, err = (&Gcloud{Mode: ModeUser, Bin: bin, Timeout: 100 * time.Millisecond}).Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("got %v", err)
	}
}
