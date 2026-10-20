// Package check verifies that an environment's token gets through IAP, and
// explains why when it does not. The doctor command and the UI share it.
package check

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

// Level grades a Result.
type Level string

const (
	OK   Level = "ok"
	Fail Level = "fail"
	Note Level = "note"
)

// Result is one line of a check report.
type Result struct {
	Level   Level  `json:"level"`
	Message string `json:"message"`
}

// Target is what to check.
type Target struct {
	Upstream     string
	Mode         string // token mode, used for hints
	Tokens       token.Source
	GrafanaToken string // optional; checked against Grafana when set
}

// Failed reports whether any result is a failure.
func Failed(results []Result) bool {
	for _, r := range results {
		if r.Level == Fail {
			return true
		}
	}
	return false
}

var client = &http.Client{
	Timeout: 20 * time.Second,
	// IAP answers a rejected token with a redirect to Google sign-in; report
	// it rather than follow it.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

type report []Result

func (r *report) add(level Level, format string, a ...any) {
	*r = append(*r, Result{Level: level, Message: fmt.Sprintf(format, a...)})
}

// Run mints a token, shows whose it is, and asks IAP (and Grafana, when a
// Grafana token is given) whether they accept it. The token is never shown.
func Run(ctx context.Context, t Target) []Result {
	var r report
	tok, err := t.Tokens.Token(ctx)
	if err != nil {
		r.add(Fail, "get token: %v", err)
		return r
	}
	claims, err := token.ParseClaims(tok)
	if err != nil {
		r.add(Fail, "parse token: %v", err)
		return r
	}
	r.add(OK, "token for %s, audience %s, expires in %s",
		claims.Identity(), claims.Audience, time.Until(claims.ExpiresAt()).Round(time.Second))
	if t.Mode != token.ModeImpersonateJWT && claims.Email == "" {
		r.add(Fail, "the ID token has no email claim, which IAP requires")
	}

	healthURL := t.Upstream + "/api/health"
	resp, err := get(ctx, healthURL, map[string]string{"Proxy-Authorization": "Bearer " + tok})
	if err != nil {
		r.add(Fail, "GET /api/health: %v", err)
		return r
	}
	if status, ok := proxy.IAPFailure(resp); ok {
		r.add(Fail, "%s", proxy.IAPFailureMessage(resp, status))
		resp.Body.Close()
		if status == http.StatusUnauthorized {
			r.explainRejection(ctx, t, healthURL, tok, claims)
		}
		return r
	}
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK {
		r.add(Fail, "GET /api/health through IAP returned HTTP %d: %s", resp.StatusCode, snippet(body))
		return r
	}
	var health struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(body, &health)
	r.add(OK, "IAP accepted the token; Grafana %s is healthy", cmp.Or(health.Version, "(unknown version)"))

	if t.GrafanaToken == "" {
		r.add(Note, "Grafana credentials not checked: no Grafana service account token given")
		return r
	}
	resp, err = get(ctx, t.Upstream+"/api/org", map[string]string{
		"Proxy-Authorization": "Bearer " + tok,
		"Authorization":       "Bearer " + t.GrafanaToken,
	})
	if err != nil {
		r.add(Fail, "GET /api/org: %v", err)
		return r
	}
	body = readBody(resp)
	if resp.StatusCode != http.StatusOK {
		r.add(Fail, "Grafana rejected the service account token (HTTP %d): %s", resp.StatusCode, snippet(body))
		return r
	}
	var org struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &org)
	r.add(OK, "Grafana accepted the service account token (org %q)", org.Name)
	return r
}

// explainRejection digs into a 401. IAP judges the Authorization header when
// the Proxy-Authorization token is invalid, so its first reason can be about
// the wrong header. Asking again with the token in Authorization gets IAP's
// verdict on the token itself.
func (r *report) explainRejection(ctx context.Context, t Target, healthURL, tok string, claims token.Claims) {
	var reason string
	if resp, err := get(ctx, healthURL, map[string]string{"Authorization": "Bearer " + tok}); err == nil {
		if _, rejected := proxy.IAPFailure(resp); rejected {
			reason = proxy.IAPReason(resp)
			r.add(Note, "IAP's verdict on the token itself: %s", cmp.Or(reason, "(no reason given)"))
		} else if resp.StatusCode == http.StatusOK {
			r.add(Note, "IAP accepts the token in Authorization but not in Proxy-Authorization: something in front of IAP may be stripping Proxy-Authorization")
		}
		resp.Body.Close()
	}

	// Without credentials IAP redirects to sign-in, naming its OAuth client.
	var iapClientID string
	if resp, err := get(ctx, healthURL, nil); err == nil {
		resp.Body.Close()
		if loc, err := url.Parse(resp.Header.Get("Location")); err == nil && loc.Host == "accounts.google.com" {
			if iapClientID = loc.Query().Get("client_id"); iapClientID != "" {
				r.add(Note, "IAP's OAuth client ID: %s", iapClientID)
			}
		}
	}

	if !strings.Contains(strings.ToLower(reason), "audience") {
		return
	}
	iapClient := cmp.Or(iapClientID, "IAP's OAuth client ID")
	switch t.Mode {
	case token.ModeUser:
		r.add(Note, "fix: IAP only accepts tokens for its own OAuth client or for clients from your organization in "+
			"programmatic_clients, and gcloud's client is neither. Use mode oauth-client with client ID %s.", iapClient)
	case token.ModeOAuthClient, token.ModeImpersonateIDToken:
		r.add(Note, "fix: the token's audience %s should be %s", claims.Audience, iapClient)
	}
}

func get(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return client.Do(req)
}

func readBody(resp *http.Response) []byte {
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return b
}

func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
