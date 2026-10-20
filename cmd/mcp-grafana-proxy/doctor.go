package main

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/config"
	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

const grafanaTokenEnv = "GRAFANA_SERVICE_ACCOUNT_TOKEN"

func runDoctor(args []string) (int, error) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "doctor [flags]",
		"Checks gcloud, then for each environment: the token's identity and audience, and whether IAP\n"+
			"accepts it. If "+grafanaTokenEnv+" is set, also checks that Grafana accepts it through IAP.\n"+
			"The token itself is never printed.")
	var ef envFlags
	ef.register(fs, true, false)
	_ = fs.Parse(args)

	envs, err := ef.resolve(fs)
	if err != nil {
		return 2, err
	}

	d := &doctor{
		out: os.Stdout,
		client: &http.Client{
			Timeout: 20 * time.Second,
			// IAP answers a rejected token with a redirect to Google sign-in;
			// report it rather than follow it.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	ctx := context.Background()
	d.checkTools(ctx)
	for _, env := range envs {
		d.checkEnv(ctx, env)
	}
	if d.failed {
		return 1, nil
	}
	return 0, nil
}

type doctor struct {
	out    io.Writer
	client *http.Client
	failed bool
}

func (d *doctor) ok(format string, a ...any)   { fmt.Fprintf(d.out, "  ok    "+format+"\n", a...) }
func (d *doctor) note(format string, a ...any) { fmt.Fprintf(d.out, "  -     "+format+"\n", a...) }
func (d *doctor) fail(format string, a ...any) {
	d.failed = true
	fmt.Fprintf(d.out, "  FAIL  "+format+"\n", a...)
}

func (d *doctor) checkTools(ctx context.Context) {
	fmt.Fprintln(d.out, "tools")
	if path, err := exec.LookPath("gcloud"); err != nil {
		d.fail("gcloud not found on PATH: install the Google Cloud CLI")
	} else {
		d.ok("gcloud: %s", path)
	}

	path, err := exec.LookPath("mcp-grafana")
	if err != nil {
		d.note("mcp-grafana not found on PATH (exec mode runs it by default)")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	d.ok("mcp-grafana: %s %s", path, strings.TrimSpace(string(out)))
}

func (d *doctor) checkEnv(ctx context.Context, env *config.Environment) {
	fmt.Fprintf(d.out, "\n%s: %s (mode %s)\n", env.Name, env.Upstream, env.Auth.Mode)

	tok, err := env.Auth.Source().Token(ctx)
	if err != nil {
		d.fail("get token: %v", err)
		return
	}
	claims, err := token.ParseClaims(tok)
	if err != nil {
		d.fail("parse token: %v", err)
		return
	}
	d.ok("token for %s, audience %s, expires in %s",
		claims.Identity(), claims.Audience, time.Until(claims.ExpiresAt()).Round(time.Second))
	if env.Auth.Mode != token.ModeImpersonateJWT && claims.Email == "" {
		d.fail("the ID token has no email claim, which IAP requires")
	}

	resp, err := d.get(ctx, env.Upstream+"/api/health", tok, "")
	if err != nil {
		d.fail("GET /api/health: %v", err)
		return
	}
	if status, ok := proxy.IAPFailure(resp); ok {
		d.fail("%s", proxy.IAPFailureMessage(resp, status))
		resp.Body.Close()
		return
	}
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK {
		d.fail("GET /api/health through IAP returned HTTP %d: %s", resp.StatusCode, snippet(body))
		return
	}
	var health struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(body, &health)
	d.ok("IAP accepted the token; Grafana %s is healthy", cmp.Or(health.Version, "(unknown version)"))

	grafanaToken := os.Getenv(grafanaTokenEnv)
	if grafanaToken == "" {
		d.note("Grafana credentials not checked: set %s to check them too", grafanaTokenEnv)
		return
	}
	resp, err = d.get(ctx, env.Upstream+"/api/org", tok, grafanaToken)
	if err != nil {
		d.fail("GET /api/org: %v", err)
		return
	}
	body = readBody(resp)
	if resp.StatusCode != http.StatusOK {
		d.fail("Grafana rejected %s (HTTP %d): %s", grafanaTokenEnv, resp.StatusCode, snippet(body))
		return
	}
	var org struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &org)
	d.ok("Grafana accepted %s (org %q)", grafanaTokenEnv, org.Name)
}

func (d *doctor) get(ctx context.Context, url, iapToken, grafanaToken string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Proxy-Authorization", "Bearer "+iapToken)
	if grafanaToken != "" {
		req.Header.Set("Authorization", "Bearer "+grafanaToken)
	}
	return d.client.Do(req)
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
