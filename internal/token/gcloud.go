package token

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Token modes.
const (
	// ModeUser sends the user's own ID token from gcloud. IAP must allowlist
	// gcloud's OAuth client ID for programmatic access.
	ModeUser = "user"
	// ModeImpersonateIDToken sends a service account ID token whose audience
	// is the IAP OAuth client ID.
	ModeImpersonateIDToken = "impersonate-id-token"
	// ModeImpersonateJWT sends a JWT signed by a service account, with the
	// IAP-secured URL as audience.
	ModeImpersonateJWT = "impersonate-jwt"
)

const (
	defaultTimeout = 30 * time.Second

	// jwtLifetime is the longest lifetime IAP accepts for a signed JWT.
	jwtLifetime = time.Hour
)

// Gcloud mints IAP tokens by running the gcloud CLI, so it uses whatever
// account and configuration the user has already set up there.
type Gcloud struct {
	Mode           string
	Account        string // optional; gcloud's active account when empty
	Configuration  string // optional named gcloud configuration
	ServiceAccount string // impersonate modes
	Audience       string // impersonate modes: IAP OAuth client ID, or the resource URL for JWT mode

	Bin     string        // defaults to "gcloud"
	Timeout time.Duration // defaults to 30s
}

// Token runs gcloud and returns the token it prints.
func (g *Gcloud) Token(ctx context.Context) (string, error) {
	switch g.Mode {
	case ModeUser:
		return g.printIdentityToken(ctx)
	case ModeImpersonateIDToken:
		return g.printIdentityToken(ctx,
			"--impersonate-service-account="+g.ServiceAccount,
			"--audiences="+g.Audience,
			"--include-email")
	case ModeImpersonateJWT:
		return g.signJWT(ctx)
	default:
		return "", fmt.Errorf("unknown token mode %q", g.Mode)
	}
}

func (g *Gcloud) printIdentityToken(ctx context.Context, flags ...string) (string, error) {
	tok, err := g.run(ctx, append([]string{"auth", "print-identity-token"}, flags...)...)
	if err == nil && tok == "" {
		err = errors.New("gcloud auth print-identity-token printed no token")
	}
	return tok, err
}

func (g *Gcloud) signJWT(ctx context.Context) (string, error) {
	dir, err := os.MkdirTemp("", "mcp-grafana-proxy-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)

	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"iss": g.ServiceAccount,
		"sub": g.ServiceAccount,
		"aud": g.Audience,
		"iat": now.Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	claimsPath := filepath.Join(dir, "claims.json")
	outPath := filepath.Join(dir, "token.jwt")
	if err := os.WriteFile(claimsPath, claims, 0o600); err != nil {
		return "", err
	}
	if _, err := g.run(ctx, "iam", "service-accounts", "sign-jwt",
		"--iam-account="+g.ServiceAccount, claimsPath, outPath); err != nil {
		return "", err
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		return "", fmt.Errorf("read signed JWT: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (g *Gcloud) run(ctx context.Context, args ...string) (string, error) {
	if g.Account != "" {
		args = append(args, "--account="+g.Account)
	}
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(g.Timeout, defaultTimeout))
	defer cancel()

	bin := cmp.Or(g.Bin, "gcloud")
	cmd := exec.CommandContext(ctx, bin, args...)
	// Stdin stays nil (/dev/null) on purpose: in exec mode this process's
	// stdin is the MCP stream, and gcloud must never read from it or prompt.
	cmd.Env = append(os.Environ(), "CLOUDSDK_CORE_DISABLE_PROMPTS=1")
	if g.Configuration != "" {
		cmd.Env = append(cmd.Env, "CLOUDSDK_ACTIVE_CONFIG_NAME="+g.Configuration)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Run(); err != nil {
		name := commandName(args)
		switch {
		case errors.Is(err, exec.ErrNotFound):
			return "", fmt.Errorf("%s not found on PATH: install the Google Cloud CLI", bin)
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return "", fmt.Errorf("%s timed out", name)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("%s failed: %s", name, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// commandName returns "gcloud" plus the leading subcommand words of args,
// for error messages.
func commandName(args []string) string {
	words := []string{"gcloud"}
	for _, a := range args {
		if strings.HasPrefix(a, "-") || filepath.IsAbs(a) {
			break
		}
		words = append(words, a)
	}
	return strings.Join(words, " ")
}
