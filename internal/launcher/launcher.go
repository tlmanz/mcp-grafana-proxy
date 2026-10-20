// Package launcher runs mcp-grafana behind a private, per-process proxy.
package launcher

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/config"
	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

const (
	grafanaURLEnv     = "GRAFANA_URL"
	extraHeadersEnv   = "GRAFANA_EXTRA_HEADERS"
	shutdownTimeout   = 2 * time.Second
	secretLengthBytes = 32
)

// Run starts a proxy for env on an ephemeral loopback port, then runs argv
// with GRAFANA_URL pointing at it. The child inherits stdin, stdout and
// stderr directly, so the MCP stdio stream never passes through this process.
// Run returns the child's exit code.
func Run(ctx context.Context, env *config.Environment, argv []string, log *slog.Logger) (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 1, err
	}
	secret, err := newSecret()
	if err != nil {
		ln.Close()
		return 1, err
	}

	cache := token.NewCache(env.Auth.Source())
	go cache.Prewarm(ctx, log)

	srv := &http.Server{
		Handler: proxy.New(proxy.Options{
			Upstream: env.UpstreamURL(),
			Tokens:   cache,
			Secret:   secret,
			Logger:   log,
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	grafanaURL := "http://" + ln.Addr().String()
	childEnv, err := buildChildEnv(os.Environ(), grafanaURL, secret)
	if err != nil {
		return 1, err
	}
	log.Info("proxy ready", "env", env.Name, "url", grafanaURL, "upstream", env.Upstream, "mode", env.Auth.Mode)

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = childEnv

	// Catch termination signals before starting the child so none are lost,
	// and pass them on instead of dying first.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start %s: %w", argv[0], err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case sig := <-sigs:
			_ = cmd.Process.Signal(sig)
		case err := <-done:
			var exitErr *exec.ExitError
			switch {
			case err == nil:
				return 0, nil
			case errors.As(err, &exitErr):
				if code := exitErr.ExitCode(); code >= 0 {
					return code, nil
				}
				return 1, nil // killed by a signal
			default:
				return 1, err
			}
		}
	}
}

// buildChildEnv points GRAFANA_URL at the proxy and adds the secret header to
// GRAFANA_EXTRA_HEADERS, keeping any headers the user already set there.
func buildChildEnv(base []string, grafanaURL, secret string) ([]string, error) {
	headers := map[string]string{}
	env := make([]string, 0, len(base)+2)
	for _, kv := range base {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case grafanaURLEnv:
			continue
		case extraHeadersEnv:
			if strings.TrimSpace(v) != "" {
				if err := json.Unmarshal([]byte(v), &headers); err != nil {
					return nil, fmt.Errorf("%s must be a JSON object of header names to values: %w", extraHeadersEnv, err)
				}
			}
			continue
		}
		env = append(env, kv)
	}
	headers[proxy.SecretHeader] = secret
	extra, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}
	return append(env, grafanaURLEnv+"="+grafanaURL, extraHeadersEnv+"="+string(extra)), nil
}

func newSecret() (string, error) {
	b := make([]byte, secretLengthBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
