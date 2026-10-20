// Package server runs long-lived proxies, one listener per environment.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/config"
	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

const shutdownTimeout = 5 * time.Second

// Serve runs a proxy for each environment until ctx is canceled.
// Environments with identical auth settings share one token cache.
func Serve(ctx context.Context, envs []*config.Environment, log *slog.Logger) error {
	caches := map[config.Auth]*token.Cache{}
	servers := make([]*http.Server, 0, len(envs))
	listeners := make([]net.Listener, 0, len(envs))
	closeAll := func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}

	for _, env := range envs {
		if env.Listen == "" {
			closeAll()
			return fmt.Errorf("environment %q has no listen address", env.Name)
		}
		cache, ok := caches[env.Auth]
		if !ok {
			cache = token.NewCache(env.Auth.Source())
			caches[env.Auth] = cache
		}
		ln, err := net.Listen("tcp", env.Listen)
		if err != nil {
			closeAll()
			return fmt.Errorf("environment %q: %w", env.Name, err)
		}
		listeners = append(listeners, ln)
		envLog := log.With("env", env.Name)
		servers = append(servers, &http.Server{
			Handler:           proxy.New(proxy.Options{Upstream: env.UpstreamURL(), Tokens: cache, Logger: envLog}),
			ReadHeaderTimeout: 10 * time.Second,
			ErrorLog:          slog.NewLogLogger(envLog.Handler(), slog.LevelWarn),
		})
		envLog.Info("listening", "url", "http://"+ln.Addr().String(), "upstream", env.Upstream, "mode", env.Auth.Mode)
	}

	for _, cache := range caches {
		go cache.Prewarm(ctx, log)
	}

	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
