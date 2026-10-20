package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
	"github.com/tlmanz/mcp-grafana-proxy/internal/store"
	"github.com/tlmanz/mcp-grafana-proxy/internal/ui"
)

func runUI(args []string) error {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "ui [flags]",
		"Runs the web UI, where you add environments and sign in, and the proxy that serves every\n"+
			"environment on one port: mcp-grafana uses GRAFANA_URL=<proxy-url>/<environment>.\n"+
			"Settings, secrets and sign-ins are kept in one encrypted file in the data directory.")
	defaultDataDir := ""
	if dir, err := os.UserConfigDir(); err == nil {
		defaultDataDir = filepath.Join(dir, "mcp-grafana-proxy", "data")
	}
	dataDir := fs.String("data-dir", defaultDataDir, "directory for the encrypted store")
	keyFile := fs.String("key-file", "", "file holding the encryption key (default: $"+store.KeyEnvVar+")")
	uiListen := fs.String("ui-listen", "127.0.0.1:8090", "address for the UI")
	proxyListen := fs.String("proxy-listen", "127.0.0.1:18080", "address for the proxy")
	uiURL := fs.String("ui-url", "", "URL your browser uses for the UI; Google redirects to <ui-url>"+ui.CallbackPath+" (default http://127.0.0.1:<ui port>)")
	proxyURL := fs.String("proxy-url", "", "URL mcp-grafana uses for the proxy (default http://127.0.0.1:<proxy port>)")
	logLevel := fs.String("log-level", envOr(logLevelEnv, "info"), "log level: debug, info, warn or error (env "+logLevelEnv+")")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	log, err := newLogger(*logLevel)
	if err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("--data-dir is required")
	}
	key, err := store.LoadKey(*keyFile)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(*dataDir, "store.enc"), key)
	if err != nil {
		return err
	}

	uiLn, err := net.Listen("tcp", *uiListen)
	if err != nil {
		return fmt.Errorf("UI: %w", err)
	}
	proxyLn, err := net.Listen("tcp", *proxyListen)
	if err != nil {
		uiLn.Close()
		return fmt.Errorf("proxy: %w", err)
	}

	router := &proxy.Router{}
	srv, err := ui.New(ui.Options{
		Store:    st,
		Router:   router,
		UIURL:    cmp.Or(*uiURL, loopbackURL(uiLn)),
		ProxyURL: cmp.Or(*proxyURL, loopbackURL(proxyLn)),
		Logger:   log,
	})
	if err != nil {
		return err
	}

	servers := []*http.Server{
		{Handler: srv, ReadHeaderTimeout: 10 * time.Second},
		{Handler: router, ReadHeaderTimeout: 10 * time.Second},
	}
	errc := make(chan error, 2)
	go func() { errc <- servers[0].Serve(uiLn) }()
	go func() { errc <- servers[1].Serve(proxyLn) }()
	log.Info("UI ready", "url", cmp.Or(*uiURL, loopbackURL(uiLn)), "redirect_uri", srv.RedirectURI())
	log.Info("proxy ready", "grafana_url", cmp.Or(*proxyURL, loopbackURL(proxyLn))+"/<environment>", "environments", len(st.List()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

// loopbackURL is how a browser or mcp-grafana on this machine reaches ln. In
// a container that publishes the same port, it is also right on the host.
func loopbackURL(ln net.Listener) string {
	return fmt.Sprintf("http://127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "keygen", "Prints a new encryption key for the ui command's store.")
	_ = fs.Parse(args)
	fmt.Println(store.NewKey())
	return nil
}
