package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

const loginTimeout = 5 * time.Minute

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "login [flags]",
		"Signs you in through your browser with the environment's OAuth client (mode oauth-client) and\n"+
			"saves a refresh token, so the proxy can mint IAP tokens without prompting. Run it once, and\n"+
			"again if the saved sign-in expires or is revoked.")
	var ef envFlags
	ef.register(fs, false, false)
	noBrowser := fs.Bool("no-browser", false, "print the sign-in URL instead of opening a browser")
	_ = fs.Parse(args)

	env, err := ef.resolveOne(fs)
	if err != nil {
		return err
	}
	if env.Auth.Mode != token.ModeOAuthClient {
		return fmt.Errorf("environment %q uses mode %s; login only applies to mode %s", env.Name, env.Auth.Mode, token.ModeOAuthClient)
	}

	client := env.Auth.OAuthClient()
	open := openBrowser
	if *noBrowser {
		open = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	fmt.Fprintf(os.Stderr, "Signing in to %s with OAuth client %s.\n", env.Upstream, client.ClientID)
	claims, err := client.Login(ctx, open, os.Stderr)
	if err != nil {
		return fmt.Errorf("%w\n\nIf Google reported redirect_uri_mismatch, add %s to the client's Authorized redirect URIs", err, env.Auth.RedirectURI())
	}
	fmt.Fprintf(os.Stderr, "Signed in as %s. Check access with: mcp-grafana-proxy doctor\n", claims.Identity())
	return nil
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
