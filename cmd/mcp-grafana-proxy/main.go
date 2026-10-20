// Command mcp-grafana-proxy adds Google IAP authentication to the requests
// that the official Grafana MCP server (mcp-grafana) makes to Grafana.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tlmanz/mcp-grafana-proxy/internal/config"
	"github.com/tlmanz/mcp-grafana-proxy/internal/launcher"
	"github.com/tlmanz/mcp-grafana-proxy/internal/server"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const logLevelEnv = "MCP_GRAFANA_PROXY_LOG_LEVEL"

const usage = `mcp-grafana-proxy adds Google IAP authentication to mcp-grafana's requests to Grafana.

Usage:
  mcp-grafana-proxy ui     [flags]
        Run the web UI (add environments, sign in) and the proxy for all of them.
  mcp-grafana-proxy keygen
        Print a new encryption key for the ui command.
  mcp-grafana-proxy exec   [flags] [-- command [args...]]
        Run mcp-grafana (or the given command) behind a private proxy.
        Use this as the command in your MCP client config.
  mcp-grafana-proxy serve  [flags]
        Run a long-lived proxy for each configured environment.
  mcp-grafana-proxy login  [flags]
        Sign in through your browser (mode oauth-client). Needed once per OAuth client.
  mcp-grafana-proxy doctor [flags]
        Check gcloud, the IAP token, and that IAP accepts it.
  mcp-grafana-proxy token  [flags]
        Print the IAP token for an environment (for curl debugging).
  mcp-grafana-proxy version

Run "mcp-grafana-proxy <command> -h" for a command's flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var (
		code int
		err  error
	)
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "exec":
		code, err = runExec(args)
	case "serve":
		err = runServe(args)
	case "ui":
		err = runUI(args)
	case "keygen":
		err = runKeygen(args)
	case "login":
		err = runLogin(args)
	case "doctor":
		code, err = runDoctor(args)
	case "token":
		err = runToken(args)
	case "version", "-version", "--version":
		fmt.Println(version)
	case "help", "-h", "-help", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-grafana-proxy:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func runExec(args []string) (int, error) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "exec [flags] [-- command [args...]]",
		"Runs the command (default: mcp-grafana) with GRAFANA_URL pointing at a private proxy on an\n"+
			"ephemeral loopback port. The command's stdin and stdout are passed through untouched.")
	var ef envFlags
	ef.register(fs, false, false)
	logLevel := fs.String("log-level", envOr(logLevelEnv, "info"), "log level: debug, info, warn or error (env "+logLevelEnv+")")
	_ = fs.Parse(args)

	env, err := ef.resolveOne(fs)
	if err != nil {
		return 2, err
	}
	log, err := newLogger(*logLevel)
	if err != nil {
		return 2, err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		argv = []string{"mcp-grafana"}
	}
	return launcher.Run(context.Background(), env, argv, log)
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "serve [flags]",
		"Runs a proxy on each environment's listen address. Point mcp-grafana at it with\n"+
			"GRAFANA_URL=http://<listen address>.")
	var ef envFlags
	ef.register(fs, true, true)
	logLevel := fs.String("log-level", envOr(logLevelEnv, "info"), "log level: debug, info, warn or error (env "+logLevelEnv+")")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	envs, err := ef.resolve(fs)
	if err != nil {
		return err
	}
	log, err := newLogger(*logLevel)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.Serve(ctx, envs, log)
}

func runToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "token [flags]",
		"Prints the token the proxy would send to IAP, for example:\n"+
			`  curl -H "Proxy-Authorization: Bearer $(mcp-grafana-proxy token --env prod)" https://grafana.example.com/api/health`)
	var ef envFlags
	ef.register(fs, false, false)
	_ = fs.Parse(args)

	env, err := ef.resolveOne(fs)
	if err != nil {
		return err
	}
	tok, err := env.Auth.Source().Token(context.Background())
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

// envFlags selects environments from the config file, or builds a single
// environment from flags when --upstream is given.
type envFlags struct {
	configPath string
	names      stringList
	adhoc      config.Environment
}

// adhocFlags only make sense together with --upstream.
var adhocFlags = []string{"listen", "mode", "account", "gcloud-configuration", "service-account", "audience", "client-id", "client-secret-file"}

func (f *envFlags) register(fs *flag.FlagSet, multi, listen bool) {
	fs.StringVar(&f.configPath, "config", "", "config file (default $"+config.PathEnvVar+", or mcp-grafana-proxy/config.yaml in the user config directory)")
	envHelp := "environment from the config file; may be omitted when the file defines only one"
	if multi {
		envHelp = "environment from the config file; repeatable (default: all)"
	}
	fs.Var(&f.names, "env", envHelp)
	fs.StringVar(&f.adhoc.Upstream, "upstream", "", "Grafana base URL; configures a single environment from flags instead of the config file")
	if listen {
		fs.StringVar(&f.adhoc.Listen, "listen", "127.0.0.1:18080", "loopback address to listen on (with --upstream)")
	}
	fs.StringVar(&f.adhoc.Auth.Mode, "mode", "", "token mode: oauth-client, user, impersonate-id-token or impersonate-jwt (with --upstream; default user)")
	fs.StringVar(&f.adhoc.Auth.Account, "account", "", "Google account to use (with --upstream; default: gcloud's active account, or the one you sign in with)")
	fs.StringVar(&f.adhoc.Auth.GcloudConfiguration, "gcloud-configuration", "", "named gcloud configuration to use (with --upstream)")
	fs.StringVar(&f.adhoc.Auth.ServiceAccount, "service-account", "", "service account to impersonate (with --upstream, impersonate modes)")
	fs.StringVar(&f.adhoc.Auth.Audience, "audience", "", "token audience (with --upstream, impersonate modes)")
	fs.StringVar(&f.adhoc.Auth.ClientID, "client-id", "", "IAP's OAuth client ID (with --upstream, mode oauth-client)")
	fs.StringVar(&f.adhoc.Auth.ClientSecretFile, "client-secret-file", "", "file holding that client's secret (with --upstream, mode oauth-client)")
}

func (f *envFlags) resolve(fs *flag.FlagSet) ([]*config.Environment, error) {
	if f.adhoc.Upstream != "" {
		if len(f.names) > 0 || f.configPath != "" {
			return nil, errors.New("--upstream cannot be combined with --env or --config")
		}
		env := f.adhoc
		env.Name = "default"
		if err := env.Normalize(); err != nil {
			return nil, err
		}
		return []*config.Environment{&env}, nil
	}

	var misplaced []string
	fs.Visit(func(fl *flag.Flag) {
		for _, name := range adhocFlags {
			if fl.Name == name {
				misplaced = append(misplaced, "--"+name)
			}
		}
	})
	if len(misplaced) > 0 {
		return nil, fmt.Errorf("%s only apply with --upstream; set them in the config file instead", strings.Join(misplaced, ", "))
	}

	path := f.configPath
	if path == "" {
		var err error
		if path, err = config.DefaultPath(); err != nil {
			return nil, err
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return cfg.Select(f.names)
}

func (f *envFlags) resolveOne(fs *flag.FlagSet) (*config.Environment, error) {
	if len(f.names) > 1 {
		return nil, errors.New("--env may only be given once for this command")
	}
	envs, err := f.resolve(fs)
	if err != nil {
		return nil, err
	}
	if len(envs) != 1 {
		names := make([]string, len(envs))
		for i, env := range envs {
			names[i] = env.Name
		}
		return nil, fmt.Errorf("the config file defines %d environments (%s); choose one with --env", len(envs), strings.Join(names, ", "))
	}
	return envs[0], nil
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func newLogger(level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	// Always stderr: in exec mode stdout belongs to the MCP stream.
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l})), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func commandUsage(fs *flag.FlagSet, synopsis, description string) func() {
	return func() {
		fmt.Fprintf(fs.Output(), "Usage: mcp-grafana-proxy %s\n\n%s\n\nFlags:\n", synopsis, description)
		fs.PrintDefaults()
	}
}
