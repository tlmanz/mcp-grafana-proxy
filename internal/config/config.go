// Package config loads and validates proxy environments.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
	"go.yaml.in/yaml/v3"
)

// PathEnvVar overrides the default config file location.
const PathEnvVar = "MCP_GRAFANA_PROXY_CONFIG"

// Config is the config file.
type Config struct {
	Environments map[string]*Environment `yaml:"environments"`
}

// Environment is one Grafana instance behind IAP.
type Environment struct {
	Name     string `yaml:"-"`
	Upstream string `yaml:"upstream"`
	Listen   string `yaml:"listen"` // serve mode only
	Auth     Auth   `yaml:"auth"`
}

// Auth selects how the IAP token is obtained. It is comparable, so
// environments with identical settings can share one token cache.
type Auth struct {
	Mode                string `yaml:"mode"`
	Account             string `yaml:"account"`
	GcloudConfiguration string `yaml:"gcloud_configuration"`
	ServiceAccount      string `yaml:"service_account"`
	Audience            string `yaml:"audience"`
	ClientID            string `yaml:"client_id"`
	ClientSecretFile    string `yaml:"client_secret_file"`
	RedirectPort        int    `yaml:"redirect_port"`

	// Filled in by Normalize for mode oauth-client.
	clientSecret, credentialsDir string
}

// DefaultRedirectPort is the loopback port for the oauth-client sign-in. A
// Web OAuth client only accepts redirect URIs registered exactly, so the port
// is fixed rather than picked at random.
const DefaultRedirectPort = 18085

// RedirectURI is the address to register on the OAuth client for mode
// oauth-client.
func (a Auth) RedirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d/", a.RedirectPort)
}

// Source returns the token source for these settings.
func (a Auth) Source() token.Source {
	if a.Mode == token.ModeOAuthClient {
		return a.OAuthClient()
	}
	return &token.Gcloud{
		Mode:           a.Mode,
		Account:        a.Account,
		Configuration:  a.GcloudConfiguration,
		ServiceAccount: a.ServiceAccount,
		Audience:       a.Audience,
	}
}

// OAuthClient returns the sign-in client for mode oauth-client. Only call it
// after Normalize.
func (a Auth) OAuthClient() *token.OAuthClient {
	return &token.OAuthClient{
		ClientID:     a.ClientID,
		ClientSecret: a.clientSecret,
		Credentials:  &token.FileCredentials{Path: filepath.Join(a.credentialsDir, a.ClientID+".json")},
		LoginHint:    a.Account,
		RedirectPort: a.RedirectPort,
	}
}

// DefaultPath returns $MCP_GRAFANA_PROXY_CONFIG, or config.yaml in the user
// config directory.
func DefaultPath() (string, error) {
	if p := os.Getenv(PathEnvVar); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mcp-grafana-proxy", "config.yaml"), nil
}

// Load reads and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file %s not found: create it, or pass --upstream to configure a single environment from flags", path)
		}
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Environments) == 0 {
		return nil, fmt.Errorf("%s defines no environments", path)
	}
	for name, env := range cfg.Environments {
		if env == nil {
			return nil, fmt.Errorf("%s: environment %q is empty", path, name)
		}
		env.Name = name
		// Relative to the config file: in exec mode the working directory is
		// whatever the MCP client happens to use.
		if p := env.Auth.ClientSecretFile; p != "" && !strings.HasPrefix(p, "~") && !filepath.IsAbs(p) {
			env.Auth.ClientSecretFile = filepath.Join(filepath.Dir(path), p)
		}
		if err := env.Normalize(); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return &cfg, nil
}

// Select returns the named environments, or all of them sorted by name when
// names is empty.
func (c *Config) Select(names []string) ([]*Environment, error) {
	if len(names) == 0 {
		names = c.names()
	}
	envs := make([]*Environment, 0, len(names))
	for _, name := range names {
		env, ok := c.Environments[name]
		if !ok {
			return nil, fmt.Errorf("unknown environment %q (known: %s)", name, strings.Join(c.names(), ", "))
		}
		envs = append(envs, env)
	}
	return envs, nil
}

func (c *Config) names() []string {
	names := make([]string, 0, len(c.Environments))
	for name := range c.Environments {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Normalize validates e and fills in defaults.
func (e *Environment) Normalize() error {
	u, err := url.Parse(e.Upstream)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("environment %q: upstream must be an http(s) URL, got %q", e.Name, e.Upstream)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("environment %q: upstream must not contain credentials, a query or a fragment", e.Name)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	e.Upstream = u.String()

	if e.Listen != "" {
		if err := checkLoopback(e.Listen); err != nil {
			return fmt.Errorf("environment %q: %w", e.Name, err)
		}
	}

	a := &e.Auth
	if a.Mode == "" {
		a.Mode = token.ModeUser
	}
	if a.Mode != token.ModeOAuthClient && (a.ClientID != "" || a.ClientSecretFile != "" || a.RedirectPort != 0) {
		return fmt.Errorf("environment %q: client_id, client_secret_file and redirect_port only apply to mode %s", e.Name, token.ModeOAuthClient)
	}
	switch a.Mode {
	case token.ModeUser:
		if a.ServiceAccount != "" || a.Audience != "" {
			return fmt.Errorf("environment %q: service_account and audience only apply to the impersonate modes", e.Name)
		}
	case token.ModeOAuthClient:
		if err := a.normalizeOAuthClient(); err != nil {
			return fmt.Errorf("environment %q: %w", e.Name, err)
		}
	case token.ModeImpersonateIDToken:
		if a.ServiceAccount == "" || a.Audience == "" {
			return fmt.Errorf("environment %q: mode %s needs service_account and audience (the IAP OAuth client ID)", e.Name, a.Mode)
		}
	case token.ModeImpersonateJWT:
		if a.ServiceAccount == "" {
			return fmt.Errorf("environment %q: mode %s needs service_account", e.Name, a.Mode)
		}
		if a.Audience == "" {
			a.Audience = e.Upstream + "/*"
		}
	default:
		return fmt.Errorf("environment %q: unknown auth mode %q (want %s, %s, %s or %s)",
			e.Name, a.Mode, token.ModeOAuthClient, token.ModeUser, token.ModeImpersonateIDToken, token.ModeImpersonateJWT)
	}
	return nil
}

func (a *Auth) normalizeOAuthClient() error {
	if a.ServiceAccount != "" || a.Audience != "" || a.GcloudConfiguration != "" {
		return fmt.Errorf("service_account, audience and gcloud_configuration do not apply to mode %s", token.ModeOAuthClient)
	}
	if a.ClientID == "" || a.ClientSecretFile == "" {
		return fmt.Errorf("mode %s needs client_id (IAP's OAuth client ID) and client_secret_file", token.ModeOAuthClient)
	}
	if strings.ContainsAny(a.ClientID, `/\`) {
		return fmt.Errorf("invalid client_id %q", a.ClientID)
	}
	if a.RedirectPort == 0 {
		a.RedirectPort = DefaultRedirectPort
	}
	if a.RedirectPort < 1 || a.RedirectPort > 65535 {
		return fmt.Errorf("invalid redirect_port %d", a.RedirectPort)
	}

	path, err := expandPath(a.ClientSecretFile)
	if err != nil {
		return err
	}
	a.ClientSecretFile = path
	if a.clientSecret, err = token.ReadClientSecret(path, a.ClientID); err != nil {
		return fmt.Errorf("client_secret_file: %w", err)
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	a.credentialsDir = filepath.Join(dir, "mcp-grafana-proxy", "credentials")
	return nil
}

// expandPath expands a leading ~ and makes path absolute.
func expandPath(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[1:])
	}
	return filepath.Abs(path)
}

// UpstreamURL returns the parsed upstream. Only call it after Normalize.
func (e *Environment) UpstreamURL() *url.URL {
	u, err := url.Parse(e.Upstream)
	if err != nil {
		panic(fmt.Sprintf("environment %q: upstream not normalized: %v", e.Name, err))
	}
	return u
}

// checkLoopback rejects listen addresses that are reachable from other hosts.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q must be on a loopback interface (127.0.0.1, ::1 or localhost)", addr)
	}
	return nil
}
