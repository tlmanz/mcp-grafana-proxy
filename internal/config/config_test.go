package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := writeConfig(t, `
environments:
  prod:
    upstream: https://grafana.example.com/
    listen: 127.0.0.1:18080
    auth:
      account: me@example.com
      gcloud_configuration: prod
  staging:
    upstream: https://staging.example.com/grafana/
    listen: localhost:18081
    auth:
      mode: impersonate-jwt
      service_account: sa@p.iam.gserviceaccount.com
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	envs, err := cfg.Select(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(envs) != 2 || envs[0].Name != "prod" || envs[1].Name != "staging" {
		t.Fatalf("Select(nil) = %v, want prod and staging in order", envs)
	}

	prod, staging := envs[0], envs[1]
	if prod.Upstream != "https://grafana.example.com" {
		t.Errorf("prod upstream = %q", prod.Upstream)
	}
	if prod.Auth.Mode != "user" || prod.Auth.Account != "me@example.com" || prod.Auth.GcloudConfiguration != "prod" {
		t.Errorf("prod auth = %+v", prod.Auth)
	}
	if staging.Upstream != "https://staging.example.com/grafana" {
		t.Errorf("staging upstream = %q", staging.Upstream)
	}
	if staging.Auth.Audience != "https://staging.example.com/grafana/*" {
		t.Errorf("staging default audience = %q", staging.Auth.Audience)
	}
	if got := staging.UpstreamURL().Path; got != "/grafana" {
		t.Errorf("staging upstream path = %q", got)
	}

	if _, err := cfg.Select([]string{"dev"}); err == nil || !strings.Contains(err.Error(), "known: prod, staging") {
		t.Errorf("Select(dev) error = %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	tests := map[string]string{
		"unknown field": `
environments:
  prod:
    upstream: https://grafana.example.com
    upstrem: typo`,
		"no environments": `environments: {}`,
		"missing scheme": `
environments:
  prod:
    upstream: grafana.example.com`,
		"query in upstream": `
environments:
  prod:
    upstream: https://grafana.example.com?orgId=1`,
		"wildcard listen": `
environments:
  prod:
    upstream: https://grafana.example.com
    listen: 0.0.0.0:18080`,
		"listen without host": `
environments:
  prod:
    upstream: https://grafana.example.com
    listen: ":18080"`,
		"user mode with service account": `
environments:
  prod:
    upstream: https://grafana.example.com
    auth: {service_account: sa@p.iam.gserviceaccount.com}`,
		"id token mode without audience": `
environments:
  prod:
    upstream: https://grafana.example.com
    auth: {mode: impersonate-id-token, service_account: sa@p.iam.gserviceaccount.com}`,
		"jwt mode without service account": `
environments:
  prod:
    upstream: https://grafana.example.com
    auth: {mode: impersonate-jwt}`,
		"unknown mode": `
environments:
  prod:
    upstream: https://grafana.example.com
    auth: {mode: magic}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatal("Load succeeded, want error")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil || !strings.Contains(err.Error(), "--upstream") {
		t.Fatalf("error = %v, want a hint about --upstream", err)
	}
}

func TestDefaultPathHonoursEnv(t *testing.T) {
	t.Setenv(PathEnvVar, "/tmp/custom.yaml")
	if p, _ := DefaultPath(); p != "/tmp/custom.yaml" {
		t.Fatalf("DefaultPath() = %q", p)
	}
}
