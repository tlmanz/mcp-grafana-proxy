package store

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(NewKey())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func validEnv(env *Environment) error {
	env.Upstream = "https://grafana.example.com/"
	env.ClientID = "123-abc.apps.googleusercontent.com"
	env.ClientSecret = "super-secret-value"
	env.GrafanaToken = "glsa_secret_token"
	return nil
}

func TestStoreRoundTripIsEncrypted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "store.enc")
	key := testKey(t)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	changes := 0
	s.OnChange(func() { changes++ })

	if err := s.Update("dev", true, validEnv); err != nil {
		t.Fatal(err)
	}
	if err := s.Credentials("dev").SaveRefreshToken("refresh-token-value", "me@example.com"); err != nil {
		t.Fatal(err)
	}
	if changes != 2 {
		t.Errorf("OnChange ran %d times, want 2", changes)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"super-secret-value", "glsa_secret_token", "refresh-token-value", "grafana.example.com", "dev"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("store file contains %q in plain text", secret)
		}
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Errorf("store file mode %o, want 600", info.Mode().Perm())
	}

	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	env, ok := reopened.Get("dev")
	if !ok || env.Upstream != "https://grafana.example.com" || env.ClientSecret != "super-secret-value" ||
		env.RefreshToken != "refresh-token-value" || env.SignedInAs != "me@example.com" || env.SignedInAt.IsZero() {
		t.Fatalf("reopened env = %+v", env)
	}
	if rt, err := reopened.Credentials("dev").LoadRefreshToken(); err != nil || rt != "refresh-token-value" {
		t.Fatalf("LoadRefreshToken = %q, %v", rt, err)
	}

	if _, err := Open(path, testKey(t)); err == nil || !strings.Contains(err.Error(), "wrong encryption key") {
		t.Fatalf("Open with another key: %v", err)
	}
}

func TestStoreUpdateAndDelete(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "store.enc"), testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update("dev", false, validEnv); err == nil {
		t.Fatal("updating a missing environment without create succeeded")
	}
	if err := s.Update("Bad Name", true, validEnv); err == nil {
		t.Fatal("invalid name accepted")
	}
	if err := s.Update("dev", true, func(e *Environment) error { e.Upstream = "ftp://x"; return nil }); err == nil {
		t.Fatal("invalid upstream accepted")
	}
	if len(s.List()) != 0 {
		t.Fatal("a failed update left an environment behind")
	}

	for _, name := range []string{"staging", "dev"} {
		if err := s.Update(name, true, validEnv); err != nil {
			t.Fatal(err)
		}
	}
	if envs := s.List(); len(envs) != 2 || envs[0].Name != "dev" || envs[1].Name != "staging" {
		t.Fatalf("List() = %v", envs)
	}

	if _, err := s.Credentials("dev").LoadRefreshToken(); !errors.Is(err, token.ErrNotSignedIn) {
		t.Fatalf("LoadRefreshToken before sign-in: %v", err)
	}
	if err := s.Delete("dev"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("dev"); ok {
		t.Fatal("deleted environment still present")
	}
	if err := s.Delete("dev"); err == nil {
		t.Fatal("deleting twice succeeded")
	}
}

func TestLoadKey(t *testing.T) {
	key := NewKey()
	t.Setenv(KeyEnvVar, key)
	if k, err := LoadKey(""); err != nil || len(k) != keySize {
		t.Fatalf("LoadKey from env: %v", err)
	}

	file := filepath.Join(t.TempDir(), "proxy.key")
	if err := os.WriteFile(file, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(KeyEnvVar, "")
	if k, err := LoadKey(file); err != nil || len(k) != keySize {
		t.Fatalf("LoadKey from file: %v", err)
	}
	if _, err := LoadKey(""); err == nil {
		t.Fatal("missing key accepted")
	}
	t.Setenv(KeyEnvVar, base64.StdEncoding.EncodeToString([]byte("short")))
	if _, err := LoadKey(""); err == nil {
		t.Fatal("short key accepted")
	}
}
