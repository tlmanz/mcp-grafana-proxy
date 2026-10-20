package launcher

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/config"
	"github.com/tlmanz/mcp-grafana-proxy/internal/proxy"
)

const (
	helperEnv    = "MGP_LAUNCHER_HELPER"
	helperOutEnv = "MGP_LAUNCHER_HELPER_OUT"
)

// TestMain lets the test binary act as the child process (a stand-in for
// mcp-grafana) when helperEnv is set.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		helperMain()
		return
	}
	os.Exit(m.Run())
}

// helperMain calls the proxy the way mcp-grafana does, once with the extra
// headers and once without, records both statuses, and exits 3.
func helperMain() {
	var headers map[string]string
	_ = json.Unmarshal([]byte(os.Getenv("GRAFANA_EXTRA_HEADERS")), &headers)
	call := func(withHeaders bool) string {
		req, _ := http.NewRequest(http.MethodGet, os.Getenv("GRAFANA_URL")+"/api/health", nil)
		req.Header.Set("Authorization", "Bearer glsa_test")
		if withHeaders {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err.Error()
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	out := call(true) + "\n" + call(false) + "\ntenant=" + headers["X-Tenant"]
	_ = os.WriteFile(os.Getenv(helperOutEnv), []byte(out), 0o600)
	os.Exit(3)
}

func TestBuildChildEnv(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"GRAFANA_URL=https://old.example.com",
		`GRAFANA_EXTRA_HEADERS={"X-Tenant":"t1"}`,
		"GRAFANA_SERVICE_ACCOUNT_TOKEN=glsa_x",
	}
	env, err := buildChildEnv(base, "http://127.0.0.1:5555", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := got[k]; dup {
			t.Fatalf("duplicate %s in child env", k)
		}
		got[k] = v
	}
	if got["GRAFANA_URL"] != "http://127.0.0.1:5555" || got["PATH"] != "/usr/bin" || got["GRAFANA_SERVICE_ACCOUNT_TOKEN"] != "glsa_x" {
		t.Fatalf("child env = %v", got)
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(got["GRAFANA_EXTRA_HEADERS"]), &headers); err != nil {
		t.Fatal(err)
	}
	if headers["X-Tenant"] != "t1" || headers[proxy.SecretHeader] != "s3cret" {
		t.Fatalf("extra headers = %v", headers)
	}

	if _, err := buildChildEnv([]string{"GRAFANA_EXTRA_HEADERS=not json"}, "u", "s"); err == nil {
		t.Fatal("invalid GRAFANA_EXTRA_HEADERS accepted")
	}
}

func TestRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake gcloud is a shell script")
	}
	payload, _ := json.Marshal(map[string]any{"email": "me@example.com", "exp": time.Now().Add(time.Hour).Unix()})
	jwt := "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"

	// Put a fake gcloud first on PATH.
	binDir := t.TempDir()
	script := "#!/bin/sh\necho " + jwt + "\n"
	if err := os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "Bearer "+jwt ||
			r.Header.Get("Authorization") != "Bearer glsa_test" ||
			r.Header.Get(proxy.SecretHeader) != "" {
			http.Error(w, "bad headers", http.StatusTeapot)
			return
		}
		_, _ = io.WriteString(w, "healthy")
	}))
	defer up.Close()

	outFile := filepath.Join(t.TempDir(), "out")
	t.Setenv(helperEnv, "1")
	t.Setenv(helperOutEnv, outFile)
	t.Setenv("GRAFANA_EXTRA_HEADERS", `{"X-Tenant":"t1"}`)

	env := &config.Environment{Name: "test", Upstream: up.URL}
	if err := env.Normalize(); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	code, err := Run(t.Context(), env, []string{os.Args[0]}, log)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Fatalf("exit code %d, want the child's 3", code)
	}

	out, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("helper output %q", out)
	}
	if lines[0] != "200 healthy" {
		t.Errorf("request with extra headers: %q, want 200 healthy", lines[0])
	}
	if !strings.HasPrefix(lines[1], "401 ") {
		t.Errorf("request without the secret: %q, want 401", lines[1])
	}
	if lines[2] != "tenant=t1" {
		t.Errorf("existing GRAFANA_EXTRA_HEADERS not kept: %q", lines[2])
	}
}
