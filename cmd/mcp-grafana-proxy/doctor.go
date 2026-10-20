package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/check"
	"github.com/tlmanz/mcp-grafana-proxy/internal/config"
	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

const grafanaTokenEnv = "GRAFANA_SERVICE_ACCOUNT_TOKEN"

func runDoctor(args []string) (int, error) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	fs.Usage = commandUsage(fs, "doctor [flags]",
		"Checks the tools, then for each environment: the token's identity and audience, and whether IAP\n"+
			"accepts it. If "+grafanaTokenEnv+" is set, also checks that Grafana accepts it through IAP.\n"+
			"The token itself is never printed.")
	var ef envFlags
	ef.register(fs, true, false)
	_ = fs.Parse(args)

	envs, err := ef.resolve(fs)
	if err != nil {
		return 2, err
	}

	ctx := context.Background()
	failed := checkTools(ctx, envs)
	for _, env := range envs {
		fmt.Printf("\n%s: %s (mode %s)\n", env.Name, env.Upstream, env.Auth.Mode)
		results := check.Run(ctx, check.Target{
			Upstream:     env.Upstream,
			Mode:         env.Auth.Mode,
			Tokens:       env.Auth.Source(),
			GrafanaToken: os.Getenv(grafanaTokenEnv),
		})
		printResults(results)
		failed = failed || check.Failed(results)
	}
	if failed {
		return 1, nil
	}
	return 0, nil
}

func checkTools(ctx context.Context, envs []*config.Environment) (failed bool) {
	fmt.Println("tools")
	var results []check.Result
	needGcloud := false
	for _, env := range envs {
		needGcloud = needGcloud || env.Auth.Mode != token.ModeOAuthClient
	}
	if path, err := exec.LookPath("gcloud"); err == nil {
		results = append(results, check.Result{Level: check.OK, Message: "gcloud: " + path})
	} else if needGcloud {
		results = append(results, check.Result{Level: check.Fail, Message: "gcloud not found on PATH: install the Google Cloud CLI"})
	}

	if path, err := exec.LookPath("mcp-grafana"); err != nil {
		results = append(results, check.Result{Level: check.Note, Message: "mcp-grafana not found on PATH (exec mode runs it by default)"})
	} else {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, path, "--version").CombinedOutput()
		results = append(results, check.Result{Level: check.OK, Message: fmt.Sprintf("mcp-grafana: %s %s", path, strings.TrimSpace(string(out)))})
	}
	printResults(results)
	return check.Failed(results)
}

func printResults(results []check.Result) {
	labels := map[check.Level]string{check.OK: "ok", check.Fail: "FAIL", check.Note: "-"}
	for _, r := range results {
		fmt.Printf("  %-5s %s\n", labels[r.Level], r.Message)
	}
}
