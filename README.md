# mcp-grafana-proxy

A local reverse proxy that lets the official [Grafana MCP server](https://github.com/grafana/mcp-grafana) (`mcp-grafana`) reach a Grafana instance protected by Google Identity-Aware Proxy (IAP). It adds an IAP token from your `gcloud` login to every request. mcp-grafana, Grafana and your MCP client stay unmodified.

```
Claude Code / Cursor / ...
   │ stdio (MCP)
   ▼
mcp-grafana (unmodified)            GRAFANA_URL=http://127.0.0.1:<port>
   │ HTTP, Authorization: Bearer <Grafana service account token>
   ▼
mcp-grafana-proxy (loopback only)   ◄── gcloud auth print-identity-token (cached)
   │ HTTPS, + Proxy-Authorization: Bearer <Google ID token>
   ▼
Google IAP ──► Grafana (unchanged)
```

Each part has one job:

- **mcp-grafana** knows Grafana and MCP.
- **The proxy** knows IAP.
- **gcloud** knows who you are.

The IAP token goes in `Proxy-Authorization`. IAP authorizes the request with it and passes `Authorization` through untouched, so mcp-grafana's Grafana service account token reaches Grafana unchanged.

## Requirements

- The [Google Cloud CLI](https://cloud.google.com/sdk/docs/install), logged in with `gcloud auth login`.
- `mcp-grafana` on your `PATH`.
- An IAP resource that uses a **custom OAuth client**. With the Google-managed client, IAP refuses programmatic access for user accounts; only the `impersonate-jwt` mode works there.
- A Grafana service account token for mcp-grafana.
- Go 1.24 or later, to install from source.

## One-time IAP setup (IAP admin)

In the default `user` mode, the proxy sends your own ID token from gcloud. That token's audience is gcloud's OAuth client ID, not the IAP client's. So IAP must allowlist gcloud's client ID for programmatic access.

1. Find the client ID: run `mcp-grafana-proxy doctor --upstream https://grafana.example.com` and copy the `audience` it prints.
2. Add it to the IAP programmatic clients. Run `gcloud iap settings get` first and keep any existing settings, then apply a file like this with `gcloud iap settings set`:

   ```yaml
   accessSettings:
     oauthSettings:
       programmaticClients:
         - <audience from step 1>
   ```

   See `gcloud iap settings set --help` for the flags that scope it to your resource (project, resource type, service).
3. Give each user the **IAP-secured Web App User** role (`roles/iap.httpsResourceAccessor`) on the resource, as for browser access.

## Install

```sh
go install github.com/tlmanz/mcp-grafana-proxy/cmd/mcp-grafana-proxy@latest
```

## Configure

Create `config.yaml` in the user config directory:

- Linux: `~/.config/mcp-grafana-proxy/config.yaml`
- macOS: `~/Library/Application Support/mcp-grafana-proxy/config.yaml`

You can also set `MCP_GRAFANA_PROXY_CONFIG` to any path. [config.example.yaml](config.example.yaml) has every option.

```yaml
environments:
  prod:
    upstream: https://grafana.example.com
    listen: 127.0.0.1:18080   # serve mode only
  staging:
    upstream: https://grafana-staging.example.com
    listen: 127.0.0.1:18081
```

Then check the setup:

```sh
GRAFANA_SERVICE_ACCOUNT_TOKEN=glsa_... mcp-grafana-proxy doctor
```

## Use with an MCP client

### exec mode (recommended)

Your MCP client starts `mcp-grafana-proxy exec`. It opens a private proxy on a free loopback port, then starts mcp-grafana with `GRAFANA_URL` pointing at it. stdin and stdout go straight to mcp-grafana. Nothing needs to be running beforehand.

Claude Code (`.mcp.json` in a project, or `~/.claude.json`) and Cursor (`~/.cursor/mcp.json`) use the same shape:

```json
{
  "mcpServers": {
    "grafana-prod": {
      "command": "mcp-grafana-proxy",
      "args": ["exec", "--env", "prod"],
      "env": { "GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_..." }
    },
    "grafana-staging": {
      "command": "mcp-grafana-proxy",
      "args": ["exec", "--env", "staging", "--", "mcp-grafana", "--disable-write"],
      "env": { "GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_..." }
    }
  }
}
```

- The command after `--` defaults to `mcp-grafana`. Pass mcp-grafana's own flags there.
- Don't set `GRAFANA_URL`: the proxy sets it. All other mcp-grafana environment variables pass through.
- Without a config file, use `"args": ["exec", "--upstream", "https://grafana.example.com"]`.

### serve mode

Run one long-lived proxy per configured environment:

```sh
mcp-grafana-proxy serve              # all environments
mcp-grafana-proxy serve --env prod   # just one
```

Then point mcp-grafana at an environment's listen address:

```json
"grafana-prod": {
  "command": "mcp-grafana",
  "env": {
    "GRAFANA_URL": "http://127.0.0.1:18080",
    "GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_..."
  }
}
```

## Token modes

Every mode uses your gcloud login. Set the mode per environment with `auth.mode`.

| Mode | What it sends | Grafana's IAP header names | IAP requirement |
| --- | --- | --- | --- |
| `user` (default) | Your ID token from `gcloud auth print-identity-token` | you | Custom OAuth client, with gcloud's client ID allowlisted (see above) |
| `impersonate-id-token` | A service account ID token for the IAP client ID (`audience`) | the service account | Custom OAuth client; you need Service Account Token Creator on the account |
| `impersonate-jwt` | A JWT signed by a service account for `<upstream>/*` | the service account | Works with any OAuth client; you need Service Account Token Creator on the account |

Tokens are cached in memory, never on disk, and refreshed two minutes before they expire. Environments with identical `auth` settings share one cache in serve mode.

## Troubleshooting

Start with `mcp-grafana-proxy doctor`. It checks gcloud, shows the token's identity and audience (never the token itself), and asks IAP whether it accepts the token. If `GRAFANA_SERVICE_ACCOUNT_TOKEN` is set, it also checks that Grafana accepts that token.

| Error from a tool call | Fix |
| --- | --- |
| `could not obtain a Google IAP token: ... Reauthentication ...` | Run `gcloud auth login` (or `gcloud auth login <account>`). |
| `Google IAP rejected the request (HTTP 401): ... audience doesn't match ...` | gcloud's client ID is not allowlisted. See the one-time IAP setup. |
| `Google IAP rejected the request (HTTP 403)` | Your identity lacks the IAP-secured Web App User role. |
| `401` with Grafana's own message, such as `invalid API key` | `GRAFANA_SERVICE_ACCOUNT_TOKEN` is wrong or expired. |

- For request logs, set `MCP_GRAFANA_PROXY_LOG_LEVEL=debug` in the MCP server's `env`. Logs go to stderr, which your MCP client keeps with the server's logs.
- To try requests by hand, print the token:

  ```sh
  curl -H "Proxy-Authorization: Bearer $(mcp-grafana-proxy token --env prod)" \
       https://grafana.example.com/api/health
  ```

## Security

- The proxy listens on loopback only. Config validation rejects any other address.
- It refuses requests whose `Host` is not loopback (DNS rebinding), and any request carrying `Origin` or `Sec-Fetch-*` headers. Web pages therefore cannot use your identity through it.
- In exec mode, each launch generates a random secret. mcp-grafana sends it through `GRAFANA_EXTRA_HEADERS`; the proxy requires it, then strips it. Other local processes cannot use that proxy.
- gcloud never reads the proxy's stdin, which carries the MCP stream in exec mode, and it runs with prompts disabled.

## Development

```sh
go test -race ./...
go build ./cmd/mcp-grafana-proxy
```
