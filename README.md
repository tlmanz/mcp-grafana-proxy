# mcp-grafana-proxy

A local proxy that lets the official [Grafana MCP server](https://github.com/grafana/mcp-grafana) (`mcp-grafana`) reach Grafana instances protected by Google Identity-Aware Proxy (IAP). You add your environments in a small web UI and sign in there once. mcp-grafana, Grafana and your MCP client stay unmodified.

```
Browser ───► UI          127.0.0.1:8090    add environments, sign in, test, copy MCP config
Claude / Cursor
   │ stdio (MCP)
   ▼
mcp-grafana            GRAFANA_URL=http://127.0.0.1:18080/<environment>
   ▼
mcp-grafana-proxy      127.0.0.1:18080   one port, one path per environment
   │  + Proxy-Authorization: Bearer <Google ID token for IAP's own OAuth client>
   │  + Authorization: Bearer <Grafana service account token>, if you saved one
   ▼
Google IAP ──► Grafana
```

## How it works

IAP accepts an ID token only when its audience is IAP's own OAuth client, or a client from your organization listed in IAP's `programmatic_clients`. A token from `gcloud auth print-identity-token` has gcloud's audience, and IAP refuses to list gcloud's client because it is not in your organization.

So the proxy signs you in with **IAP's own OAuth client**: the same client ID and secret IAP uses for the browser. Google then issues ID tokens with exactly the audience IAP expects, and IAP sees your own identity. You sign in once; the proxy keeps the refresh token and mints fresh ID tokens silently.

The ID token goes in `Proxy-Authorization`. IAP authorizes the request with it and passes `Authorization` through untouched, so Grafana still receives its own service account token.

## Quick start (Docker)

### 1. Register the redirect URI (once per OAuth client)

In the Google Cloud console for the project that owns IAP's OAuth client, open **Google Auth Platform > Clients**, select the client, and add this to **Authorized redirect URIs**:

```
http://127.0.0.1:8090/oauth/callback
```

Google can take a few minutes to apply it. Until then, sign-in fails with `redirect_uri_mismatch`.

You need IAP's OAuth **client ID** and **client secret**:

- The client ID is the `clientID` in the backend's `GCPBackendPolicy`. `mcp-grafana-proxy doctor --upstream <grafana-url>` and the UI's **Test** button also print it.
- The secret is in the Kubernetes Secret named by `oauth2ClientSecret` in that policy. Ask whoever manages IAP if you can't read it.

### 2. Create the encryption key and start

```sh
echo "MCP_GRAFANA_PROXY_KEY=$(openssl rand -base64 32)" > .env && chmod 600 .env
docker compose up -d --build
```

The key encrypts everything the UI stores. Keep `.env` out of git and back it up: without it the stored settings can't be decrypted, and you'd have to enter them again.

### 3. Add an environment and sign in

Open <http://127.0.0.1:8090> and click **Add environment**:

| Field | Example |
| --- | --- |
| Name | `dev` (becomes the path: `/dev`) |
| Grafana URL | `https://grafana.dev.example.com` |
| IAP OAuth client ID | `1234-abc.apps.googleusercontent.com` |
| OAuth client secret | the client's secret |
| Google account (optional) | preselected at sign-in |
| Grafana service account token (optional) | `glsa_...`; sent to Grafana when mcp-grafana sends none |

Then click **Sign in** and finish in Google. Click **Test**: you should see `IAP accepted the token; Grafana ... is healthy`.

### 4. Point your MCP client at it

**Copy MCP config** on each environment gives you this (Claude Code: `.mcp.json` or `~/.claude.json`; Cursor: `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "grafana-dev": {
      "command": "mcp-grafana",
      "env": { "GRAFANA_URL": "http://127.0.0.1:18080/dev" }
    }
  }
}
```

If you didn't save a Grafana token in the UI, add `"GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_..."` to `env`. A token sent by mcp-grafana always wins over the saved one.

## Security

- **Loopback only.** `docker-compose.yml` publishes both ports on `127.0.0.1`. The UI and the proxy refuse any request whose `Host` isn't a loopback address, which blocks DNS rebinding.
- **No browser access to the proxy.** Requests carrying `Origin` or `Sec-Fetch-*` headers are refused, so web pages can't use your identity through it.
- **UI hardening.** API calls need a CSRF token and a same-origin request. The page sets a strict Content-Security-Policy, can't be framed, and sends no referrer.
- **Encrypted at rest.** Client secrets, Grafana tokens and refresh tokens live in one AES-256-GCM encrypted file (`/data/store.enc`). The key stays outside the volume.
- **Secrets stay write-only.** The UI never sends them back to the browser.
- **Sign out revokes.** Signing out or deleting an environment revokes the refresh token at Google.
- **Shared secret.** IAP's OAuth client secret now lives (encrypted) on your machine. Anyone with your `.env` key and the volume could use it, so treat both as sensitive.
- **Access levels.** If IAP enforces access level (context-aware) policies, Google doesn't support the refresh-token flow, and you'll need to sign in again when tokens expire.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Sign-in shows `redirect_uri_mismatch` | Add `http://127.0.0.1:8090/oauth/callback` to the client's Authorized redirect URIs, then wait a few minutes. |
| Tool calls fail with `not signed in` | Click **Sign in** for that environment. |
| `the saved sign-in is no longer valid` | The refresh token expired or was revoked. Sign in again. |
| `Google IAP rejected the request (HTTP 401)` | Click **Test**. It shows IAP's verdict and IAP's real client ID, and the client ID you saved must match it. |
| `Google IAP rejected the request (HTTP 403)` | Your account lacks the IAP-secured Web App User role on that resource. |
| `401` with Grafana's own message, such as `invalid API key` | The Grafana service account token is wrong or expired. |
| `no environment "x"` | The path in `GRAFANA_URL` must match an environment name in the UI. |
| UI unreachable although the container is running | A VPN may route Docker's subnet away (check `ip route get <container IP>`). The compose file uses Docker's default `bridge` network to avoid this. |

For request logs, set `MCP_GRAFANA_PROXY_LOG_LEVEL=debug` in `docker-compose.yml` and run `docker compose logs -f`.

## Without Docker

Install the binary:

```sh
go install github.com/tlmanz/mcp-grafana-proxy/cmd/mcp-grafana-proxy@latest
```

Run the same UI natively:

```sh
export MCP_GRAFANA_PROXY_KEY=$(mcp-grafana-proxy keygen)   # store it somewhere safe
mcp-grafana-proxy ui
```

The binary also has a config-file mode with no UI:

| Command | What it does |
| --- | --- |
| `exec --env <name> [-- mcp-grafana ...]` | Used as the MCP server command. Starts a private proxy on a free port, then runs mcp-grafana pointed at it. |
| `serve` | Long-running proxy, one port per environment in the config file. |
| `login --env <name>` | Browser sign-in for `mode: oauth-client` environments. Register `http://127.0.0.1:18085/` on the client for this. |
| `doctor` | Checks the token's identity and audience, and whether IAP and Grafana accept it. |
| `token` | Prints the IAP token, for testing with curl. |

[config.example.yaml](config.example.yaml) documents the config file. Its token modes:

| Mode | Token | Works when |
| --- | --- | --- |
| `oauth-client` | Your ID token for IAP's own client (`client_id`, `client_secret_file`) | Always, once the redirect URI is registered |
| `impersonate-jwt` | A JWT signed by a service account for `<upstream>/*` | You have Service Account Token Creator on an account with IAP access |
| `impersonate-id-token` | A service account ID token for IAP's client ID | As above, with a custom OAuth client |
| `user` (default) | Your `gcloud auth print-identity-token` | Rarely: IAP must accept gcloud's client, which it refuses for resources in an organization |

## Development

```sh
go test -race ./...
docker build -t mcp-grafana-proxy:local .
```
