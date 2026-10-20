// Package proxy is the reverse proxy that adds a Google IAP token to
// mcp-grafana's requests.
package proxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SecretHeader carries the per-launch shared secret from mcp-grafana to the
// proxy. The proxy checks and strips it, so it never reaches IAP or Grafana.
const SecretHeader = "X-Mcp-Grafana-Proxy-Key"

// iapGeneratedHeader marks responses produced by IAP itself rather than by
// Grafana.
const iapGeneratedHeader = "X-Goog-Iap-Generated-Response"

// TokenSource supplies IAP tokens. *token.Cache implements it.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
	Invalidate(token string)
}

// Options configures New.
type Options struct {
	Upstream  *url.URL
	Tokens    TokenSource
	Secret    string            // optional; required on every request when set
	Transport http.RoundTripper // optional; defaults to http.DefaultTransport
	Logger    *slog.Logger
}

type tokenKey struct{}

type handler struct {
	upstream *url.URL
	tokens   TokenSource
	secret   string
	log      *slog.Logger
	rp       *httputil.ReverseProxy
}

// New returns a handler that forwards requests to opts.Upstream with an IAP
// token in the Proxy-Authorization header. The client's Authorization header
// (mcp-grafana's Grafana credentials) passes through untouched.
func New(opts Options) http.Handler {
	h := &handler{
		upstream: opts.Upstream,
		tokens:   opts.Tokens,
		secret:   opts.Secret,
		log:      opts.Logger,
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	h.rp = &httputil.ReverseProxy{
		// Rewrite, not Director: Proxy-Authorization is a hop-by-hop header,
		// and ReverseProxy strips those after Director runs but before
		// Rewrite runs.
		Rewrite:        h.rewrite,
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.handleError,
		Transport:      opts.Transport,
		FlushInterval:  -1,
		ErrorLog:       slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
	}
	return h
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.serve(rec, r)
	h.log.Debug("request", "method", r.Method, "path", r.URL.Path,
		"status", rec.status, "duration", time.Since(start).Round(time.Millisecond))
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	// A loopback Host defeats DNS rebinding, and refusing browser requests
	// stops web pages from using the user's identity through the proxy.
	if !isLoopbackHost(r.Host) {
		writeError(w, http.StatusForbidden, "mcp-grafana-proxy only accepts requests addressed to a loopback host")
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Sec-Fetch-Mode") != "" {
		writeError(w, http.StatusForbidden, "mcp-grafana-proxy does not accept browser requests")
		return
	}
	if h.secret != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get(SecretHeader)), []byte(h.secret)) != 1 {
		writeError(w, http.StatusUnauthorized, "missing or invalid "+SecretHeader+" header")
		return
	}

	tok, err := h.tokens.Token(r.Context())
	if err != nil {
		h.log.Warn("could not obtain IAP token", "error", err)
		writeError(w, http.StatusBadGateway, "mcp-grafana-proxy could not obtain a Google IAP token: "+err.Error())
		return
	}
	h.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, tok)))
}

func (h *handler) rewrite(pr *httputil.ProxyRequest) {
	pr.SetURL(h.upstream)
	pr.Out.Header.Del(SecretHeader)
	tok, _ := pr.In.Context().Value(tokenKey{}).(string)
	pr.Out.Header.Set("Proxy-Authorization", "Bearer "+tok)
}

func (h *handler) modifyResponse(resp *http.Response) error {
	if status, ok := IAPFailure(resp); ok {
		if status == http.StatusUnauthorized {
			tok, _ := resp.Request.Context().Value(tokenKey{}).(string)
			h.tokens.Invalidate(tok)
		}
		msg := IAPFailureMessage(resp, status) + " Run `mcp-grafana-proxy doctor` to check the token's identity and audience."
		h.log.Warn("IAP rejected request", "path", resp.Request.URL.Path, "status", resp.StatusCode, "detail", msg)
		replaceBody(resp, status, msg)
		return nil
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		resp.Header.Set("Location", h.rewriteLocation(loc))
	}
	return nil
}

func (h *handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if !errors.Is(err, context.Canceled) {
		h.log.Warn("upstream request failed", "path", r.URL.Path, "error", err)
	}
	writeError(w, http.StatusBadGateway, fmt.Sprintf("mcp-grafana-proxy: request to %s failed: %v", h.upstream.Host, err))
}

// rewriteLocation maps redirects that point at the upstream back onto the
// proxy. mcp-grafana refuses cross-origin redirects, so an absolute upstream
// URL would otherwise fail.
func (h *handler) rewriteLocation(loc string) string {
	u, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	if u.Host != "" {
		if !strings.EqualFold(u.Host, h.upstream.Host) || (u.Scheme != "" && u.Scheme != h.upstream.Scheme) {
			return loc
		}
	} else if !strings.HasPrefix(u.Path, "/") {
		return loc // relative to the current path; already correct
	}

	path := u.Path
	if base := h.upstream.Path; base != "" {
		if path != base && !strings.HasPrefix(path, base+"/") {
			return loc // outside the proxied prefix
		}
		path = strings.TrimPrefix(path, base)
		if path == "" {
			path = "/"
		}
	}
	return (&url.URL{Path: path, RawQuery: u.RawQuery, Fragment: u.Fragment}).String()
}

// IAPFailure reports whether resp is IAP refusing the request, and the status
// to report for it. A redirect to Google sign-in means IAP did not accept the
// token, so it is reported as 401.
func IAPFailure(resp *http.Response) (status int, ok bool) {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if u, err := url.Parse(resp.Header.Get("Location")); err == nil && u.Host == "accounts.google.com" {
			return http.StatusUnauthorized, true
		}
	}
	if resp.Header.Get(iapGeneratedHeader) == "true" &&
		(resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		return resp.StatusCode, true
	}
	return 0, false
}

// IAPFailureMessage explains an IAP failure, including IAP's own plain-text
// reason when it gave one. It reads resp.Body.
func IAPFailureMessage(resp *http.Response, status int) string {
	var b strings.Builder
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		b.WriteString("Google IAP redirected to Google sign-in, so it did not accept the token")
	} else {
		fmt.Fprintf(&b, "Google IAP rejected the request (HTTP %d)", resp.StatusCode)
		if detail := plainTextSnippet(resp); detail != "" {
			b.WriteString(": ")
			b.WriteString(detail)
		}
	}
	b.WriteString(". ")
	if status == http.StatusForbidden {
		b.WriteString("The token was valid, but this identity lacks access: it needs the IAP-secured Web App User role on this resource.")
	} else {
		b.WriteString("In user mode, IAP must allowlist the token's audience (gcloud's OAuth client ID) for programmatic access.")
	}
	return b.String()
}

func plainTextSnippet(resp *http.Response) string {
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		return ""
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "html") {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return strings.Join(strings.Fields(string(b)), " ")
}

// replaceBody swaps resp for a Grafana-style JSON error, which mcp-grafana
// shows to the model instead of IAP's page.
func replaceBody(resp *http.Response, status int, msg string) {
	body, _ := json.Marshal(errorBody{Message: msg})
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.StatusCode = status
	resp.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
	resp.Header = http.Header{
		"Content-Type":   {"application/json"},
		"Content-Length": {strconv.Itoa(len(body))},
	}
	resp.Trailer = nil
}

type errorBody struct {
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Message: msg})
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// statusRecorder captures the response status for logging. Unwrap lets
// http.ResponseController reach the underlying writer for flushing and
// connection upgrades.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader && code >= 200 {
		r.status, r.wroteHeader = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
