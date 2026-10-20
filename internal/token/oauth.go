package token

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ModeOAuthClient signs the user in with IAP's own OAuth client, then mints
// ID tokens for that client from a saved refresh token. IAP accepts tokens
// whose audience is its own client ID without any allowlist.
const ModeOAuthClient = "oauth-client"

const (
	googleAuthURL   = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL  = "https://oauth2.googleapis.com/token"
	googleRevokeURL = "https://oauth2.googleapis.com/revoke"
)

// ErrNotSignedIn is wrapped by credential stores that hold no sign-in yet.
var ErrNotSignedIn = errors.New("not signed in")

// CredentialStore keeps the refresh token from a sign-in.
type CredentialStore interface {
	// LoadRefreshToken returns an error wrapping ErrNotSignedIn when there
	// is no saved sign-in.
	LoadRefreshToken() (string, error)
	SaveRefreshToken(refreshToken, account string) error
}

// OAuthClient signs the user in through the browser (authorization code flow
// with PKCE), saves the refresh token, and then silently refreshes it into ID
// tokens whose audience is ClientID.
type OAuthClient struct {
	ClientID     string
	ClientSecret string
	Credentials  CredentialStore
	LoginHint    string // optional account to preselect at sign-in
	RedirectPort int    // Login's loopback port; 0 picks a free one

	AuthURL    string       // defaults to Google's
	TokenURL   string       // defaults to Google's
	RevokeURL  string       // defaults to Google's
	HTTPClient *http.Client // defaults to a client with a 30s timeout
}

// PKCE is a code verifier and its S256 challenge for one sign-in.
type PKCE struct {
	Verifier, Challenge string
}

// NewPKCE returns a fresh verifier and challenge.
func NewPKCE() PKCE {
	verifier := RandomString(32)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}
}

// AuthCodeURL returns the Google sign-in URL that redirects to redirectURI.
func (o *OAuthClient) AuthCodeURL(redirectURI, state string, pkce PKCE) string {
	q := url.Values{
		"client_id":             {o.ClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"access_type":           {"offline"},
		"prompt":                {"consent"}, // always return a refresh token
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	if o.LoginHint != "" {
		q.Set("login_hint", o.LoginHint)
	}
	return cmp.Or(o.AuthURL, googleAuthURL) + "?" + q.Encode()
}

// Exchange swaps an authorization code for a refresh token, saves it, and
// returns the claims of the accompanying ID token.
func (o *OAuthClient) Exchange(ctx context.Context, code, redirectURI string, pkce PKCE) (Claims, error) {
	tr, err := o.tokenRequest(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {pkce.Verifier},
	})
	if err != nil {
		return Claims{}, err
	}
	if tr.RefreshToken == "" {
		return Claims{}, errors.New("google returned no refresh token")
	}
	claims, err := ParseClaims(tr.IDToken)
	if err != nil {
		return Claims{}, err
	}
	return claims, o.Credentials.SaveRefreshToken(tr.RefreshToken, claims.Identity())
}

// Token exchanges the saved refresh token for a fresh ID token.
func (o *OAuthClient) Token(ctx context.Context) (string, error) {
	refreshToken, err := o.Credentials.LoadRefreshToken()
	if err != nil {
		return "", err
	}
	tr, err := o.tokenRequest(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		return "", err
	}
	return tr.IDToken, nil
}

// Revoke asks Google to invalidate a refresh token.
func (o *OAuthClient) Revoke(ctx context.Context, refreshToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cmp.Or(o.RevokeURL, googleRevokeURL),
		strings.NewReader(url.Values{"token": {refreshToken}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("google revoke returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (o *OAuthClient) httpClient() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Login runs the sign-in from a terminal: it waits for Google's redirect on a
// loopback port and saves the result. open is called with the sign-in URL
// (nil only prints it); instructions go to out.
func (o *OAuthClient) Login(ctx context.Context, open func(string) error, out io.Writer) (Claims, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", o.RedirectPort))
	if err != nil {
		return Claims{}, fmt.Errorf("listen for the sign-in redirect: %w", err)
	}
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/", ln.Addr().(*net.TCPAddr).Port)
	pkce, state := NewPKCE(), RandomString(16)
	authURL := o.AuthCodeURL(redirectURI, state, pkce)

	type result struct {
		code string
		err  error
	}
	results := make(chan result, 1)
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			code, err := CallbackCode(r.URL.Query(), state)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			} else {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = io.WriteString(w, signedInPage)
			}
			select {
			case results <- result{code, err}:
			default:
			}
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	fmt.Fprintf(out, "Sign in with your browser. If it does not open, visit:\n\n  %s\n\n", authURL)
	if open != nil {
		if err := open(authURL); err != nil {
			fmt.Fprintf(out, "Could not open a browser (%v); open the URL above yourself.\n", err)
		}
	}

	var res result
	select {
	case res = <-results:
	case <-ctx.Done():
		return Claims{}, fmt.Errorf("waiting for sign-in: %w", ctx.Err())
	}
	if res.err != nil {
		return Claims{}, res.err
	}
	return o.Exchange(ctx, res.code, redirectURI, pkce)
}

// CallbackCode validates the query of Google's redirect against the expected
// state and returns the authorization code.
func CallbackCode(q url.Values, state string) (string, error) {
	switch {
	case state == "" || q.Get("state") != state:
		return "", errors.New("the sign-in response did not match this sign-in attempt; try again")
	case q.Get("error") != "":
		return "", fmt.Errorf("sign-in failed: %s", q.Get("error"))
	case q.Get("code") == "":
		return "", errors.New("the sign-in response had no authorization code")
	}
	return q.Get("code"), nil
}

type tokenResponse struct {
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (o *OAuthClient) tokenRequest(ctx context.Context, form url.Values) (*tokenResponse, error) {
	form.Set("client_id", o.ClientID)
	form.Set("client_secret", o.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cmp.Or(o.TokenURL, googleTokenURL), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := o.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("google token request: %w", err)
	}
	defer resp.Body.Close()

	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return nil, fmt.Errorf("google token response (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || tr.Error != "" {
		reason := strings.TrimSpace(tr.Error + ": " + tr.ErrorDescription)
		if tr.Error == "invalid_grant" && form.Get("grant_type") == "refresh_token" {
			return nil, fmt.Errorf("%w: the saved sign-in is no longer valid (%s); sign in again", ErrNotSignedIn, reason)
		}
		return nil, fmt.Errorf("google token request failed (HTTP %d): %s", resp.StatusCode, reason)
	}
	if tr.IDToken == "" {
		return nil, errors.New("google returned no ID token")
	}
	return &tr, nil
}

// FileCredentials keeps the refresh token in a JSON file readable only by
// the user, like gcloud's own credential store.
type FileCredentials struct {
	Path string
}

type savedCredential struct {
	RefreshToken string    `json:"refresh_token"`
	Account      string    `json:"account,omitempty"`
	SavedAt      time.Time `json:"saved_at"`
}

func (f *FileCredentials) LoadRefreshToken() (string, error) {
	notSignedIn := fmt.Errorf("%w: run `mcp-grafana-proxy login` with the same --env or --upstream", ErrNotSignedIn)
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return "", notSignedIn
	}
	if err != nil {
		return "", err
	}
	var cred savedCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return "", fmt.Errorf("read %s: %w", f.Path, err)
	}
	if cred.RefreshToken == "" {
		return "", notSignedIn
	}
	return cred.RefreshToken, nil
}

func (f *FileCredentials) SaveRefreshToken(refreshToken, account string) error {
	data, err := json.MarshalIndent(savedCredential{RefreshToken: refreshToken, Account: account, SavedAt: time.Now()}, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(f.Path, data)
}

// WriteFileAtomic replaces path with data, readable only by the user, and
// creates its directory (also user-only) when needed.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ReadClientSecret reads an OAuth client secret from path. The file holds
// either the bare secret or a client JSON file downloaded from the Google
// Cloud console, whose client_id must then match clientID.
func ReadClientSecret(path, clientID string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	content := strings.TrimSpace(string(data))
	if !strings.HasPrefix(content, "{") {
		if content == "" {
			return "", fmt.Errorf("%s is empty", path)
		}
		return content, nil
	}

	var file struct {
		Installed *clientFields `json:"installed"`
		Web       *clientFields `json:"web"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	c := cmp.Or(file.Web, file.Installed)
	if c == nil || c.ClientSecret == "" {
		return "", fmt.Errorf("%s has no client_secret under \"web\" or \"installed\"", path)
	}
	if c.ClientID != "" && c.ClientID != clientID {
		return "", fmt.Errorf("%s is for client %s, not %s", path, c.ClientID, clientID)
	}
	return c.ClientSecret, nil
}

type clientFields struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// RandomString returns n random bytes, base64url-encoded.
func RandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

const signedInPage = `<!doctype html><meta charset="utf-8"><title>Signed in</title>
<body style="font-family:system-ui,sans-serif;margin:3rem">
<h1>Signed in</h1><p>mcp-grafana-proxy has your sign-in. You can close this tab.</p></body>`
