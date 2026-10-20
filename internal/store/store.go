// Package store keeps the UI's environments, client secrets, Grafana tokens
// and sign-ins in a single AES-256-GCM encrypted file.
package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tlmanz/mcp-grafana-proxy/internal/token"
)

// KeyEnvVar holds the base64 encryption key when no key file is given.
const KeyEnvVar = "MCP_GRAFANA_PROXY_KEY"

const keySize = 32 // AES-256

// magic starts every store file and is authenticated with the ciphertext.
var magic = []byte("MGPSTORE1")

// Environment is one Grafana instance behind IAP.
type Environment struct {
	Name         string    `json:"name"`
	Upstream     string    `json:"upstream"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	Account      string    `json:"account,omitempty"`
	GrafanaToken string    `json:"grafana_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	SignedInAs   string    `json:"signed_in_as,omitempty"`
	SignedInAt   time.Time `json:"signed_in_at,omitzero"`
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Validate checks e and normalizes its upstream URL.
func (e *Environment) Validate() error {
	if !namePattern.MatchString(e.Name) {
		return errors.New("name must be lowercase letters, digits and dashes (it becomes the URL path)")
	}
	u, err := url.Parse(strings.TrimSpace(e.Upstream))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("Grafana URL must be an http(s) URL without credentials, query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	e.Upstream = u.String()
	e.ClientID = strings.TrimSpace(e.ClientID)
	if e.ClientID == "" || strings.ContainsAny(e.ClientID, " /\\") {
		return errors.New("a valid OAuth client ID is required")
	}
	if e.ClientSecret == "" {
		return errors.New("the OAuth client secret is required")
	}
	return nil
}

type fileData struct {
	Version      int           `json:"version"`
	Environments []Environment `json:"environments"`
}

// Store is safe for concurrent use.
type Store struct {
	path string
	aead cipher.AEAD

	mu       sync.RWMutex
	envs     map[string]Environment
	onChange []func()
}

// Open loads the store at path, or starts an empty one if it does not exist.
func Open(path string, key []byte) (*Store, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("encryption key must be %d bytes, got %d", keySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, aead: aead, envs: map[string]Environment{}}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.decrypt(raw)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	var data fileData
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	for _, env := range data.Environments {
		s.envs[env.Name] = env
	}
	return s, nil
}

// List returns all environments sorted by name.
func (s *Store) List() []Environment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	envs := make([]Environment, 0, len(s.envs))
	for _, env := range s.envs {
		envs = append(envs, env)
	}
	slices.SortFunc(envs, func(a, b Environment) int { return strings.Compare(a.Name, b.Name) })
	return envs
}

// Get returns the named environment.
func (s *Store) Get(name string) (Environment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	env, ok := s.envs[name]
	return env, ok
}

// Update applies fn to the named environment, or to a new one with that name
// when create is true and none exists, then validates and saves it.
func (s *Store) Update(name string, create bool, fn func(*Environment) error) error {
	err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		env, ok := s.envs[name]
		if !ok && !create {
			return fmt.Errorf("no environment named %q", name)
		}
		if !ok {
			env = Environment{Name: name}
		}
		if err := fn(&env); err != nil {
			return err
		}
		env.Name = name
		if err := env.Validate(); err != nil {
			return err
		}
		old, existed := s.envs[name]
		s.envs[name] = env
		if err := s.persistLocked(); err != nil {
			if existed {
				s.envs[name] = old
			} else {
				delete(s.envs, name)
			}
			return err
		}
		return nil
	}()
	if err == nil {
		s.notify()
	}
	return err
}

// Delete removes the named environment.
func (s *Store) Delete(name string) error {
	err := func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		old, ok := s.envs[name]
		if !ok {
			return fmt.Errorf("no environment named %q", name)
		}
		delete(s.envs, name)
		if err := s.persistLocked(); err != nil {
			s.envs[name] = old
			return err
		}
		return nil
	}()
	if err == nil {
		s.notify()
	}
	return err
}

// OnChange registers fn to run after every successful change.
func (s *Store) OnChange(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, fn)
}

func (s *Store) notify() {
	s.mu.RLock()
	fns := slices.Clone(s.onChange)
	s.mu.RUnlock()
	for _, fn := range fns {
		fn()
	}
}

// Credentials returns a token.CredentialStore that keeps the named
// environment's sign-in in this store.
func (s *Store) Credentials(name string) token.CredentialStore {
	return envCredentials{s: s, name: name}
}

type envCredentials struct {
	s    *Store
	name string
}

func (c envCredentials) LoadRefreshToken() (string, error) {
	env, ok := c.s.Get(c.name)
	if !ok || env.RefreshToken == "" {
		return "", fmt.Errorf("%w: sign in to environment %q in the mcp-grafana-proxy UI", token.ErrNotSignedIn, c.name)
	}
	return env.RefreshToken, nil
}

func (c envCredentials) SaveRefreshToken(refreshToken, account string) error {
	return c.s.Update(c.name, false, func(env *Environment) error {
		env.RefreshToken, env.SignedInAs, env.SignedInAt = refreshToken, account, time.Now()
		return nil
	})
}

func (s *Store) persistLocked() error {
	data := fileData{Version: 1, Environments: make([]Environment, 0, len(s.envs))}
	for _, env := range s.envs {
		data.Environments = append(data.Environments, env)
	}
	slices.SortFunc(data.Environments, func(a, b Environment) int { return strings.Compare(a.Name, b.Name) })
	plain, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return token.WriteFileAtomic(s.path, s.encrypt(plain))
}

// File layout: magic | nonce | AES-GCM(plaintext), with magic as associated data.
func (s *Store) encrypt(plain []byte) []byte {
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce)
	out := append(slices.Clone(magic), nonce...)
	return s.aead.Seal(out, nonce, plain, magic)
}

func (s *Store) decrypt(raw []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, magic) || len(raw) < len(magic)+s.aead.NonceSize() {
		return nil, errors.New("not an mcp-grafana-proxy store file")
	}
	rest := raw[len(magic):]
	nonce, ciphertext := rest[:s.aead.NonceSize()], rest[s.aead.NonceSize():]
	plain, err := s.aead.Open(nil, nonce, ciphertext, magic)
	if err != nil {
		return nil, errors.New("cannot decrypt the store: wrong encryption key, or the file is damaged")
	}
	return plain, nil
}

// NewKey returns a new random key, base64-encoded.
func NewKey() string {
	key := make([]byte, keySize)
	_, _ = rand.Read(key)
	return base64.StdEncoding.EncodeToString(key)
}

// LoadKey reads the base64 key from keyFile, or from $MCP_GRAFANA_PROXY_KEY
// when keyFile is empty.
func LoadKey(keyFile string) ([]byte, error) {
	encoded := os.Getenv(KeyEnvVar)
	source := "$" + KeyEnvVar
	if keyFile != "" {
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("read key file: %w", err)
		}
		encoded, source = string(raw), keyFile
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("no encryption key: set %s or pass --key-file (create one with `mcp-grafana-proxy keygen`)", KeyEnvVar)
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	problem := ""
	switch {
	case err != nil:
		problem = "it is not valid base64"
	case len(key) != keySize:
		problem = fmt.Sprintf("it decodes to %d bytes", len(key))
	default:
		return key, nil
	}
	return nil, fmt.Errorf("%s must hold a base64-encoded %d-byte key, but %s (create one with `mcp-grafana-proxy keygen` or `openssl rand -base64 32`)",
		source, keySize, problem)
}
