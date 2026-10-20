package token

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Source mints a token that IAP accepts.
type Source interface {
	Token(ctx context.Context) (string, error)
}

const (
	// DefaultMargin is how long before expiry a cached token is replaced.
	DefaultMargin = 2 * time.Minute

	// minReuse bounds how often the source is called when it keeps returning
	// tokens that are already inside the margin.
	minReuse = 30 * time.Second
)

// Cache wraps a Source and reuses its token until shortly before expiry.
// Concurrent callers wait for a single refresh instead of each calling the
// source.
type Cache struct {
	src    Source
	margin time.Duration
	now    func() time.Time

	mu        sync.Mutex
	tok       string
	refreshAt time.Time
}

// NewCache returns a Cache around src.
func NewCache(src Source) *Cache {
	return &Cache{src: src, margin: DefaultMargin, now: time.Now}
}

// Token returns the cached token, minting a new one when needed.
func (c *Cache) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if c.tok != "" && now.Before(c.refreshAt) {
		return c.tok, nil
	}

	// The refresh is shared by every waiting caller, so one caller going away
	// must not abort it. The source applies its own timeout.
	tok, err := c.src.Token(context.WithoutCancel(ctx))
	if err != nil {
		return "", err
	}
	claims, err := ParseClaims(tok)
	if err != nil {
		return "", err
	}
	exp := claims.ExpiresAt()
	remaining := exp.Sub(now)
	if remaining <= 0 {
		return "", fmt.Errorf("token source returned a token that expired at %s", exp.Format(time.RFC3339))
	}

	// Refresh ahead of expiry. If the source hands back a token that is
	// already inside the margin, keep it briefly rather than calling the
	// source on every request.
	refreshAt := exp.Add(-c.margin)
	if floor := now.Add(min(minReuse, remaining/2)); refreshAt.Before(floor) {
		refreshAt = floor
	}
	c.tok, c.refreshAt = tok, refreshAt
	return tok, nil
}

// Invalidate drops tok if it is still the cached token, so the next call
// mints a fresh one.
func (c *Cache) Invalidate(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok == tok {
		c.tok = ""
	}
}

// Prewarm fetches a token so the first proxied request does not wait for the
// source. Failures are only logged: requests will retry and report them.
func (c *Cache) Prewarm(ctx context.Context, log *slog.Logger) {
	tok, err := c.Token(ctx)
	if err != nil {
		log.Warn("could not fetch IAP token yet", "error", err)
		return
	}
	if claims, err := ParseClaims(tok); err == nil {
		log.Info("IAP token ready", "identity", claims.Identity(), "expires", claims.ExpiresAt().Format(time.RFC3339))
	}
}
