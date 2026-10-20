package token

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims holds the JWT claims the proxy reads. Signatures are never verified
// here; IAP does that. The proxy only needs expiry for caching and identity
// for diagnostics.
type Claims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Email    string   `json:"email"`
	Audience Audience `json:"aud"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
}

// ExpiresAt returns the exp claim as a time.
func (c Claims) ExpiresAt() time.Time { return time.Unix(c.Expiry, 0) }

// Identity returns the email claim, falling back to sub.
func (c Claims) Identity() string {
	if c.Email != "" {
		return c.Email
	}
	return c.Subject
}

// Audience accepts both the string and the array form of the aud claim.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	*a = list
	return nil
}

func (a Audience) String() string { return strings.Join(a, ",") }

// ParseClaims decodes the payload of a compact JWT without verifying it.
func ParseClaims(tok string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return Claims{}, fmt.Errorf("decode JWT payload: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, fmt.Errorf("parse JWT payload: %w", err)
	}
	if c.Expiry == 0 {
		return Claims{}, errors.New("JWT has no exp claim")
	}
	return c, nil
}
