package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

var ErrInvalidToken = errors.New("invalid token")

type KeySource interface {
	Key(ctx context.Context, kid string) (any, error)
}

type keySetSource struct {
	ks *KeySet
}

func (s keySetSource) Key(ctx context.Context, kid string) (any, error) {
	return s.ks.Key(ctx, kid)
}

func FromKeySet(ks *KeySet) KeySource {
	return keySetSource{ks: ks}
}

type VerifierOptions struct {
	Issuer     string
	Audiences  []string
	Algorithms []string
	Leeway     time.Duration
	Now        func() time.Time
}

type Verifier struct {
	keys   KeySource
	parser *jwt.Parser
}

func NewVerifier(keys KeySource, o VerifierOptions) *Verifier {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(o.Algorithms),
		jwt.WithIssuer(o.Issuer),
		jwt.WithAudience(o.Audiences...),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(o.Leeway),
		jwt.WithIssuedAt(),
		jwt.WithStrictDecoding(),
	}
	if o.Now != nil {
		opts = append(opts, jwt.WithTimeFunc(o.Now))
	}
	return &Verifier{keys: keys, parser: jwt.NewParser(opts...)}
}

func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:4])
}

func (v *Verifier) Verify(ctx context.Context, raw string) (identity.Principal, error) {
	var keyErr error
	claims := jwt.MapClaims{}
	_, err := v.parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("missing kid: %w", ErrInvalidToken)
		}
		k, err := v.keys.Key(ctx, kid)
		if err != nil {
			keyErr = err
		}
		return k, err
	})
	if err != nil {
		if keyErr != nil && errors.Is(keyErr, ErrKeysUnavailable) {
			return identity.Principal{}, keyErr
		}
		return identity.Principal{}, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	sub := claimString(claims, "sub")
	if sub == "" {
		return identity.Principal{}, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	iss := claimString(claims, "iss")
	clientID := claimString(claims, "client_id")
	if clientID == "" {
		clientID = claimString(claims, "azp")
	}
	return identity.Principal{
		Subject:     sub,
		ClientID:    clientID,
		Issuer:      iss,
		Scopes:      scopes(claims),
		Claims:      claims,
		Fingerprint: Fingerprint(raw),
	}, nil
}

func claimString(c jwt.MapClaims, k string) string {
	s, ok := c[k].(string)
	if !ok {
		return ""
	}
	return s
}

func scopes(c jwt.MapClaims) []string {
	if s, ok := c["scope"].(string); ok {
		return strings.Fields(s)
	}
	raw, ok := c["scp"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
