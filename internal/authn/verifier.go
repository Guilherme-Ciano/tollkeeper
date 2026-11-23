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
	Types      []string
	Issuer     string
	Audiences  []string
	Algorithms []string
	Leeway     time.Duration
	Claims     ClaimMapping
	Now        func() time.Time
}

type Verifier struct {
	keys   KeySource
	parser *jwt.Parser
	types  []string
	claims ClaimMapping
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
	return &Verifier{
		keys:   keys,
		parser: jwt.NewParser(opts...),
		types:  o.Types,
		claims: ResolveClaimMapping("", o.Claims),
	}
}

func Fingerprint(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:4])
}

func (v *Verifier) Verify(ctx context.Context, raw string) (identity.Principal, error) {
	var keyErr error
	claims := jwt.MapClaims{}
	_, err := v.parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if !v.typeAllowed(t) {
			return nil, fmt.Errorf("token typ not accepted: %w", ErrInvalidToken)
		}
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
	clientID := extractStringClaim(claims, v.claims.ClientIDClaim, "client_id", "azp", "appid", "cid")
	tenant := extractStringClaim(claims, v.claims.TenantClaim, "tenant_id", "tid", "org_id")
	tokenScopes := scopesWithMapping(claims, v.claims.ScopeClaim)
	return identity.Principal{
		Subject:         sub,
		ClientID:        clientID,
		Issuer:          iss,
		Tenant:          tenant,
		Actor:           parseActor(claims["act"], 0),
		Scopes:          tokenScopes,
		Roles:           extractStringSliceClaim(claims, v.claims.RolesClaim),
		Groups:          extractStringSliceClaim(claims, v.claims.GroupsClaim),
		ACR:             claimString(claims, "acr"),
		AMR:             extractStringSliceClaim(claims, "amr"),
		AuthTime:        extractAuthTime(claims),
		TokenThumbprint: extractConfirmationJKT(claims),
		Claims:          claims,
		Fingerprint:     Fingerprint(raw),
	}, nil
}

const maxActorDepth = 8

func mapString(m map[string]any, k string) string {
	s, ok := m[k].(string)
	if !ok {
		return ""
	}
	return s
}

func parseActor(raw any, depth int) *identity.Actor {
	if raw == nil || depth >= maxActorDepth {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	sub := mapString(m, "sub")
	if sub == "" {
		return nil
	}
	clientID := mapString(m, "client_id")
	if clientID == "" {
		clientID = mapString(m, "azp")
	}
	return &identity.Actor{
		Subject:  sub,
		ClientID: clientID,
		Issuer:   mapString(m, "iss"),
		Actor:    parseActor(m["act"], depth+1),
	}
}

func scopesWithMapping(c jwt.MapClaims, claimPath string) []string {
	if claimPath != "" {
		if got := extractStringSliceClaim(c, claimPath); len(got) > 0 {
			return got
		}
	}
	return scopes(c)
}

func (v *Verifier) typeAllowed(t *jwt.Token) bool {
	if len(v.types) == 0 {
		return true
	}
	typ, ok := t.Header["typ"].(string)
	if !ok {
		return false
	}
	typ = strings.TrimPrefix(strings.ToLower(typ), "application/")
	for _, want := range v.types {
		if strings.TrimPrefix(strings.ToLower(want), "application/") == typ {
			return true
		}
	}
	return false
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
