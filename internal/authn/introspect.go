package authn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

const (
	maxIntrospectionBody = 64 << 10
	negativeCacheTTL     = 10 * time.Second
)

var ErrIntrospectionUnavailable = fmt.Errorf("introspection endpoint unavailable: %w", ErrKeysUnavailable)

type IntrospectorOptions struct {
	URL          string
	ClientID     string
	ClientSecret string
	Issuer       string
	Audiences    []string
	CacheTTL     time.Duration
	MaxEntries   int
	Leeway       time.Duration
	Client       *http.Client
	Now          func() time.Time
}

type cached struct {
	p       identity.Principal
	err     error
	expires time.Time
}

type Introspector struct {
	o     IntrospectorOptions
	mu    sync.Mutex
	cache map[[32]byte]cached
	group singleflight.Group
}

func NewIntrospector(o IntrospectorOptions) *Introspector {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 10000
	}
	if o.Client == nil {
		o.Client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Introspector{o: o, cache: map[[32]byte]cached{}}
}

type introspection struct {
	Active    bool            `json:"active"`
	Sub       string          `json:"sub"`
	Username  string          `json:"username"`
	ClientID  string          `json:"client_id"`
	Scope     string          `json:"scope"`
	Aud       json.RawMessage `json:"aud"`
	Iss       string          `json:"iss"`
	Exp       int64           `json:"exp"`
	Nbf       int64           `json:"nbf"`
	TokenType string          `json:"token_type"`
}

func (in *introspection) audiences() []string {
	var one string
	if json.Unmarshal(in.Aud, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(in.Aud, &many) == nil {
		return many
	}
	return nil
}

func (i *Introspector) Verify(ctx context.Context, raw string) (identity.Principal, error) {
	key := sha256.Sum256([]byte(raw))
	now := i.o.Now()
	i.mu.Lock()
	c, ok := i.cache[key]
	i.mu.Unlock()
	if ok && now.Before(c.expires) {
		return c.p, c.err
	}
	v, err, _ := i.group.Do(string(key[:]), func() (any, error) {
		p, ttl, err := i.introspect(context.WithoutCancel(ctx), raw)
		if errors.Is(err, ErrKeysUnavailable) {
			return nil, err
		}
		i.store(key, cached{p: p, err: err, expires: i.o.Now().Add(ttl)})
		return cached{p: p, err: err}, nil
	})
	if err != nil {
		return identity.Principal{}, fmt.Errorf("introspect: %w", err)
	}
	res, ok := v.(cached)
	if !ok {
		return identity.Principal{}, ErrIntrospectionUnavailable
	}
	return res.p, res.err
}

func (i *Introspector) store(key [32]byte, c cached) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.cache) >= i.o.MaxEntries {
		now := i.o.Now()
		for k := range i.cache {
			if !now.Before(i.cache[k].expires) {
				delete(i.cache, k)
			}
		}
		for k := range i.cache {
			if len(i.cache) < i.o.MaxEntries {
				break
			}
			delete(i.cache, k)
		}
	}
	i.cache[key] = c
}

func (i *Introspector) introspect(ctx context.Context, raw string) (identity.Principal, time.Duration, error) {
	form := url.Values{"token": {raw}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.o.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return identity.Principal{}, 0, fmt.Errorf("%w: %w", ErrIntrospectionUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(i.o.ClientID), url.QueryEscape(i.o.ClientSecret))
	resp, err := i.o.Client.Do(req)
	if err != nil {
		return identity.Principal{}, 0, fmt.Errorf("%w: %w", ErrIntrospectionUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionBody+1))
	if err != nil || len(body) > maxIntrospectionBody {
		return identity.Principal{}, 0, fmt.Errorf("%w: unreadable response", ErrIntrospectionUnavailable)
	}
	if resp.StatusCode != http.StatusOK {
		return identity.Principal{}, 0, fmt.Errorf("%w: status %d", ErrIntrospectionUnavailable, resp.StatusCode)
	}
	var in introspection
	if err := json.Unmarshal(body, &in); err != nil {
		return identity.Principal{}, 0, fmt.Errorf("%w: malformed response", ErrIntrospectionUnavailable)
	}
	p, err := i.principal(&in, raw)
	if err != nil {
		return identity.Principal{}, negativeCacheTTL, err
	}
	ttl := i.o.CacheTTL
	if in.Exp > 0 {
		ttl = min(ttl, time.Unix(in.Exp, 0).Sub(i.o.Now()))
	}
	return p, max(ttl, 0), nil
}

func (i *Introspector) principal(in *introspection, raw string) (identity.Principal, error) {
	now := i.o.Now()
	switch {
	case !in.Active:
		return identity.Principal{}, fmt.Errorf("%w: inactive", ErrInvalidToken)
	case in.Exp > 0 && !now.Before(time.Unix(in.Exp, 0).Add(i.o.Leeway)):
		return identity.Principal{}, fmt.Errorf("%w: expired", ErrInvalidToken)
	case in.Nbf > 0 && now.Add(i.o.Leeway).Before(time.Unix(in.Nbf, 0)):
		return identity.Principal{}, fmt.Errorf("%w: not yet valid", ErrInvalidToken)
	case i.o.Issuer != "" && in.Iss != i.o.Issuer:
		return identity.Principal{}, fmt.Errorf("%w: issuer", ErrInvalidToken)
	case !slices.ContainsFunc(in.audiences(), func(a string) bool { return slices.Contains(i.o.Audiences, a) }):
		return identity.Principal{}, fmt.Errorf("%w: audience", ErrInvalidToken)
	case in.TokenType != "" && !strings.EqualFold(in.TokenType, "Bearer") &&
		!strings.EqualFold(in.TokenType, "access_token"):
		return identity.Principal{}, fmt.Errorf("%w: token_type %q", ErrInvalidToken, in.TokenType)
	}
	sub := in.Sub
	if sub == "" {
		return identity.Principal{}, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	claims := map[string]any{"sub": sub, "iss": in.Iss, "client_id": in.ClientID, "scope": in.Scope}
	if in.Username != "" {
		claims["username"] = in.Username
	}
	return identity.Principal{
		Subject:     sub,
		ClientID:    in.ClientID,
		Issuer:      in.Iss,
		Scopes:      strings.Fields(in.Scope),
		Claims:      claims,
		Fingerprint: Fingerprint(raw),
	}, nil
}
