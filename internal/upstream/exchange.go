package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/sync/singleflight"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

const (
	RFC8693GrantType  = "urn:ietf:params:oauth:grant-type:token-exchange"
	RFC8693AccessType = "urn:ietf:params:oauth:token-type:access_token"
	RFC8693JWTType    = "urn:ietf:params:oauth:token-type:jwt"

	defaultExchangeTimeout  = 10 * time.Second
	defaultExchangeCacheTTL = 5 * time.Minute
	exchangeExpirySkew      = 30 * time.Second
	maxExchangeCacheEntries = 4096
	maxExchangeBodyBytes    = 64 << 10
)

var (
	ErrTokenExchange    = errors.New("oauth token exchange failed")
	ErrDelegationDenied = errors.New("delegation denied by upstream policy")
)

type exchangedEntry struct {
	token   string
	expires time.Time
}

type tokenExchangeResp struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

type TokenExchanger struct {
	tokenURL           string
	clientID           string
	clientSecret       string
	resource           string
	audience           string
	scopes             []string
	subjectTokenType   string
	requestedTokenType string
	actorToken         string
	actorTokenType     string
	intersectScopes    bool
	maxDelegationDepth int
	allowedIssuers     []string
	cacheTTL           time.Duration
	client             *http.Client
	now                func() time.Time

	mu    sync.Mutex
	cache map[[32]byte]exchangedEntry
	group singleflight.Group
}

func NewTokenExchanger(auth config.UpstreamAuth, client *http.Client, now func() time.Time) *TokenExchanger {
	te := auth.TokenExchange
	if te == nil {
		te = &config.TokenExchange{}
	}
	subType := strings.TrimSpace(te.SubjectTokenType)
	if subType == "" {
		subType = RFC8693AccessType
	}
	actorType := strings.TrimSpace(te.ActorTokenType)
	if te.ActorToken != "" && actorType == "" {
		actorType = RFC8693AccessType
	}
	cacheTTL := te.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultExchangeCacheTTL
	}
	if now == nil {
		now = time.Now
	}
	scopes := slices.Clone(auth.Scopes)
	sort.Strings(scopes)
	return &TokenExchanger{
		tokenURL:           auth.TokenURL,
		clientID:           auth.ClientID,
		clientSecret:       auth.ClientSecret,
		resource:           auth.Resource,
		audience:           te.Audience,
		scopes:             scopes,
		subjectTokenType:   subType,
		requestedTokenType: strings.TrimSpace(te.RequestedTokenType),
		actorToken:         te.ActorToken,
		actorTokenType:     actorType,
		intersectScopes:    te.IntersectCallerScopes,
		maxDelegationDepth: te.MaxDelegationDepth,
		allowedIssuers:     slices.Clone(te.AllowedIssuers),
		cacheTTL:           cacheTTL,
		client:             client,
		now:                now,
		cache:              map[[32]byte]exchangedEntry{},
	}
}

func (e *TokenExchanger) checkDelegation(p identity.Principal) error {
	if e.maxDelegationDepth > 0 && p.DelegationDepth() > e.maxDelegationDepth {
		return fmt.Errorf(
			"%w: delegation depth %d exceeds limit %d",
			ErrDelegationDenied,
			p.DelegationDepth(),
			e.maxDelegationDepth,
		)
	}
	if len(e.allowedIssuers) > 0 && !slices.Contains(e.allowedIssuers, p.Issuer) {
		return fmt.Errorf("%w: issuer %q is not permitted for token exchange", ErrDelegationDenied, p.Issuer)
	}
	return nil
}

func (e *TokenExchanger) effectiveScopes(p identity.Principal) ([]string, error) {
	if !e.intersectScopes {
		return e.scopes, nil
	}
	if len(e.scopes) == 0 {
		out := slices.Clone(p.Scopes)
		sort.Strings(out)
		return out, nil
	}
	out := make([]string, 0, len(e.scopes))
	for _, s := range e.scopes {
		if p.HasScope(s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: caller holds none of the required upstream scopes", ErrDelegationDenied)
	}
	return out, nil
}

func exchangeCacheKey(subjectToken string, scopes []string) [32]byte {
	h := sha256.New()
	h.Write([]byte(subjectToken))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(scopes, " ")))
	var key [32]byte
	h.Sum(key[:0])
	return key
}

func (e *TokenExchanger) Exchange(ctx context.Context, subjectToken string, p identity.Principal) (string, error) {
	if strings.TrimSpace(subjectToken) == "" {
		return "", fmt.Errorf("%w: missing subject token", ErrTokenExchange)
	}
	if err := e.checkDelegation(p); err != nil {
		return "", err
	}
	scopes, err := e.effectiveScopes(p)
	if err != nil {
		return "", fmt.Errorf("exchange: %w", err)
	}
	key := exchangeCacheKey(subjectToken, scopes)
	if tok, ok := e.lookup(key); ok {
		return tok, nil
	}
	v, err, _ := e.group.Do(hex.EncodeToString(key[:]), func() (any, error) {
		if tok, ok := e.lookup(key); ok {
			return tok, nil
		}
		tok, ttl, err := e.request(context.WithoutCancel(ctx), subjectToken, scopes)
		if err != nil {
			return "", err
		}
		if ttl > 0 {
			e.store(key, exchangedEntry{token: tok, expires: e.now().Add(ttl)})
		}
		return tok, nil
	})
	if err != nil {
		return "", fmt.Errorf("exchange: %w", err)
	}
	tok, ok := v.(string)
	if !ok || tok == "" {
		return "", ErrTokenExchange
	}
	return tok, nil
}

func (e *TokenExchanger) lookup(key [32]byte) (string, bool) {
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.cache[key]
	if !ok || !now.Before(entry.expires) {
		return "", false
	}
	return entry.token, true
}

func (e *TokenExchanger) store(key [32]byte, entry exchangedEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.cache) >= maxExchangeCacheEntries {
		now := e.now()
		for k, v := range e.cache {
			if !now.Before(v.expires) {
				delete(e.cache, k)
			}
		}
		for k := range e.cache {
			if len(e.cache) < maxExchangeCacheEntries {
				break
			}
			delete(e.cache, k)
		}
	}
	e.cache[key] = entry
}

func (e *TokenExchanger) formValues(subjectToken string, scopes []string) url.Values {
	form := url.Values{
		"grant_type":         {RFC8693GrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {e.subjectTokenType},
	}
	if e.resource != "" {
		form.Set("resource", e.resource)
	}
	if e.audience != "" {
		form.Set("audience", e.audience)
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	if e.requestedTokenType != "" {
		form.Set("requested_token_type", e.requestedTokenType)
	}
	if e.actorToken != "" {
		form.Set("actor_token", e.actorToken)
		form.Set("actor_token_type", e.actorTokenType)
	}
	return form
}

func (e *TokenExchanger) request(
	ctx context.Context,
	subjectToken string,
	scopes []string,
) (string, time.Duration, error) {
	form := e.formValues(subjectToken, scopes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("%w: build request: %w", ErrTokenExchange, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(e.clientID), url.QueryEscape(e.clientSecret))

	resp, err := e.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrTokenExchange, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxExchangeBodyBytes+1))
	if err != nil || len(body) > maxExchangeBodyBytes {
		return "", 0, fmt.Errorf("%w: unreadable response", ErrTokenExchange)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("%w: status %d", ErrTokenExchange, resp.StatusCode)
	}
	var parsed tokenExchangeResp
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, fmt.Errorf("%w: malformed json: %w", ErrTokenExchange, err)
	}
	if strings.TrimSpace(parsed.AccessToken) == "" {
		return "", 0, fmt.Errorf("%w: empty access_token", ErrTokenExchange)
	}
	if parsed.TokenType != "" && !strings.EqualFold(parsed.TokenType, "Bearer") {
		return "", 0, fmt.Errorf("%w: unsupported token_type %q", ErrTokenExchange, parsed.TokenType)
	}
	var ttl time.Duration
	if parsed.ExpiresIn > 0 {
		lifetime := time.Duration(parsed.ExpiresIn) * time.Second
		if lifetime > exchangeExpirySkew {
			ttl = min(e.cacheTTL, lifetime-exchangeExpirySkew)
		}
	}
	return parsed.AccessToken, ttl, nil
}

type tokenExchangeTransport struct {
	host      string
	exchanger *TokenExchanger
	discovery oauth2.TokenSource
	base      http.RoundTripper
}

func newTokenExchangeTransport(
	ctx context.Context,
	cfg config.Upstream,
	targetHost string,
	tokenClient *http.Client,
	base http.RoundTripper,
) http.RoundTripper {
	ex := NewTokenExchanger(cfg.Auth, tokenClient, nil)
	discScopes := cfg.Auth.Scopes
	if cfg.Auth.TokenExchange != nil && len(cfg.Auth.TokenExchange.DiscoveryScopes) > 0 {
		discScopes = cfg.Auth.TokenExchange.DiscoveryScopes
	}
	params := url.Values{}
	if cfg.Auth.Resource != "" {
		params.Set("resource", cfg.Auth.Resource)
	}
	cc := &clientcredentials.Config{
		ClientID:       cfg.Auth.ClientID,
		ClientSecret:   cfg.Auth.ClientSecret,
		TokenURL:       cfg.Auth.TokenURL,
		Scopes:         discScopes,
		EndpointParams: params,
		AuthStyle:      oauth2.AuthStyleInHeader,
	}
	tctx := context.WithValue(context.WithoutCancel(ctx), oauth2.HTTPClient, tokenClient)
	return &tokenExchangeTransport{
		host:      targetHost,
		exchanger: ex,
		discovery: oauth2.ReuseTokenSource(nil, cc.TokenSource(tctx)),
		base:      base,
	}
}

func (t *tokenExchangeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != t.host {
		return nil, fmt.Errorf("%w: %s", ErrForeignHost, r.URL.Host)
	}
	tok, err := t.resolveToken(r.Context())
	if err != nil {
		return nil, err
	}
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+tok)
	resp, err := t.base.RoundTrip(r2)
	if err != nil {
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	return resp, nil
}

func (t *tokenExchangeTransport) resolveToken(ctx context.Context) (string, error) {
	if subjectToken, ok := identity.SubjectTokenFrom(ctx); ok {
		p, _ := identity.FromContext(ctx)
		return t.exchanger.Exchange(ctx, subjectToken, p)
	}
	if p, ok := identity.FromContext(ctx); ok && p.Subject != "" && p.Subject != "anonymous" {
		return "", fmt.Errorf("%w: caller %q has no subject token", ErrTokenExchange, p.Subject)
	}
	svcTok, err := t.discovery.Token()
	if err != nil {
		return "", fmt.Errorf("%w: discovery service token: %w", ErrTokenExchange, err)
	}
	return svcTok.AccessToken, nil
}
