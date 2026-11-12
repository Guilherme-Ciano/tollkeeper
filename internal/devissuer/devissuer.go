package devissuer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.yaml.in/yaml/v3"

	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
)

const maxPendingCodes = 10_000

var (
	ErrNonLoopback = errors.New("dev issuer refuses to bind a non-loopback address without --i-know-this-is-insecure")
	ErrConfig      = errors.New("invalid dev issuer config")
)

type Client struct {
	ID           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	Scopes       []string `yaml:"scopes"`
	RedirectURIs []string `yaml:"redirect_uris"`
	Resources    []string `yaml:"resources"`
	Grants       []string `yaml:"grants"`
}

type User struct {
	Sub    string   `yaml:"sub"`
	Name   string   `yaml:"name"`
	Scopes []string `yaml:"scopes"`
}

type Config struct {
	Issuer   string        `yaml:"issuer"`
	Listen   string        `yaml:"listen"`
	TokenTTL time.Duration `yaml:"token_ttl"`
	Clients  []Client      `yaml:"clients"`
	Users    []User        `yaml:"users"`
}

func ParseConfig(r io.Reader) (Config, error) {
	cfg := Config{Listen: "127.0.0.1:9000", TokenTTL: 15 * time.Minute}
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse dev issuer config: %w", err)
	}
	if cfg.Issuer == "" || len(cfg.Clients) == 0 {
		return cfg, fmt.Errorf("%w: issuer and at least one client are required", ErrConfig)
	}
	return cfg, nil
}

func CheckListen(addr string, insecure bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	if insecure {
		return nil
	}
	return ErrNonLoopback
}

type authCode struct {
	clientID    string
	redirectURI string
	challenge   string
	resource    string
	sub         string
	scopes      []string
	expires     time.Time
}

type Issuer struct {
	cfg  Config
	key  ed25519.PrivateKey
	kid  string
	log  *slog.Logger
	now  func() time.Time
	mu   sync.Mutex
	code map[string]authCode
}

func New(cfg Config, key ed25519.PrivateKey, log *slog.Logger) (*Issuer, error) {
	if key == nil {
		var err error
		if _, key, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, fmt.Errorf("generate signing key: %w", err)
		}
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: signing key is not ed25519", ErrConfig)
	}
	sum := sha256.Sum256(pub)
	return &Issuer{
		cfg:  cfg,
		key:  key,
		kid:  hex.EncodeToString(sum[:8]),
		log:  log,
		now:  time.Now,
		code: map[string]authCode{},
	}, nil
}

func (i *Issuer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", i.metadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", i.metadata)
	mux.HandleFunc("GET /jwks.json", i.jwks)
	mux.HandleFunc("POST /token", i.token)
	mux.HandleFunc("GET /authorize", i.authorize)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Debug("response write failed", slog.String("error", err.Error()))
	}
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (i *Issuer) metadata(w http.ResponseWriter, _ *http.Request) {
	var scopes []string
	for ci := range i.cfg.Clients {
		for _, s := range i.cfg.Clients[ci].Scopes {
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}
	slices.Sort(scopes)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         i.cfg.Issuer,
		"authorization_endpoint":                         i.cfg.Issuer + "/authorize",
		"token_endpoint":                                 i.cfg.Issuer + "/token",
		"jwks_uri":                                       i.cfg.Issuer + "/jwks.json",
		"grant_types_supported":                          []string{"client_credentials", "authorization_code"},
		"response_types_supported":                       []string{"code"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                               scopes,
		"authorization_response_iss_parameter_supported": true,
		"id_token_signing_alg_values_supported":          []string{"EdDSA"},
		"subject_types_supported":                        []string{"public"},
	})
}

func (i *Issuer) jwks(w http.ResponseWriter, _ *http.Request) {
	pub, ok := i.key.Public().(ed25519.PublicKey)
	k, err := authn.EncodeJWK(i.kid, pub)
	if !ok || err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "key encoding failed")
		return
	}
	writeJSON(w, http.StatusOK, authn.JWKSet{Keys: []authn.JWK{k}})
}

func (i *Issuer) client(id string) (Client, bool) {
	for ci := range i.cfg.Clients {
		if i.cfg.Clients[ci].ID == id {
			return i.cfg.Clients[ci], true
		}
	}
	return Client{}, false
}

func (i *Issuer) user(sub string) (User, bool) {
	for _, u := range i.cfg.Users {
		if u.Sub == sub {
			return u, true
		}
	}
	return User{}, false
}

func clientCredentials(r *http.Request) (id, secret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		uid, err1 := url.QueryUnescape(id)
		usec, err2 := url.QueryUnescape(secret)
		if err1 == nil && err2 == nil {
			return uid, usec
		}
		return id, secret
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
}

func grantScopes(requested string, allowed ...[]string) []string {
	want := strings.Fields(requested)
	if len(want) == 0 && len(allowed) > 0 {
		want = allowed[0]
	}
	var out []string
	for _, s := range want {
		ok := true
		for _, a := range allowed {
			if !slices.Contains(a, s) {
				ok = false
				break
			}
		}
		if ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func (i *Issuer) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}
	id, secret := clientCredentials(r)
	c, ok := i.client(id)
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "unknown client")
		return
	}
	if c.Secret != "" && subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "bad client credentials")
		return
	}
	grant := r.PostForm.Get("grant_type")
	if !slices.Contains(c.Grants, grant) {
		oauthError(w, http.StatusBadRequest, "unauthorized_client", "grant not allowed for client")
		return
	}
	switch grant {
	case "client_credentials":
		if c.Secret == "" {
			oauthError(
				w,
				http.StatusUnauthorized,
				"invalid_client",
				"client_credentials requires a confidential client",
			)
			return
		}
		resource := r.PostForm.Get("resource")
		if !slices.Contains(c.Resources, resource) {
			oauthError(w, http.StatusBadRequest, "invalid_target", "resource not allowed for client")
			return
		}
		i.issue(w, c.ID, c.ID, resource, grantScopes(r.PostForm.Get("scope"), c.Scopes))
	case "authorization_code":
		i.exchange(w, r, c)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant")
	}
}

func (i *Issuer) exchange(w http.ResponseWriter, r *http.Request, c Client) {
	code := r.PostForm.Get("code")
	i.mu.Lock()
	ac, ok := i.code[code]
	delete(i.code, code)
	i.mu.Unlock()
	if !ok || ac.clientID != c.ID || i.now().After(ac.expires) || ac.redirectURI != r.PostForm.Get("redirect_uri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
		return
	}
	verifier := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if len(verifier) < 43 || base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	if res := r.PostForm.Get("resource"); res != "" && res != ac.resource {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource differs from authorization request")
		return
	}
	i.issue(w, ac.sub, c.ID, ac.resource, ac.scopes)
}

func (i *Issuer) Mint(sub, clientID, audience string, scopes []string, ttl time.Duration) (string, error) {
	now := i.now()
	var jti [12]byte
	_, _ = rand.Read(jti[:])
	claims := jwt.MapClaims{
		"iss":       i.cfg.Issuer,
		"sub":       sub,
		"aud":       []string{audience},
		"client_id": clientID,
		"scope":     strings.Join(scopes, " "),
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"jti":       hex.EncodeToString(jti[:]),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = i.kid
	t.Header["typ"] = "at+jwt"
	s, err := t.SignedString(i.key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return s, nil
}

func (i *Issuer) issue(w http.ResponseWriter, sub, clientID, resource string, scopes []string) {
	tok, err := i.Mint(sub, clientID, resource, scopes, i.cfg.TokenTTL)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "signing failed")
		return
	}
	i.log.Info("token issued", slog.String("sub", sub), slog.String("client_id", clientID),
		slog.String("aud", resource), slog.String("scope", strings.Join(scopes, " ")))
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(i.cfg.TokenTTL.Seconds()),
		"scope":        strings.Join(scopes, " "),
	})
}

const consentPage = `<!doctype html><html><head><meta charset="utf-8"><title>tollkeeper dev issuer</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:2rem auto">
<p style="background:#b00;color:#fff;padding:.5rem;font-weight:bold">DEV ONLY: this issuer auto-approves and must never face the internet.</p>
<h1>Sign in as</h1><ul>{{range .Users}}<li><a href="{{$.Base}}&amp;user={{.Sub}}">{{.Name}} ({{.Sub}})</a> scopes: {{.Scopes}}</li>{{end}}</ul>
</body></html>`

func (i *Issuer) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := i.client(q.Get("client_id"))
	if !ok || !slices.Contains(c.RedirectURIs, q.Get("redirect_uri")) {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	fail := func(code string) {
		v := redirect.Query()
		v.Set("error", code)
		v.Set("state", q.Get("state"))
		v.Set("iss", i.cfg.Issuer)
		redirect.RawQuery = v.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	}
	if q.Get("response_type") != "code" || !slices.Contains(c.Grants, "authorization_code") {
		fail("unsupported_response_type")
		return
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
		fail("invalid_request")
		return
	}
	if !slices.Contains(c.Resources, q.Get("resource")) {
		fail("invalid_target")
		return
	}
	sub := q.Get("user")
	if sub == "" {
		tpl, err := template.New("consent").Parse(consentPage)
		if err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tpl.Execute(
			w,
			map[string]any{"Users": i.cfg.Users, "Base": "/authorize?" + r.URL.RawQuery},
		); err != nil {
			i.log.DebugContext(r.Context(), "consent page write failed", slog.String("error", err.Error()))
		}
		return
	}
	u, ok := i.user(sub)
	if !ok {
		fail("access_denied")
		return
	}
	var raw [24]byte
	_, _ = rand.Read(raw[:])
	code := base64.RawURLEncoding.EncodeToString(raw[:])
	i.mu.Lock()
	for k := range i.code {
		if i.now().After(i.code[k].expires) {
			delete(i.code, k)
		}
	}
	if len(i.code) >= maxPendingCodes {
		i.mu.Unlock()
		fail("temporarily_unavailable")
		return
	}
	i.code[code] = authCode{
		clientID: c.ID, redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"),
		resource: q.Get("resource"), sub: u.Sub, scopes: grantScopes(q.Get("scope"), c.Scopes, u.Scopes),
		expires: i.now().Add(time.Minute),
	}
	i.mu.Unlock()
	v := redirect.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	v.Set("iss", i.cfg.Issuer)
	redirect.RawQuery = v.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}
