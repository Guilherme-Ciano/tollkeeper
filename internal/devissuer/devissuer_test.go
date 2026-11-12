package devissuer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
)

const cfgYAML = `
issuer: http://issuer.test
clients:
  - id: agent
    redirect_uris: ["http://127.0.0.1:1/cb"]
    resources: ["http://gw.test/mcp"]
    scopes: ["mcp:tools", "files:write"]
    grants: ["authorization_code"]
  - id: svc
    secret: s3cret
    resources: ["http://files.test/mcp"]
    scopes: ["files:upstream"]
    grants: ["client_credentials"]
users:
  - { sub: alice, scopes: ["mcp:tools"] }
`

func setup(t *testing.T) *httptest.Server {
	t.Helper()
	cfg, err := ParseConfig(strings.NewReader(cfgYAML))
	if err != nil {
		t.Fatal(err)
	}
	iss, err := New(cfg, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(iss.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func postForm(
	t *testing.T,
	srv *httptest.Server,
	form url.Values,
	user, pass string,
) (status int, body map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		srv.URL+"/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func verifier(t *testing.T, srv *httptest.Server, aud string) *authn.Verifier {
	t.Helper()
	ks := authn.NewKeySet(srv.URL+"/jwks.json", srv.Client(), time.Second)
	return authn.NewVerifier(
		authn.FromKeySet(ks),
		authn.VerifierOptions{Issuer: "http://issuer.test", Audiences: []string{aud}, Algorithms: []string{"EdDSA"}},
	)
}

func authorize(t *testing.T, srv *httptest.Server, challenge, resource, user string) *url.URL {
	t.Helper()
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {"agent"},
		"redirect_uri":  {"http://127.0.0.1:1/cb"},
		"code_challenge": {
			challenge,
		},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
		"state":                 {"st"},
		"user":                  {user},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/authorize?"+q.Encode(), http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestAuthorizationCodePKCE(t *testing.T) {
	t.Parallel()
	srv := setup(t)
	verifierStr := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifierStr))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	loc := authorize(t, srv, challenge, "http://gw.test/mcp", "alice")
	if loc.Query().Get("iss") != "http://issuer.test" || loc.Query().Get("state") != "st" ||
		loc.Query().Get("code") == "" {
		t.Fatalf("redirect %s", loc)
	}
	code := loc.Query().Get("code")
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"agent"}, "code": {code},
		"redirect_uri": {"http://127.0.0.1:1/cb"}, "code_verifier": {strings.Repeat("w", 64)},
	}
	if status, _ := postForm(t, srv, form, "", ""); status != http.StatusBadRequest {
		t.Fatalf("wrong verifier accepted: %d", status)
	}
	loc = authorize(t, srv, challenge, "http://gw.test/mcp", "alice")
	form.Set("code", loc.Query().Get("code"))
	form.Set("code_verifier", verifierStr)
	status, tok := postForm(t, srv, form, "", "")
	if status != http.StatusOK {
		t.Fatalf("token exchange failed: %d %v", status, tok)
	}
	access, ok := tok["access_token"].(string)
	if !ok {
		t.Fatalf("no access token in %v", tok)
	}
	p, err := verifier(t, srv, "http://gw.test/mcp").Verify(t.Context(), access)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "alice" || p.HasScope("files:write") || !p.HasScope("mcp:tools") {
		t.Fatalf("user scopes not intersected: %+v", p)
	}
	if status, _ := postForm(t, srv, form, "", ""); status != http.StatusBadRequest {
		t.Fatal("authorization code reused")
	}
	bad := authorize(t, srv, challenge, "http://evil.test/mcp", "alice")
	if bad.Query().Get("error") != "invalid_target" {
		t.Fatalf("foreign resource accepted: %s", bad)
	}
}

func TestClientCredentials(t *testing.T) {
	t.Parallel()
	srv := setup(t)
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {"http://files.test/mcp"}}
	if status, _ := postForm(t, srv, form, "svc", "wrong"); status != http.StatusUnauthorized {
		t.Fatalf("bad secret: %d", status)
	}
	status, tok := postForm(t, srv, form, "svc", "s3cret")
	if status != http.StatusOK {
		t.Fatalf("status %d %v", status, tok)
	}
	access, ok := tok["access_token"].(string)
	if !ok {
		t.Fatalf("no access token in %v", tok)
	}
	p, err := verifier(t, srv, "http://files.test/mcp").Verify(t.Context(), access)
	if err != nil || p.Subject != "svc" || !p.HasScope("files:upstream") {
		t.Fatalf("%+v %v", p, err)
	}
	form.Set("resource", "http://gw.test/mcp")
	if status, _ := postForm(t, srv, form, "svc", "s3cret"); status != http.StatusBadRequest {
		t.Fatal("client got a token for a resource it is not registered for")
	}
	form.Set("grant_type", "authorization_code")
	if status, _ := postForm(t, srv, form, "svc", "s3cret"); status != http.StatusBadRequest {
		t.Fatal("grant not allowed for client was accepted")
	}
}

func TestCheckListen(t *testing.T) {
	t.Parallel()
	for addr, ok := range map[string]bool{"127.0.0.1:9000": true, "localhost:9000": true, "[::1]:9000": true, "0.0.0.0:9000": false, ":9000": false} {
		if err := CheckListen(addr, false); (err == nil) != ok {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	if err := CheckListen("0.0.0.0:9000", true); err != nil {
		t.Fatal(err)
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	srv := setup(t)
	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		srv.URL+"/.well-known/oauth-authorization-server",
		http.NoBody,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	if m["issuer"] != "http://issuer.test" || m["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("metadata %v", m)
	}
}
