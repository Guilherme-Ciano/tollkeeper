package app

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/devissuer"
)

func issuer(t *testing.T) (iss *devissuer.Issuer, url string) {
	t.Helper()
	srv := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { iss.Handler().ServeHTTP(w, r) }),
	)
	t.Cleanup(srv.Close)
	cfg, err := devissuer.ParseConfig(
		strings.NewReader("issuer: " + srv.URL + "\nclients:\n  - id: x\n    grants: [client_credentials]\n"),
	)
	if err != nil {
		t.Fatal(err)
	}
	iss, err = devissuer.New(cfg, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return iss, srv.URL
}

func jwtConfig(t *testing.T, upURL, issuerURL string) config.Config {
	t.Helper()
	cfg := testConfig(t, upURL)
	cfg.Auth = config.Defaults().Auth
	cfg.Auth.Resource = "http://127.0.0.1/mcp"
	cfg.Auth.AuthorizationServers = []string{issuerURL}
	cfg.Auth.RequiredScopes = []string{"mcp:tools"}
	cfg.Auth.ScopesSupported = []string{"mcp:tools"}
	cfg.Auth.JWT.Issuer = issuerURL
	cfg.Auth.JWT.JWKSURL = issuerURL + "/jwks.json"
	cfg.Auth.JWT.AllowInsecure = true
	cfg.Auth.JWT.Audiences = []string{"http://127.0.0.1/mcp"}
	cfg.Auth.JWT.Algorithms = []string{"EdDSA"}
	cfg.RateLimits.Rules = nil
	return cfg
}

type rawResult struct {
	status int
	header http.Header
	body   string
}

func post(t *testing.T, url, token, body string, headers map[string]string) rawResult {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return rawResult{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

const callEcho = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake__echo","arguments":{"text":"hi"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`

func modernHeaders(name string) map[string]string {
	return map[string]string{"Mcp-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": name}
}

func TestResourceServer(t *testing.T) {
	iss, issURL := issuer(t)
	up := fakeUpstream(t, &headerLog{})
	url := startApp(t, jwtConfig(t, up.URL, issURL))
	good, err := iss.Mint("alice", "agent", "http://127.0.0.1/mcp", []string{"mcp:tools"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	wrongAud, err := iss.Mint("alice", "agent", "http://other/mcp", []string{"mcp:tools"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	noScope, err := iss.Mint("alice", "agent", "http://127.0.0.1/mcp", nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("protected resource metadata", func(t *testing.T) {
		req, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			strings.TrimSuffix(url, "/mcp")+"/.well-known/oauth-protected-resource/mcp",
			http.NoBody,
		)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var prm map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&prm); err != nil {
			t.Fatal(err)
		}
		if prm["resource"] != "http://127.0.0.1/mcp" {
			t.Fatalf("prm %v", prm)
		}
	})
	cases := []struct {
		name, token string
		status      int
		challenge   string
	}{
		{
			"no token",
			"",
			http.StatusUnauthorized,
			`resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource/mcp"`,
		},
		{"wrong audience", wrongAud, http.StatusUnauthorized, `error="invalid_token"`},
		{"garbage", "abc.def.ghi", http.StatusUnauthorized, `error="invalid_token"`},
		{"missing required scope", noScope, http.StatusForbidden, `error="insufficient_scope"`},
		{"valid", good, http.StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := post(t, url, tc.token, callEcho, modernHeaders("fake__echo"))
			if r.status != tc.status {
				t.Fatalf("status %d body %s", r.status, r.body)
			}
			if tc.challenge != "" && !strings.Contains(r.header.Get("WWW-Authenticate"), tc.challenge) {
				t.Fatalf("challenge %q missing %q", r.header.Get("WWW-Authenticate"), tc.challenge)
			}
		})
	}
	t.Run("header mismatch", func(t *testing.T) {
		r := post(t, url, good, callEcho, modernHeaders("fake__other"))
		if r.status != http.StatusBadRequest || !strings.Contains(r.body, "-32020") {
			t.Fatalf("%d %s", r.status, r.body)
		}
	})
	t.Run("legacy client without standard headers", func(t *testing.T) {
		body := strings.Replace(
			callEcho,
			`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`,
			`"_meta":{}`,
			1,
		)
		r := post(t, url, good, body, map[string]string{"Mcp-Protocol-Version": "2025-11-25"})
		if r.status == http.StatusBadRequest && strings.Contains(r.body, "-32020") {
			t.Fatalf("legacy request rejected for missing headers: %s", r.body)
		}
	})
	t.Run("batch rejected", func(t *testing.T) {
		r := post(t, url, good, "["+callEcho+"]", nil)
		if r.status != http.StatusBadRequest {
			t.Fatalf("%d %s", r.status, r.body)
		}
	})
	t.Run("parser differential rejected", func(t *testing.T) {
		body := strings.Replace(callEcho, `"name":"fake__echo"`, `"name":"fake__echo","Name":"fake__secret"`, 1)
		r := post(t, url, good, body, nil)
		if r.status != http.StatusBadRequest {
			t.Fatalf("%d %s", r.status, r.body)
		}
	})
	t.Run("unsupported method", func(t *testing.T) {
		r := post(t, url, good, `{"jsonrpc":"2.0","id":3,"method":"sampling/createMessage","params":{}}`, nil)
		if !strings.Contains(r.body, "-32601") {
			t.Fatalf("%d %s", r.status, r.body)
		}
	})
	t.Run("sdk client with token", func(t *testing.T) {
		c := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "1"}, nil)
		cs, err := c.Connect(
			t.Context(),
			&mcp.StreamableClientTransport{
				Endpoint:   url,
				HTTPClient: &http.Client{Transport: authTransport{token: good}},
			},
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer cs.Close()
		res, err := cs.ListTools(t.Context(), nil)
		if err != nil || len(res.Tools) != 1 {
			t.Fatalf("%v %v", res, err)
		}
	})
}

func TestStdioUpstreamEnvIsolation(t *testing.T) {
	t.Setenv("GATEWAY_SECRET_SHOULD_NOT_LEAK", "x")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, "http://unused")
	cfg.Upstreams = []config.Upstream{{
		ID: "local", Transport: config.TransportStdio, Command: []string{exe},
		Env: map[string]string{stdioEnv: "1"},
	}}
	cfg.Policy.Rules = []config.Rule{{Name: "all", Tools: []string{"local__*"}, Effect: config.EffectAllow}}
	cfg.RateLimits.Rules = nil
	url := startApp(t, cfg)
	cs := connect(t, url, "")
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "local__env", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatal("no text content")
	}
	names := strings.Split(tc.Text, ",")
	if strings.Contains(tc.Text, "GATEWAY_SECRET_SHOULD_NOT_LEAK") || len(names) > 3 {
		t.Fatalf("stdio upstream inherited gateway environment: %v", names)
	}
}
