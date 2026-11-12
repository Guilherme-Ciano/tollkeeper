package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const redirectURI = "http://127.0.0.1:8765/callback"

var errLogin = errors.New("login failed")

type opts struct {
	issuer   string
	gateway  string
	resource string
	clientID string
}

func login(ctx context.Context, o opts, user, scope string) (string, error) {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	verifier := base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {o.clientID}, "redirect_uri": {redirectURI},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"resource": {o.resource}, "scope": {scope}, "state": {"demo"}, "user": {user},
	}
	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       5 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.issuer+"/authorize?"+q.Encode(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("authorize request: %w", err)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", fmt.Errorf("authorize: %w", err)
	}
	resp.Body.Close()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		return "", fmt.Errorf("%w: authorize redirect %q", errLogin, resp.Header.Get("Location"))
	}
	if loc.Query().Get("iss") != o.issuer {
		return "", fmt.Errorf("%w: RFC 9207 iss mismatch %q", errLogin, loc.Query().Get("iss"))
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")}, "redirect_uri": {redirectURI},
		"client_id": {o.clientID}, "code_verifier": {verifier}, "resource": {o.resource},
	}
	treq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.issuer+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tresp, err := http.DefaultClient.Do(treq)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	defer tresp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(tresp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("%w: token response %s", errLogin, tok.Error)
	}
	fmt.Printf("  logged in as %s, granted scope %q\n", user, tok.Scope)
	return tok.AccessToken, nil
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+b.token)
	resp, err := http.DefaultTransport.RoundTrip(r2)
	if err != nil {
		return nil, fmt.Errorf("gateway request: %w", err)
	}
	return resp, nil
}

func session(ctx context.Context, o opts, token string) (*mcp.ClientSession, error) {
	c := mcp.NewClient(&mcp.Implementation{Name: "tollkeeper-democlient", Version: "1.0.0"}, nil)
	cs, err := c.Connect(
		ctx,
		&mcp.StreamableClientTransport{Endpoint: o.gateway, HTTPClient: &http.Client{Transport: bearer{token}}},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("connect gateway: %w", err)
	}
	return cs, nil
}

type rawResult struct {
	status int
	header http.Header
	body   string
}

func rawCall(ctx context.Context, o opts, token, tool string, args map[string]any) (rawResult, error) {
	body, err := json.Marshal(
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
			"name": tool, "arguments": args,
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"io.modelcontextprotocol/clientInfo": map[string]any{
					"name":    "tollkeeper-democlient",
					"version": "1.0.0",
				},
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			},
		}},
	)
	if err != nil {
		return rawResult{}, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.gateway, strings.NewReader(string(body)))
	if err != nil {
		return rawResult{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return rawResult{}, fmt.Errorf("call %s: %w", tool, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return rawResult{}, fmt.Errorf("read %s response: %w", tool, err)
	}
	return rawResult{status: resp.StatusCode, header: resp.Header, body: strings.TrimSpace(string(b))}, nil
}

func text(r *mcp.CallToolResult) string {
	if r.StructuredContent != nil {
		b, err := json.Marshal(r.StructuredContent)
		if err != nil {
			return fmt.Sprintf("<unencodable structured content: %v>", err)
		}
		return string(b)
	}
	if len(r.Content) > 0 {
		if t, ok := r.Content[0].(*mcp.TextContent); ok {
			return t.Text
		}
	}
	return ""
}

func demo(ctx context.Context, o opts) error {
	fmt.Println("1. alice (reader) logs in with authorization_code + PKCE")
	alice, err := login(ctx, o, "alice", "mcp:tools")
	if err != nil {
		return err
	}
	cs, err := session(ctx, o, alice)
	if err != nil {
		return err
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("list tools: %w", err)
	}
	fmt.Printf("2. tools visible to alice (%d):\n", len(tools.Tools))
	for _, t := range tools.Tools {
		fmt.Printf("   - %s\n", t.Name)
	}
	res, err := cs.CallTool(
		ctx,
		&mcp.CallToolParams{Name: "notes__search", Arguments: map[string]any{"query": "audit"}},
	)
	if err != nil {
		return fmt.Errorf("notes__search: %w", err)
	}
	fmt.Printf("3. notes__search (stdio upstream) -> %s\n", text(res))
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "files__list_files", Arguments: map[string]any{}})
	if err != nil {
		return fmt.Errorf("files__list_files: %w", err)
	}
	fmt.Printf(
		"4. files__list_files (OAuth-protected upstream, gateway uses its own client_credentials) -> %s\n",
		text(res),
	)
	rr, err := rawCall(ctx, o, alice, "files__delete_file", map[string]any{"path": "/tmp/old.log"})
	if err != nil {
		return err
	}
	fmt.Printf(
		"5. alice calls files__delete_file -> HTTP %d\n   WWW-Authenticate: %s\n   %s\n",
		rr.status,
		rr.header.Get("WWW-Authenticate"),
		rr.body,
	)
	fmt.Println("6. bob steps up with files:write")
	bob, err := login(ctx, o, "bob", "mcp:tools files:write")
	if err != nil {
		return err
	}
	rr, err = rawCall(ctx, o, bob, "files__delete_file", map[string]any{"path": "/tmp/old.log"})
	if err != nil {
		return err
	}
	fmt.Printf("   bob calls files__delete_file -> HTTP %d %s\n", rr.status, rr.body)
	fmt.Println("7. alice bursts weather__forecast")
	for i := range 8 {
		rr, err = rawCall(ctx, o, alice, "weather__forecast", map[string]any{"city": "Lisbon"})
		if err != nil {
			return err
		}
		extra := ""
		if rr.status == http.StatusTooManyRequests {
			extra = " Retry-After=" + rr.header.Get("Retry-After") + " " + rr.header.Get("RateLimit")
		}
		fmt.Printf("   call %d -> HTTP %d%s\n", i+1, rr.status, extra)
	}
	return nil
}

func run() error {
	var o opts
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&o.issuer, "issuer", "http://localhost:9000", "dev issuer URL")
	fs.StringVar(&o.gateway, "gateway", "http://localhost:8080/mcp", "gateway MCP endpoint")
	fs.StringVar(&o.resource, "resource", "http://localhost:8080/mcp", "gateway resource identifier (token audience)")
	fs.StringVar(&o.clientID, "client-id", "demo-agent", "public OAuth client id")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return fmt.Errorf("flags: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return demo(ctx, o)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo failed:", err)
		os.Exit(1)
	}
}
