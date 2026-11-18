package authn

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAS struct {
	hits   atomic.Int32
	status int
	resp   map[string]map[string]any
	gate   chan struct{}
}

func (f *fakeAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if f.gate != nil {
		<-f.gate
	}
	id, secret, ok := r.BasicAuth()
	if !ok || id != "gw" || secret != "s3cret" || r.FormValue("token_type_hint") != "access_token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	body, ok := f.resp[r.FormValue("token")]
	if !ok {
		body = map[string]any{"active": false}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

var introspectNow = time.Unix(1_800_000_000, 0)

func newIntrospector(t *testing.T, as *fakeAS) *Introspector {
	t.Helper()
	srv := httptest.NewServer(as)
	t.Cleanup(srv.Close)
	return NewIntrospector(IntrospectorOptions{
		URL: srv.URL, ClientID: "gw", ClientSecret: "s3cret", Issuer: "https://as.example",
		Audiences: []string{"https://mcp.example/mcp"}, CacheTTL: time.Minute, MaxEntries: 4,
		Now: func() time.Time { return introspectNow },
	})
}

func activeToken(extra map[string]any) map[string]any {
	m := map[string]any{
		"active": true, "sub": "alice", "client_id": "cli", "scope": "notes:read notes:write",
		"aud": "https://mcp.example/mcp", "iss": "https://as.example", "exp": introspectNow.Unix() + 3600,
	}
	maps.Copy(m, extra)
	return m
}

func TestIntrospectionAcceptsAndCaches(t *testing.T) {
	t.Parallel()
	as := &fakeAS{resp: map[string]map[string]any{"good": activeToken(nil)}}
	in := newIntrospector(t, as)
	for range 3 {
		p, err := in.Verify(t.Context(), "good")
		if err != nil {
			t.Fatal(err)
		}
		if p.Subject != "alice" || p.ClientID != "cli" || !p.HasScope("notes:write") || p.Fingerprint == "" {
			t.Fatalf("principal %+v", p)
		}
	}
	if n := as.hits.Load(); n != 1 {
		t.Fatalf("authorization server hit %d times", n)
	}
}

func TestIntrospectionRejects(t *testing.T) {
	t.Parallel()
	as := &fakeAS{resp: map[string]map[string]any{
		"other-aud": activeToken(map[string]any{"aud": []string{"https://elsewhere"}}),
		"expired":   activeToken(map[string]any{"exp": introspectNow.Unix() - 1}),
		"wrong-iss": activeToken(map[string]any{"iss": "https://evil.example"}),
		"no-sub":    activeToken(map[string]any{"sub": ""}),
		"refresh":   activeToken(map[string]any{"token_type": "refresh_token"}),
		"future":    activeToken(map[string]any{"nbf": introspectNow.Unix() + 600}),
	}}
	in := newIntrospector(t, as)
	for range 2 {
		if _, err := in.Verify(t.Context(), "inactive"); !errors.Is(err, ErrInvalidToken) {
			t.Fatal(err)
		}
	}
	if n := as.hits.Load(); n != 1 {
		t.Fatalf("an inactive token was not negatively cached: %d hits", n)
	}
	for _, tok := range []string{"other-aud", "expired", "wrong-iss", "no-sub", "refresh", "future"} {
		if _, err := in.Verify(t.Context(), tok); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v", tok, err)
		}
	}
}

func TestIntrospectionOutageIsUnavailableAndNotCached(t *testing.T) {
	t.Parallel()
	as := &fakeAS{status: http.StatusBadGateway}
	in := newIntrospector(t, as)
	for range 2 {
		if _, err := in.Verify(t.Context(), "any"); !errors.Is(err, ErrKeysUnavailable) {
			t.Fatalf("outage: %v", err)
		}
	}
	if n := as.hits.Load(); n != 2 {
		t.Fatalf("outage result was cached: %d hits", n)
	}
}

func TestIntrospectionCollapsesConcurrentLookups(t *testing.T) {
	t.Parallel()
	as := &fakeAS{resp: map[string]map[string]any{"good": activeToken(nil)}, gate: make(chan struct{})}
	in := newIntrospector(t, as)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := in.Verify(t.Context(), "good"); err != nil {
				t.Error(err)
			}
		})
	}
	for as.hits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(as.gate)
	wg.Wait()
	if n := as.hits.Load(); n != 1 {
		t.Fatalf("%d concurrent lookups reached the server", n)
	}
}

func TestIntrospectionCacheIsBoundedAndCappedByExp(t *testing.T) {
	t.Parallel()
	as := &fakeAS{resp: map[string]map[string]any{
		"short": activeToken(map[string]any{"exp": introspectNow.Unix() + 5}),
	}}
	in := newIntrospector(t, as)
	if _, err := in.Verify(t.Context(), "short"); err != nil {
		t.Fatal(err)
	}
	for _, v := range in.cache {
		if got := v.expires.Sub(introspectNow); got != 5*time.Second {
			t.Fatalf("cache ttl %v, want the token's remaining 5s", got)
		}
	}
	for _, tok := range []string{"a", "b", "c", "d", "e", "f"} {
		if _, err := in.Verify(t.Context(), tok); !errors.Is(err, ErrInvalidToken) {
			t.Fatal(err)
		}
	}
	if len(in.cache) > 4 {
		t.Fatalf("cache grew to %d entries", len(in.cache))
	}
}
