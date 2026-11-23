package upstream

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/netguard"
)

func TestSSRFBlockPrivateIPsRefusesLoopbackUpstream(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	hc, err := HTTPClient(t.Context(), config.Upstream{
		ID:              "ext",
		Transport:       config.TransportStreamable,
		URL:             internal.URL,
		BlockPrivateIPs: true,
		Auth:            config.UpstreamAuth{Type: config.UpstreamAuthBearer, Token: "upstream-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, internal.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("upstream client reached loopback despite block_private_ips=true")
	}
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("error = %v, want ErrBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("internal server received %d hits, want 0", hits.Load())
	}
}

func TestSSRFBlockPrivateIPsRefusesClientCredentialsTokenEndpoint(t *testing.T) {
	t.Parallel()
	var tokenHits atomic.Int32
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":60}`))
	}))
	defer tokenSrv.Close()

	hc, err := HTTPClient(t.Context(), config.Upstream{
		ID:              "cc",
		Transport:       config.TransportStreamable,
		URL:             "https://198.51.100.10/mcp",
		BlockPrivateIPs: true,
		Auth: config.UpstreamAuth{
			Type:         config.UpstreamAuthClientCredentials,
			TokenURL:     tokenSrv.URL + "/token",
			ClientID:     "gw",
			ClientSecret: "super-secret",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://198.51.100.10/mcp", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("token fetch to loopback succeeded despite block_private_ips=true")
	}
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("error = %v, want ErrBlockedAddress", err)
	}
	if tokenHits.Load() != 0 {
		t.Fatalf("private token endpoint received %d hits, want 0", tokenHits.Load())
	}
}

func TestSSRFRedirectsNeverFollowOrLeakCredentials(t *testing.T) {
	t.Parallel()
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	t.Cleanup(func() {
		if internalHits.Load() != 0 {
			t.Errorf("redirect target received %d hits, want 0", internalHits.Load())
		}
	})
	for _, code := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()
			redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, internal.URL+"/latest/meta-data/", code)
			}))
			defer redirector.Close()

			hc, err := HTTPClient(t.Context(), config.Upstream{
				ID:        "up",
				Transport: config.TransportStreamable,
				URL:       redirector.URL,
				Auth:      config.UpstreamAuth{Type: config.UpstreamAuthBearer, Token: "upstream-only-secret"},
			})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, redirector.URL, http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != code {
				t.Fatalf("status = %d, want %d (must not follow redirect)", resp.StatusCode, code)
			}
		})
	}
}

func TestSSRFForeignHostRefusesBearerExfiltration(t *testing.T) {
	t.Parallel()
	var victimHits atomic.Int32
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		victimHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer victim.Close()

	hc, err := HTTPClient(t.Context(), config.Upstream{
		ID:        "up",
		Transport: config.TransportStreamable,
		URL:       "https://allowed.example.com/mcp",
		Auth:      config.UpstreamAuth{Type: config.UpstreamAuthBearer, Token: "top-secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, victim.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("bearer token sent to foreign host")
	}
	if !errors.Is(err, ErrForeignHost) {
		t.Fatalf("error = %v, want ErrForeignHost", err)
	}
	if victimHits.Load() != 0 {
		t.Fatalf("foreign host received %d hits, want 0", victimHits.Load())
	}
}
