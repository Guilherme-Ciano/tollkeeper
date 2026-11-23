package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/netguard"
)

func TestSSRFIntrospectionRefusesRedirects(t *testing.T) {
	t.Parallel()
	var secretHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secretHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/metadata", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	intr := NewIntrospector(IntrospectorOptions{
		URL:          redirector.URL,
		ClientID:     "gw",
		ClientSecret: "do-not-leak",
		Audiences:    []string{"https://mcp.example.com/mcp"},
		CacheTTL:     time.Minute,
	})
	_, err := intr.Verify(t.Context(), "opaque-caller-token")
	if !errors.Is(err, ErrIntrospectionUnavailable) {
		t.Fatalf("Verify = %v, want ErrIntrospectionUnavailable", err)
	}
	if secretHits.Load() != 0 {
		t.Fatalf("redirect target received %d hits, want 0", secretHits.Load())
	}
}

func TestSSRFJWKSBlockedByNetguard(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer internal.Close()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: netguard.Dialer(2*time.Second, 0, true).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ks := NewKeySet(internal.URL+"/.well-known/jwks.json", client, time.Second)
	err := ks.Refresh(t.Context())
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("Refresh = %v, want ErrBlockedAddress", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("internal jwks server received %d hits, want 0", hits.Load())
	}
}
