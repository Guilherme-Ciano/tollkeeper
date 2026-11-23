package upstream

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

func BenchmarkTokenExchangeCached(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, map[string]any{
			"access_token": "downscoped-downstream-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	b.Cleanup(srv.Close)

	now := time.Date(2026, 11, 23, 16, 0, 0, 0, time.UTC)
	ex := NewTokenExchanger(config.UpstreamAuth{
		Type:         config.UpstreamAuthTokenExchange,
		TokenURL:     srv.URL,
		ClientID:     "gw",
		ClientSecret: "sec",
		Resource:     "https://crm.internal/mcp",
		Scopes:       []string{"crm:read"},
		TokenExchange: &config.TokenExchange{
			IntersectCallerScopes: true,
			CacheTTL:              10 * time.Minute,
		},
	}, srv.Client(), func() time.Time { return now })

	const users = 32
	tokens := make([]string, users)
	principals := make([]identity.Principal, users)
	ctx := b.Context()
	for i := range users {
		tokens[i] = fmt.Sprintf("subject-token-%02d", i)
		principals[i] = identity.Principal{
			Subject: fmt.Sprintf("user-%02d", i),
			Scopes:  []string{"crm:read", "crm:write"},
		}
		if _, err := ex.Exchange(ctx, tokens[i], principals[i]); err != nil {
			b.Fatal(err)
		}
	}

	var seq atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := seq.Add(1) % users
			if _, err := ex.Exchange(ctx, tokens[idx], principals[idx]); err != nil {
				b.Fatal(err)
			}
		}
	})
}
