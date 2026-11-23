package adminui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesEmbeddedAssetsWithSecurityHeaders(t *testing.T) {
	t.Parallel()
	h := Handler()

	cases := []struct {
		path    string
		wantCT  string
		wantSub string
	}{
		{path: "/ui/", wantCT: "text/html", wantSub: "tollkeeper"},
		{path: "/ui/styles.css", wantCT: "text/css", wantSub: "--accent"},
		{path: "/ui/app.js", wantCT: "javascript", wantSub: "/api/simulate"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.path, http.NoBody)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tc.wantCT) {
				t.Fatalf("content-type = %q, want substring %q", ct, tc.wantCT)
			}
			if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
				t.Fatalf("missing strict CSP header: %q", csp)
			}
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("missing nosniff header")
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" {
				t.Fatalf("missing X-Frame-Options DENY")
			}
			if !strings.Contains(rec.Body.String(), tc.wantSub) {
				t.Fatalf("body missing %q", tc.wantSub)
			}
		})
	}
}

func TestHandlerMissingAssetReturns404(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ui/does-not-exist.js", http.NoBody)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
