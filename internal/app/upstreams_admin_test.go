package app

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminUpstreamsDiagnosticsEndpoint(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})
	cfg := testConfig(t, up.URL)
	a, _ := readyApp(t, cfg)

	req, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"http://"+a.Addr("admin")+"/upstreams",
		http.NoBody,
	)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /upstreams: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /upstreams status = %d, want 200", resp.StatusCode)
	}

	var payload struct {
		Upstreams []struct {
			ID           string `json:"id"`
			Up           bool   `json:"up"`
			Synced       bool   `json:"synced"`
			Tools        int    `json:"tools"`
			BreakerState string `json:"breaker_state"`
			Generation   uint64 `json:"generation"`
		} `json:"upstreams"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /upstreams: %v", err)
	}
	if len(payload.Upstreams) != 1 {
		t.Fatalf("upstreams len = %d, want 1", len(payload.Upstreams))
	}
	u := payload.Upstreams[0]
	if u.ID != "fake" || !u.Up || !u.Synced || u.Tools == 0 || u.BreakerState != "closed" || u.Generation == 0 {
		t.Fatalf("unexpected upstream diagnostic entry: %+v", u)
	}
}
