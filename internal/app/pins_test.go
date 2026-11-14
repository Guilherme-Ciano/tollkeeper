package app

import (
	"net/http"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func pinsStatus(t *testing.T, a *App, token string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+a.Addr("admin")+"/pins", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestPinsEndpointAccess(t *testing.T) {
	up := fakeUpstream(t, &headerLog{})
	cases := []struct {
		name   string
		mode   string
		token  string
		bearer string
		want   int
	}{
		{name: "loopback without token", mode: config.PinModeWarn, want: http.StatusOK},
		{name: "pinning off", mode: config.PinModeOff, want: http.StatusNotFound},
		{name: "token required and missing", mode: config.PinModeWarn, token: "s3cret", want: http.StatusNotFound},
		{
			name:   "token required and wrong",
			mode:   config.PinModeWarn,
			token:  "s3cret",
			bearer: "guess",
			want:   http.StatusNotFound,
		},
		{
			name:   "token required and given",
			mode:   config.PinModeWarn,
			token:  "s3cret",
			bearer: "s3cret",
			want:   http.StatusOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, up.URL)
			cfg.Pinning.Mode = tc.mode
			cfg.Pinning.ReportToken = tc.token
			a := runApp(t, cfg)
			if got := pinsStatus(t, a, tc.bearer); got != tc.want {
				t.Fatalf("GET /pins = %d, want %d", got, tc.want)
			}
		})
	}
}
