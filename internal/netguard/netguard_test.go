package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestIsRestrictedIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		addr       string
		restricted bool
	}{
		{"127.0.0.1", true},
		{"127.255.255.254", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"::", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"100.64.0.1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"fd00:ec2::254", true},
		{"224.0.0.1", true},
		{"ff02::1", true},
		{"240.0.0.1", true},
		{"255.255.255.255", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"::ffff:10.0.0.5", true},
		{"198.18.0.1", true},
		{"192.0.2.1", true},
		{"2001:db8::1", true},
		{"1.1.1.1", false},
		{"8.8.8.8", false},
		{"93.184.216.34", false},
		{"2606:4700:4700::1111", false},
		{"::ffff:93.184.216.34", false},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			t.Parallel()
			ip, err := netip.ParseAddr(tc.addr)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.addr, err)
			}
			if got := IsRestrictedIP(ip); got != tc.restricted {
				t.Fatalf("IsRestrictedIP(%s) = %v, want %v", tc.addr, got, tc.restricted)
			}
		})
	}
}

func TestInvalidAddrIsRestricted(t *testing.T) {
	t.Parallel()
	if !IsRestrictedIP(netip.Addr{}) {
		t.Fatal("zero netip.Addr must be treated as restricted")
	}
	if err := CheckAddrPort("not-an-address"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("CheckAddrPort(invalid) = %v, want ErrBlockedAddress", err)
	}
}

func TestDialerBlocksLoopbackBeforeConnect(t *testing.T) {
	t.Parallel()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: Dialer(2*time.Second, 0, true).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request to loopback succeeded despite blockPrivate=true")
	}
	if !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("error = %v, want ErrBlockedAddress", err)
	}
	if hits != 0 {
		t.Fatalf("loopback server received %d hits, want 0", hits)
	}
}
