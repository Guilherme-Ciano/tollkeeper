package gateway

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func testSealer() *stateSealer {
	return newStateSealer(bytes.Repeat([]byte{7}, MinStateKeyLen), time.Minute)
}

func TestRequestStateRoundTrip(t *testing.T) {
	t.Parallel()
	s := testSealer()
	now := time.Unix(1_800_000_000, 0)
	want := statePayload{Upstream: "notes", Tool: "search", Subject: "alice", ClientID: "cli", Inner: "opaque-ü"}
	tok, err := s.seal(want, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.open(tok, now.Add(59*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want.Expires = now.Add(time.Minute).Unix()
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRequestStateRejects(t *testing.T) {
	t.Parallel()
	s := testSealer()
	now := time.Unix(1_800_000_000, 0)
	tok, err := s.seal(statePayload{Upstream: "u", Tool: "t", Inner: "x"}, now)
	if err != nil {
		t.Fatal(err)
	}
	other := newStateSealer(bytes.Repeat([]byte{8}, MinStateKeyLen), time.Minute)
	foreign, err := other.seal(statePayload{Upstream: "u", Tool: "t", Inner: "x"}, now)
	if err != nil {
		t.Fatal(err)
	}
	body, sig, _ := strings.Cut(tok[len(statePrefix):], ".")
	cases := map[string]struct {
		token string
		at    time.Time
	}{
		"expired":        {tok, now.Add(time.Minute)},
		"appended":       {tok + "-TAMPERED", now},
		"other key":      {foreign, now},
		"swapped body":   {statePrefix + body + "x." + sig, now},
		"no prefix":      {tok[len(statePrefix):], now},
		"no signature":   {statePrefix + body, now},
		"empty":          {"", now},
		"raw upstream":   {"st-1", now},
		"oversized":      {statePrefix + strings.Repeat("a", maxStateToken) + "." + sig, now},
		"bad base64 sig": {statePrefix + body + ".!!", now},
	}
	for name, tc := range cases {
		if _, err := s.open(tc.token, tc.at); !errors.Is(err, ErrRequestState) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestEphemeralKeysDiffer(t *testing.T) {
	t.Parallel()
	a, b := newStateSealer(nil, 0), newStateSealer(nil, 0)
	if len(a.key) < MinStateKeyLen || bytes.Equal(a.key, b.key) || a.ttl != DefaultStateTTL {
		t.Fatalf("ephemeral keys: %d bytes, equal=%t, ttl=%v", len(a.key), bytes.Equal(a.key, b.key), a.ttl)
	}
}

func FuzzOpenRequestState(f *testing.F) {
	s := testSealer()
	now := time.Unix(1_800_000_000, 0)
	tok, err := s.seal(statePayload{Upstream: "u", Tool: "t", Subject: "s", Inner: "i"}, now)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tok)
	f.Add(tok + "x")
	f.Add("tk1..")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		p, err := s.open(token, now)
		if err != nil {
			return
		}
		again, err := s.seal(p, time.Unix(p.Expires, 0).Add(-s.ttl))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.open(again, now); err != nil {
			t.Fatalf("resealed state does not open: %v", err)
		}
		if token != tok {
			raw := token[len(statePrefix):strings.LastIndexByte(token, '.')]
			if !strings.HasPrefix(tok, statePrefix+raw) {
				t.Fatalf("forged token accepted: %q", token)
			}
		}
	})
}

func TestTamperedStateIsAProtocolError(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	for _, disable := range []bool{false, true} {
		s := newDiffSide(t, disable, schema)
		got := s.do(t, statelessHeaders(), callBody(`1`, `"arguments":{"mode":"text"},"requestState":"`+
			diffSeal(t, "t")+`-TAMPERED",`+statelessMeta))
		if got.status != 400 || !strings.Contains(got.body, `"code":-32602`) {
			t.Fatalf("disable=%t: %+v", disable, got)
		}
		if calls := s.caller.take(); len(calls) != 0 {
			t.Fatalf("disable=%t: tampered state reached the upstream", disable)
		}
	}
}

func TestSealedStateRoundTripsThroughTheGateway(t *testing.T) {
	t.Parallel()
	schema := map[string]any{"name": "up__t", "inputSchema": map[string]any{"type": "object"}}
	s := newDiffSide(t, false, schema)
	first := s.do(t, statelessHeaders(), callBody(`1`, `"arguments":{"mode":"input"},`+statelessMeta))
	if strings.Contains(first.body, `"requestState":"st-1"`) || !strings.Contains(first.body, `"requestState":"tk1.`) {
		t.Fatalf("upstream state leaked unsealed: %s", first.body)
	}
	start := strings.Index(first.body, `"requestState":"`) + len(`"requestState":"`)
	tok := first.body[start : start+strings.IndexByte(first.body[start:], '"')]
	s.caller.take()
	s.do(t, statelessHeaders(), callBody(`2`, `"arguments":{"mode":"text"},"requestState":"`+tok+`",`+statelessMeta))
	calls := s.caller.take()
	if len(calls) != 1 || calls[0].RequestState != "st-1" {
		t.Fatalf("upstream did not get its own state back: %+v", calls)
	}
}
