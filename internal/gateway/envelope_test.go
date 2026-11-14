package gateway

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseEnvelope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want Envelope
		err  error
	}{
		{
			"tools call",
			`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"notes__search","arguments":{"q":"x"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"c","version":"1"},"traceparent":"00-abc"}}}`,
			Envelope{
				ID: json.RawMessage(
					"7",
				),
				Method:          "tools/call",
				Name:            "notes__search",
				Arguments:       json.RawMessage(`{"q":"x"}`),
				ProtocolVersion: "2026-07-28",
				ClientName:      "c",
				ClientVersion:   "1",
				TraceParent:     "00-abc",
				HasParams:       true,
			},
			nil,
		},
		{
			"notification",
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			Envelope{Method: "notifications/initialized"},
			nil,
		},
		{
			"initialize",
			`{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"legacy","version":"0.1"}}}`,
			Envelope{
				ID:              json.RawMessage(`"a"`),
				Method:          "initialize",
				ProtocolVersion: "2025-11-25",
				ClientName:      "legacy",
				ClientVersion:   "0.1",
				HasParams:       true,
			},
			nil,
		},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, Envelope{}, ErrBatch},
		{
			"duplicate name",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a__b","name":"x__y"}}`,
			Envelope{},
			ErrDuplicateKey,
		},
		{
			"case variant name",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a__b","Name":"x__y"}}`,
			Envelope{},
			ErrDuplicateKey,
		},
		{
			"case variant method",
			`{"jsonrpc":"2.0","id":1,"Method":"tools/call","method":"tools/list"}`,
			Envelope{},
			ErrDuplicateKey,
		},
		{
			"duplicate args key",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a__b","arguments":{"body":"s","body":"long"}}}`,
			Envelope{},
			ErrDuplicateKey,
		},
		{
			"nested duplicate args key",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a__b","arguments":{"x":[{"k":1,"k":2}]}}}`,
			Envelope{},
			ErrDuplicateKey,
		},
		{
			"args not object",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a__b","arguments":[1]}}`,
			Envelope{},
			ErrEnvelope,
		},
		{"bad version", `{"jsonrpc":"1.0","id":1,"method":"x"}`, Envelope{}, ErrEnvelope},
		{"missing method", `{"jsonrpc":"2.0","id":1}`, Envelope{}, ErrEnvelope},
		{
			"name not string",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":1}}`,
			Envelope{},
			ErrEnvelope,
		},
		{"id object", `{"jsonrpc":"2.0","id":{},"method":"x"}`, Envelope{}, ErrEnvelope},
		{"trailing", `{"jsonrpc":"2.0","method":"x"} {}`, Envelope{}, ErrEnvelope},
		{"params array", `{"jsonrpc":"2.0","method":"x","params":[]}`, Envelope{}, ErrEnvelope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseEnvelope([]byte(tc.body))
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if string(got.ID) != string(tc.want.ID) || got.Method != tc.want.Method || got.Name != tc.want.Name ||
				string(got.Arguments) != string(tc.want.Arguments) || got.ProtocolVersion != tc.want.ProtocolVersion ||
				got.ClientName != tc.want.ClientName || got.ClientVersion != tc.want.ClientVersion ||
				got.TraceParent != tc.want.TraceParent || got.HasParams != tc.want.HasParams {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestArgumentTokenLimit(t *testing.T) {
	t.Parallel()
	wide := "{\"a\":[" + strings.Repeat("{},", MaxArgumentTokens) + "{}]}"
	if err := RejectDuplicateKeys([]byte(wide)); !errors.Is(err, ErrTooComplex) {
		t.Fatalf("expected ErrTooComplex, got %v", err)
	}
	ok := "{\"a\":[" + strings.Repeat("{\"k\":1},", 1000) + "{}]}"
	if err := RejectDuplicateKeys([]byte(ok)); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkRejectDuplicateKeysWide(b *testing.B) {
	wide := []byte("{\"a\":[" + strings.Repeat("{},", 30000) + "{}]}")
	b.ReportAllocs()
	b.SetBytes(int64(len(wide)))
	for b.Loop() {
		if err := RejectDuplicateKeys(wide); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzParseEnvelope(f *testing.F) {
	for _, s := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a__b","arguments":{"x":1}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","Name":"b"}}`,
		`[]`, `{}`, `{"jsonrpc":"2.0","id":"x","method":"m","params":null}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		env, err := ParseEnvelope(body)
		if err != nil {
			return
		}
		if env.Method == "" {
			t.Fatal("accepted envelope without method")
		}
		var std map[string]any
		if json.Unmarshal(body, &std) != nil {
			t.Fatalf("strict parser accepted what encoding/json rejects: %q", body)
		}
		if std["method"] != env.Method {
			t.Fatalf("parser differential on method: %q vs %v", env.Method, std["method"])
		}
		if env.Method == "tools/call" {
			params, ok := std["params"].(map[string]any)
			if ok && params["name"] != nil && params["name"] != env.Name {
				t.Fatalf("parser differential on name: %q vs %v", env.Name, params["name"])
			}
		}
	})
}

func FuzzRejectDuplicateKeys(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{"a":[{"x":1},{"x":2}]}`, `[1,{"y":2,"y":3}]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if RejectDuplicateKeys(data) != nil {
			return
		}
		var v any
		if json.Unmarshal(data, &v) != nil {
			return
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if RejectDuplicateKeys(b) != nil {
			t.Fatalf("re-encoded value rejected: %s", b)
		}
	})
}

func BenchmarkParseEnvelope(b *testing.B) {
	body := []byte(
		`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"notes__search","arguments":{"query":"audit","limit":10},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"bench","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}`,
	)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		if _, err := ParseEnvelope(body); err != nil {
			b.Fatal(err)
		}
	}
}

func TestEnvelopeRejectsControlCharsInToolName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{`x\u0000`, `notes__search\u001b[2K`, `a\nb`} {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
		if _, err := ParseEnvelope([]byte(body)); !errors.Is(err, ErrEnvelope) {
			t.Errorf("name %s: err = %v, want ErrEnvelope", name, err)
		}
	}
}
