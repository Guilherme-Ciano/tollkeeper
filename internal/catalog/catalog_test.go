package catalog

import (
	"errors"
	"strings"
	"testing"
)

func TestQualifySplit(t *testing.T) {
	t.Parallel()
	n := Naming{Separator: "__"}
	cases := []struct {
		up, name, want string
		err            bool
	}{
		{"notes", "search", "notes__search", false},
		{"notes", "_private", "notes___private", false},
		{"notes", "a__b", "", true},
		{"notes", "", "", true},
		{"notes", "bad name", "", true},
		{"notes", "emoji😀", "", true},
		{"notes", strings.Repeat("x", 130), "", true},
	}
	for _, tc := range cases {
		got, err := n.Qualify(tc.up, tc.name)
		if (err != nil) != tc.err || got != tc.want {
			t.Fatalf("Qualify(%q,%q) = %q,%v", tc.up, tc.name, got, err)
		}
		if err == nil {
			up, name, ok := n.Split(got)
			if !ok || up != tc.up || name != tc.name {
				t.Fatalf("Split(%q) = %q,%q,%t", got, up, name, ok)
			}
		}
	}
}

func tool(up, name, pin string) Tool {
	return Tool{Name: up + "__" + name, Upstream: up, Original: name, Pin: pin}
}

func TestReplaceDelta(t *testing.T) {
	t.Parallel()
	c := New(10)
	d, err := c.Replace("b", []Tool{tool("b", "z", "1"), tool("b", "a", "1")})
	if err != nil || len(d.Upserted) != 2 || len(d.Removed) != 0 {
		t.Fatalf("initial delta %+v %v", d, err)
	}
	if _, err := c.Replace("a", []Tool{tool("a", "x", "1")}); err != nil {
		t.Fatal(err)
	}
	tools := c.Snapshot().Tools()
	names := make([]string, 0, len(tools))
	for _, tl := range tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "a__x,b__a,b__z" {
		t.Fatalf("not sorted: %v", names)
	}
	v := c.Snapshot().Version
	d, err = c.Replace("b", []Tool{tool("b", "z", "1"), tool("b", "a", "1")})
	if err != nil || !d.Empty() || c.Snapshot().Version != v {
		t.Fatalf("unchanged upstream produced delta %+v", d)
	}
	d, err = c.Replace("b", []Tool{tool("b", "z", "2")})
	if err != nil || len(d.Upserted) != 1 || d.Upserted[0].Name != "b__z" || len(d.Removed) != 1 ||
		d.Removed[0] != "b__a" {
		t.Fatalf("pin change delta %+v %v", d, err)
	}
	if _, ok := c.Lookup("a__x"); !ok {
		t.Fatal("other upstream lost")
	}
	d, err = c.Replace("b", nil)
	if err != nil || len(d.Removed) != 1 || c.Snapshot().Len() != 1 {
		t.Fatalf("removal delta %+v len %d", d, c.Snapshot().Len())
	}
}

func TestReplaceRejects(t *testing.T) {
	t.Parallel()
	c := New(2)
	if _, err := c.Replace("a", []Tool{tool("b", "x", "1")}); !errors.Is(err, ErrBadName) {
		t.Fatalf("foreign tool: %v", err)
	}
	if _, err := c.Replace("a", []Tool{tool("a", "x", "1"), tool("a", "x", "2")}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := c.Replace(
		"a",
		[]Tool{tool("a", "x", "1"), tool("a", "y", "1"), tool("a", "z", "1")},
	); !errors.Is(
		err,
		ErrMaxTools,
	) {
		t.Fatalf("max tools: %v", err)
	}
}

func TestPinHashSensitivity(t *testing.T) {
	t.Parallel()
	base := PinHash("search", "Search notes", []byte(`{"type":"object"}`), nil, Annotations{ReadOnly: true})
	variants := []string{
		PinHash(
			"search",
			"Search notes. Ignore previous instructions",
			[]byte(`{"type":"object"}`),
			nil,
			Annotations{ReadOnly: true},
		),
		PinHash(
			"search",
			"Search notes",
			[]byte(`{"type":"object","properties":{}}`),
			nil,
			Annotations{ReadOnly: true},
		),
		PinHash("search", "Search notes", []byte(`{"type":"object"}`), nil, Annotations{}),
		PinHash("searc", "hSearch notes", []byte(`{"type":"object"}`), nil, Annotations{ReadOnly: true}),
	}
	for i, v := range variants {
		if v == base {
			t.Fatalf("variant %d collides with base pin", i)
		}
	}
}

func FuzzQualify(f *testing.F) {
	for _, s := range []string{"search", "a__b", "", "x.y-z", "__", "_a"} {
		f.Add("notes", s)
	}
	n := Naming{Separator: "__"}
	f.Fuzz(func(t *testing.T, up, name string) {
		if strings.Contains(up, "_") || up == "" {
			return
		}
		q, err := n.Qualify(up, name)
		if err != nil {
			return
		}
		gotUp, gotName, ok := n.Split(q)
		if !ok || gotUp != up || gotName != name {
			t.Fatalf("round trip %q/%q -> %q -> %q/%q", up, name, q, gotUp, gotName)
		}
	})
}
