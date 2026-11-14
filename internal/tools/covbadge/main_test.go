package main

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestParseProfile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		want    float64
		wantErr error
	}{
		{name: "empty profile", in: "mode: atomic\n", want: 0},
		{name: "all covered", in: "mode: atomic\na.go:1.1,2.2 3 1\na.go:3.1,4.2 1 5\n", want: 100},
		{name: "half covered", in: "mode: set\na.go:1.1,2.2 2 1\nb.go:1.1,2.2 2 0\n", want: 50},
		{
			name: "duplicate block counts once and any hit wins",
			in:   "mode: atomic\na.go:1.1,2.2 4 0\na.go:1.1,2.2 4 2\nb.go:1.1,2.2 4 0\n",
			want: 50,
		},
		{name: "missing field", in: "mode: atomic\na.go:1.1,2.2 4\n", wantErr: errMalformed},
		{name: "non numeric count", in: "mode: atomic\na.go:1.1,2.2 4 x\n", wantErr: errMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseProfile(strings.NewReader(tc.in))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRender(t *testing.T) {
	t.Parallel()
	data, err := render(72.345)
	if err != nil {
		t.Fatal(err)
	}
	var b badge
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if b.SchemaVersion != 1 || b.Label != "coverage" || b.Message != "72.3%" || b.Color != "green" {
		t.Fatalf("unexpected badge %+v", b)
	}
}

func TestColorFor(t *testing.T) {
	t.Parallel()
	cases := map[float64]string{
		95: "brightgreen",
		80: "brightgreen",
		75: "green",
		65: "yellowgreen",
		55: "yellow",
		10: "orange",
	}
	for pct, want := range cases {
		if got := colorFor(pct); got != want {
			t.Errorf("colorFor(%v) = %q, want %q", pct, got, want)
		}
	}
}
