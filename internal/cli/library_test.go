package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestReusablePolicyLibraryFixtures(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("..", "..", "policies", "library")
	fixtures, err := filepath.Glob(filepath.Join(dir, "*_test.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 5 {
		t.Fatalf("expected at least 5 library policy fixture packs, found %d", len(fixtures))
	}
	for _, fx := range fixtures {
		cfgPath := strings.TrimSuffix(fx, "_test.yaml") + ".yaml"
		t.Run(filepath.Base(cfgPath), func(t *testing.T) {
			t.Parallel()
			out, err := runRoot(t, "policy", "test", "-c", cfgPath, "-f", fx)
			if err != nil || !strings.Contains(out, "0 failed") {
				t.Fatalf("policy test %s failed: err=%v\n%s", cfgPath, err, out)
			}
		})
	}
}
