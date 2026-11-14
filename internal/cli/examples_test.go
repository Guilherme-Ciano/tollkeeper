package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleConfigsValidate(t *testing.T) {
	t.Setenv("GITHUB_PAT", "placeholder")
	paths, err := filepath.Glob(filepath.Join("..", "..", "examples", "configs", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no example configs found")
	}
	for _, p := range paths {
		out, err := runRoot(t, "config", "validate", "-c", p)
		if err != nil || !strings.Contains(out, "OK") {
			t.Errorf("%s: %v\n%s", p, err, out)
		}
	}
}
