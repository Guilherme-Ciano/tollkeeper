package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const explainConfig = `server:
  public_url: "http://localhost:8080/mcp"
auth:
  mode: none
upstreams:
  - id: notes
    transport: streamable_http
    url: "http://127.0.0.1:3001/mcp"
policy:
  default: deny
  rules:
    - name: watch-deletes
      tools: ["notes__delete"]
      effect: deny
      mode: shadow
    - name: notes-for-editors
      tools: ["notes__*"]
      subjects: { scopes_any: ["notes:write"] }
      effect: allow
    - name: docs
      resources: ["file:///docs/*"]
      effect: allow
audit:
  enabled: false
`

func TestPolicyExplain(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "gw.yaml")
	if err := os.WriteFile(path, []byte(explainConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runRoot(t, "policy", "explain", "-c", path, "--sub", "ana", "--scope", "notes:write",
		"--tool", "notes__delete")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"watch-deletes      shadow   matches: deny",
		"decision: allow via notes-for-editors",
		"shadow:   watch-deletes would deny",
		"visible:  true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	out, err = runRoot(t, "policy", "explain", "-c", path, "--resource", "file:///etc/passwd")
	if err != nil || !strings.Contains(out, "decision: deny via default") || !strings.Contains(out, "visible:  false") {
		t.Fatalf("resource: %v\n%s", err, out)
	}
	if _, err := runRoot(
		t,
		"policy",
		"explain",
		"-c",
		path,
		"--tool",
		"a",
		"--prompt",
		"b",
	); !errors.Is(
		err,
		ErrExplainTarget,
	) {
		t.Fatalf("two targets: %v", err)
	}
}
