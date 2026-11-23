package config

import (
	"strings"
	"testing"
)

func TestParseAndValidateStdioSandbox(t *testing.T) {
	t.Parallel()
	raw := `
server:
  public_url: "http://localhost:8080/mcp"
auth:
  mode: none
upstreams:
  - id: fs
    transport: stdio
    command: ["mcp-fs", "/srv/shared"]
    sandbox:
      mode: enforce
      backend: bwrap
      workdir: "/srv/shared"
      network: none
      read_only_paths: ["/usr", "/lib"]
      read_write_paths: ["/srv/shared/drafts"]
      rlimits:
        max_memory_mb: 256
        max_open_files: 128
        max_processes: 32
        max_file_size_mb: 16
policy:
  default: deny
audit:
  enabled: false
`
	cfg, err := Parse([]byte(raw), func(string) (string, bool) { return "", false }, func() []string { return nil })
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	sb := cfg.Upstreams[0].Sandbox
	if sb.Mode != SandboxModeEnforce || sb.Backend != SandboxBackendBwrap || sb.Network != SandboxNetworkNone {
		t.Fatalf("unexpected sandbox config: %+v", sb)
	}
	if sb.RLimits.MaxMemoryMB != 256 || sb.RLimits.MaxOpenFiles != 128 {
		t.Fatalf("unexpected rlimits: %+v", sb.RLimits)
	}
}

func TestValidateRejectsInvalidSandboxConfigs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "sandbox on streamable_http",
			yaml: `
server: { public_url: "http://localhost:8080/mcp" }
auth: { mode: none }
upstreams:
  - id: api
    transport: streamable_http
    url: "https://mcp.example.com/mcp"
    sandbox: { mode: enforce }
audit: { enabled: false }
`,
			want: "only allowed for stdio transport",
		},
		{
			name: "relative path in read_only_paths",
			yaml: `
server: { public_url: "http://localhost:8080/mcp" }
auth: { mode: none }
upstreams:
  - id: fs
    transport: stdio
    command: ["mcp-fs"]
    sandbox:
      mode: enforce
      read_only_paths: ["./relative"]
audit: { enabled: false }
`,
			want: "read_only_paths[0]",
		},
		{
			name: "negative rlimit",
			yaml: `
server: { public_url: "http://localhost:8080/mcp" }
auth: { mode: none }
upstreams:
  - id: fs
    transport: stdio
    command: ["mcp-fs"]
    sandbox:
      mode: warn
      rlimits: { max_memory_mb: -1 }
audit: { enabled: false }
`,
			want: "max_memory_mb",
		},
		{
			name: "unknown mode",
			yaml: `
server: { public_url: "http://localhost:8080/mcp" }
auth: { mode: none }
upstreams:
  - id: fs
    transport: stdio
    command: ["mcp-fs"]
    sandbox: { mode: strict }
audit: { enabled: false }
`,
			want: "sandbox.mode",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := Parse([]byte(tc.yaml), func(string) (string, bool) { return "", false }, func() []string { return nil })
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			err = cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
