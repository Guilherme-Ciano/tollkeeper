package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitProfilesValidateAndPassFixtures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "local default",
			args: nil,
			want: "http://localhost:8080/mcp",
		},
		{
			name: "local custom http upstream",
			args: []string{
				"--upstream-url", "https://mcp.internal.example/mcp",
				"--listen", "127.0.0.1:8181",
			},
			want: "http://localhost:8181/mcp",
		},
		{
			name: "local custom stdio upstream",
			args: []string{
				"--upstream-id", "docs",
				"--upstream-cmd", "my-mcp-server",
				"--upstream-cmd", "--stdio",
			},
			want: "http://localhost:8080/mcp",
		},
		{
			name: "team default",
			args: []string{"--profile", "team"},
			want: "https://mcp.example.com/mcp",
		},
		{
			name: "team custom upstream",
			args: []string{
				"--profile", "team",
				"--upstream-id", "crm",
				"--upstream-url", "https://crm-mcp.example.com/mcp",
				"--public-url", "https://gw.example.com/mcp",
			},
			want: "https://gw.example.com/mcp",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			args := append([]string{"init", "-d", dir}, tc.args...)
			out, err := runRoot(t, args...)
			if err != nil {
				t.Fatalf("init failed: %v\n%s", err, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("output missing %q:\n%s", tc.want, out)
			}
			cfgPath := filepath.Join(dir, "tollkeeper.yaml")
			fixPath := filepath.Join(dir, "policies_test.yaml")
			if out, err := runRoot(t, "config", "validate", "-c", cfgPath); err != nil {
				t.Fatalf("config validate failed: %v\n%s", err, out)
			}
			if out, err := runRoot(t, "policy", "test", "-c", cfgPath, "-f", fixPath); err != nil {
				t.Fatalf("policy test failed: %v\n%s", err, out)
			}
		})
	}
}

func TestInitRefusesOverwriteAndPreservesKeysOnForce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if out, err := runRoot(t, "init", "-d", dir); err != nil {
		t.Fatalf("first init failed: %v\n%s", err, out)
	}
	privPath := filepath.Join(dir, "keys", "audit-ed25519.pem")
	firstKey, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runRoot(t, "init", "-d", dir); !errors.Is(err, ErrInit) {
		t.Fatalf("second init without --force = %v, want ErrInit", err)
	}
	out, err := runRoot(t, "init", "-d", dir, "--profile", "team", "--force")
	if err != nil {
		t.Fatalf("init --force failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "kept existing") {
		t.Fatalf("expected existing key to be preserved, got:\n%s", out)
	}
	secondKey, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstKey, secondKey) {
		t.Fatal("init --force replaced an existing audit signing key")
	}
}

func TestInitRejectsInvalidFlags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
	}{
		{"unknown profile", []string{"--profile", "enterprise"}},
		{"both url and cmd", []string{"--upstream-url", "https://example.com/mcp", "--upstream-cmd", "echo"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			args := append([]string{"init", "-d", dir}, tc.args...)
			if _, err := runRoot(t, args...); !errors.Is(err, ErrInit) {
				t.Fatalf("init %v = %v, want ErrInit", tc.args, err)
			}
		})
	}
}
