package upstream

import (
	"errors"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func fakeLookPath(bins map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		if p, ok := bins[name]; ok {
			return p, nil
		}
		return "", exec.ErrNotFound
	}
}

func TestPlanSandboxModeOffPassesThrough(t *testing.T) {
	t.Parallel()
	cmd := []string{"notes-server", "--stdio"}
	plan, err := PlanSandbox(cmd, config.StdioSandbox{
		Mode:    config.SandboxModeOff,
		WorkDir: "/srv/notes",
		Network: config.SandboxNetworkNone,
	}, osLinux, fakeLookPath(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(plan.Command, cmd) || plan.Dir != "/srv/notes" || plan.UsesBwrap || plan.UsesPrlimit {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}

func TestPlanSandboxLinuxBwrapAndPrlimit(t *testing.T) {
	t.Parallel()
	look := fakeLookPath(map[string]string{
		"bwrap":   "/usr/bin/bwrap",
		"prlimit": "/usr/bin/prlimit",
	})
	sb := config.StdioSandbox{
		Mode:           config.SandboxModeEnforce,
		Backend:        config.SandboxBackendAuto,
		WorkDir:        "/srv/drafts",
		Network:        config.SandboxNetworkNone,
		ReadOnlyPaths:  []string{"/usr", "/lib"},
		ReadWritePaths: []string{"/srv/drafts"},
		RLimits: config.SandboxLimits{
			MaxMemoryMB:   256,
			MaxOpenFiles:  128,
			MaxProcesses:  32,
			MaxFileSizeMB: 16,
		},
	}
	plan, err := PlanSandbox([]string{"mcp-fs", "/srv/drafts"}, sb, osLinux, look)
	if err != nil {
		t.Fatalf("PlanSandbox failed: %v", err)
	}
	if !plan.UsesBwrap || !plan.UsesPrlimit || len(plan.Warnings) != 0 {
		t.Fatalf("unexpected flags/warnings: %+v", plan)
	}
	want := []string{
		"/usr/bin/prlimit",
		"--as=268435456",
		"--nofile=128",
		"--nproc=32",
		"--fsize=16777216",
		"--",
		"/usr/bin/bwrap",
		"--die-with-parent",
		"--new-session",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-net",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/lib", "/lib",
		"--bind", "/srv/drafts", "/srv/drafts",
		"--chdir", "/srv/drafts",
		"--",
		"mcp-fs", "/srv/drafts",
	}
	if !slices.Equal(plan.Command, want) {
		t.Fatalf("command mismatch:\ngot:  %v\nwant: %v", plan.Command, want)
	}
}

func TestPlanSandboxLinuxDefaultReadOnlyRoot(t *testing.T) {
	t.Parallel()
	look := fakeLookPath(map[string]string{"bwrap": "/usr/bin/bwrap"})
	plan, err := PlanSandbox([]string{"srv"}, config.StdioSandbox{
		Mode:    config.SandboxModeEnforce,
		Backend: config.SandboxBackendBwrap,
		Network: config.SandboxNetworkInherit,
	}, osLinux, look)
	if err != nil {
		t.Fatalf("PlanSandbox failed: %v", err)
	}
	joined := strings.Join(plan.Command, " ")
	if !strings.Contains(joined, "--ro-bind / /") || strings.Contains(joined, "--unshare-net") {
		t.Fatalf("unexpected default root args: %s", joined)
	}
}

func TestPlanSandboxEnforceFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		goos string
		bins map[string]string
		sb   config.StdioSandbox
		want string
	}{
		{
			name: "linux missing bwrap",
			goos: osLinux,
			bins: map[string]string{"prlimit": "/usr/bin/prlimit"},
			sb: config.StdioSandbox{
				Mode:    config.SandboxModeEnforce,
				Backend: config.SandboxBackendAuto,
				Network: config.SandboxNetworkNone,
			},
			want: "bwrap",
		},
		{
			name: "linux missing prlimit",
			goos: osLinux,
			bins: map[string]string{"bwrap": "/usr/bin/bwrap"},
			sb: config.StdioSandbox{
				Mode:    config.SandboxModeEnforce,
				Backend: config.SandboxBackendOS,
				RLimits: config.SandboxLimits{MaxOpenFiles: 64},
			},
			want: "prlimit",
		},
		{
			name: "os backend rejects network isolation",
			goos: osLinux,
			bins: map[string]string{"bwrap": "/usr/bin/bwrap"},
			sb: config.StdioSandbox{
				Mode:    config.SandboxModeEnforce,
				Backend: config.SandboxBackendOS,
				Network: config.SandboxNetworkNone,
			},
			want: "backend=bwrap",
		},
		{
			name: "darwin rejects bwrap and rlimits",
			goos: "darwin",
			bins: nil,
			sb: config.StdioSandbox{
				Mode:    config.SandboxModeEnforce,
				Backend: config.SandboxBackendAuto,
				Network: config.SandboxNetworkNone,
				RLimits: config.SandboxLimits{MaxMemoryMB: 128},
			},
			want: "unsupported on darwin",
		},
		{
			name: "windows rejects bwrap",
			goos: "windows",
			bins: nil,
			sb: config.StdioSandbox{
				Mode:          config.SandboxModeEnforce,
				Backend:       config.SandboxBackendAuto,
				ReadOnlyPaths: []string{"/usr"},
			},
			want: "unsupported on windows",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := PlanSandbox([]string{"srv"}, tc.sb, tc.goos, fakeLookPath(tc.bins))
			if !errors.Is(err, ErrSandboxUnsupported) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("PlanSandbox = %v, want ErrSandboxUnsupported containing %q", err, tc.want)
			}
		})
	}
}

func TestPlanSandboxWarnDegradesGracefully(t *testing.T) {
	t.Parallel()
	plan, err := PlanSandbox([]string{"srv"}, config.StdioSandbox{
		Mode:    config.SandboxModeWarn,
		Backend: config.SandboxBackendAuto,
		Network: config.SandboxNetworkNone,
		RLimits: config.SandboxLimits{MaxOpenFiles: 64},
	}, "darwin", fakeLookPath(nil))
	if err != nil {
		t.Fatalf("warn mode should not fail: %v", err)
	}
	if len(plan.Warnings) != 2 || !slices.Equal(plan.Command, []string{"srv"}) {
		t.Fatalf("unexpected warn plan: %+v", plan)
	}
}

func TestFactoryFailsFastOnUnsupportedEnforcedSandbox(t *testing.T) {
	t.Parallel()
	_, err := Factory(t.Context(), config.Upstream{
		ID:        "notes",
		Transport: config.TransportStdio,
		Command:   []string{"notes-server"},
		Sandbox: config.StdioSandbox{
			Mode:    config.SandboxModeEnforce,
			Backend: config.SandboxBackendOS,
			Network: config.SandboxNetworkNone,
		},
	}, slog.New(slog.DiscardHandler), LookupEnv)
	if !errors.Is(err, ErrSandboxUnsupported) {
		t.Fatalf("Factory = %v, want ErrSandboxUnsupported", err)
	}
}
