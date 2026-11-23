//go:build linux

package upstream

import (
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

func TestLinuxProcessGroupSetsPdeathsig(t *testing.T) {
	t.Parallel()
	attr := processGroup()
	if !attr.Setpgid || attr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("processGroup() = %+v, want Setpgid=true and Pdeathsig=SIGKILL", attr)
	}
}

func TestLinuxPrlimitEnforcesOpenFileLimit(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("prlimit"); err != nil {
		t.Skip("prlimit not available")
	}
	plan, err := PlanHostSandbox(
		[]string{"/bin/sh", "-c", "ulimit -n"},
		config.StdioSandbox{
			Mode:    config.SandboxModeEnforce,
			Backend: config.SandboxBackendOS,
			RLimits: config.SandboxLimits{MaxOpenFiles: 128},
		},
	)
	if err != nil {
		t.Fatalf("PlanHostSandbox failed: %v", err)
	}
	out, err := exec.CommandContext(t.Context(), plan.Command[0], plan.Command[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("run sandboxed command: %v (%s)", err, string(out))
	}
	if got := strings.TrimSpace(string(out)); got != "128" {
		t.Fatalf("child ulimit -n = %q, want 128", got)
	}
}
