package upstream

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
)

const (
	osLinux         = "linux"
	bytesPerMiB     = int64(1 << 20)
	bwrapBinaryName = "bwrap"
	prlimitBinary   = "prlimit"
	sandboxArgSep   = "--"
	bwrapRoBindFlag = "--ro-bind"
	bwrapRwBindFlag = "--bind"
	bwrapChdirFlag  = "--chdir"
	bwrapUnshareNet = "--unshare-net"
)

var ErrSandboxUnsupported = errors.New("stdio sandbox requirements unsupported on this host")

type SandboxPlan struct {
	Command     []string
	Dir         string
	Warnings    []string
	UsesBwrap   bool
	UsesPrlimit bool
}

func PlanHostSandbox(cmd []string, sb config.StdioSandbox) (SandboxPlan, error) {
	return PlanSandbox(cmd, sb, runtime.GOOS, exec.LookPath)
}

func PlanSandbox(
	cmd []string,
	sb config.StdioSandbox,
	goos string,
	lookPath func(string) (string, error),
) (SandboxPlan, error) {
	plan := SandboxPlan{
		Command: append([]string(nil), cmd...),
		Dir:     sb.WorkDir,
	}
	mode := sb.Mode
	if mode == "" || mode == config.SandboxModeOff {
		return plan, nil
	}
	needsIsolation := sb.Network == config.SandboxNetworkNone ||
		len(sb.ReadOnlyPaths) > 0 ||
		len(sb.ReadWritePaths) > 0
	wantBwrap := sb.Backend == config.SandboxBackendBwrap ||
		(sb.Backend == config.SandboxBackendAuto && needsIsolation)
	wantPrlimit := sb.RLimits.Any()

	var missing []string
	if sb.Backend == config.SandboxBackendOS && needsIsolation {
		missing = append(missing, "network and filesystem isolation require backend=bwrap or backend=auto")
	}
	if goos != osLinux {
		missing = appendNonLinuxGaps(missing, goos, wantBwrap, wantPrlimit)
		return finalizeSandboxPlan(plan, mode, missing)
	}
	if wantBwrap {
		bin, err := lookPath(bwrapBinaryName)
		if err != nil {
			missing = append(missing, "bwrap binary not found in PATH")
		} else {
			plan.Command = wrapBwrap(bin, sb, plan.Command)
			plan.UsesBwrap = true
		}
	}
	if wantPrlimit {
		bin, err := lookPath(prlimitBinary)
		if err != nil {
			missing = append(missing, "prlimit binary not found in PATH")
		} else {
			plan.Command = wrapPrlimit(bin, sb.RLimits, plan.Command)
			plan.UsesPrlimit = true
		}
	}
	return finalizeSandboxPlan(plan, mode, missing)
}

func appendNonLinuxGaps(missing []string, goos string, wantBwrap, wantPrlimit bool) []string {
	if wantBwrap {
		missing = append(missing, "namespace/filesystem sandboxing (bwrap) is unsupported on "+goos)
	}
	if wantPrlimit {
		missing = append(missing, "rlimit sandboxing (prlimit) is unsupported on "+goos)
	}
	return missing
}

func finalizeSandboxPlan(plan SandboxPlan, mode string, missing []string) (SandboxPlan, error) {
	if len(missing) == 0 {
		return plan, nil
	}
	if mode == config.SandboxModeEnforce {
		return SandboxPlan{}, fmt.Errorf("%w: %s", ErrSandboxUnsupported, strings.Join(missing, "; "))
	}
	plan.Warnings = missing
	return plan, nil
}

func wrapBwrap(bin string, sb config.StdioSandbox, cmd []string) []string {
	args := []string{
		bin,
		"--die-with-parent",
		"--new-session",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
	}
	if sb.Network == config.SandboxNetworkNone {
		args = append(args, bwrapUnshareNet)
	}
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp")
	if len(sb.ReadOnlyPaths) == 0 && len(sb.ReadWritePaths) == 0 {
		args = append(args, bwrapRoBindFlag, "/", "/")
	} else {
		for _, p := range sb.ReadOnlyPaths {
			args = append(args, bwrapRoBindFlag, p, p)
		}
		for _, p := range sb.ReadWritePaths {
			args = append(args, bwrapRwBindFlag, p, p)
		}
	}
	if sb.WorkDir != "" {
		args = append(args, bwrapChdirFlag, sb.WorkDir)
	}
	args = append(args, sandboxArgSep)
	return append(args, cmd...)
}

func wrapPrlimit(bin string, l config.SandboxLimits, cmd []string) []string {
	args := []string{bin}
	if l.MaxMemoryMB > 0 {
		args = append(args, "--as="+strconv.FormatInt(l.MaxMemoryMB*bytesPerMiB, 10))
	}
	if l.MaxOpenFiles > 0 {
		args = append(args, "--nofile="+strconv.FormatInt(l.MaxOpenFiles, 10))
	}
	if l.MaxProcesses > 0 {
		args = append(args, "--nproc="+strconv.FormatInt(l.MaxProcesses, 10))
	}
	if l.MaxFileSizeMB > 0 {
		args = append(args, "--fsize="+strconv.FormatInt(l.MaxFileSizeMB*bytesPerMiB, 10))
	}
	args = append(args, sandboxArgSep)
	return append(args, cmd...)
}
