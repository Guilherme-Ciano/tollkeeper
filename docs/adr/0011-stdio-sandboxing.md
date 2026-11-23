# ADR 0011: Stdio upstream sandboxing

## Context

Stdio MCP servers run as child processes of the gateway. Before this change, tollkeeper restricted their environment via an explicit allowlist (`env_passthrough` + `env`) and killed their process group on shutdown (`Setpgid`), but a compromised or buggy stdio server still inherited the host filesystem view, network access, open-file/memory limits, and could survive as an orphan if the gateway died abruptly (`SIGKILL`).

At the same time, tollkeeper ships as a single static Go binary (`CGO_ENABLED=0`) across Linux, macOS and Windows, and `go-sdk`'s `mcp.CommandTransport` owns calling `exec.Cmd.Start()`.

## Decision

1. **Linux `Pdeathsig: SIGKILL` by default:** On Linux, every stdio subprocess sets `SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}` so the kernel terminates the child immediately if the gateway process dies unexpectedly.
2. **Declarative per-upstream `sandbox` configuration (`off` | `warn` | `enforce`):**
   - `rlimits` (`max_memory_mb`, `max_open_files`, `max_processes`, `max_file_size_mb`) are enforced pre-`execve` on Linux via `prlimit` (no shell interpolation).
   - Namespace and filesystem isolation (`network: none`, `read_only_paths`, `read_write_paths`, PID/IPC/UTS unsharing, `--die-with-parent`, `--new-session`) are enforced on Linux via `bwrap` (bubblewrap), defaulting to a read-only rootfs when no explicit path lists are given.
   - `workdir` sets the subprocess working directory (`--chdir` inside `bwrap`, or `exec.Cmd.Dir` otherwise).
3. **Strict fail-closed enforcement:** When `sandbox.mode: enforce` is set, `upstream.Factory` resolves and verifies host capabilities at startup and refuses to start (`ErrSandboxUnsupported`) if the host OS or missing binaries (`bwrap`/`prlimit`) cannot satisfy every requested control. In `warn` mode, missing controls are logged explicitly and available controls still apply.

## Alternatives considered

- **CGO bindings to libseccomp / Landlock C wrappers:** Breaks static `CGO_ENABLED=0` cross-compilation in GoReleaser.
- **Silent best-effort fallback everywhere:** Dangerous for security gateways — operators who configure `network: none` or `read_write_paths` must know immediately if the host cannot enforce it.
- **Running every stdio server inside a separate Docker/OCI container:** Requires a container daemon socket (often a worse privilege escalation surface than the host itself).

## Consequences

- Zero new Go dependencies and zero impact on `CGO_ENABLED=0` static binaries.
- Production Linux deployments that want full namespace/FS isolation install `bubblewrap` (`bwrap`) and `util-linux` (`prlimit`) in their runtime image or host.
- Non-Linux hosts (macOS/Windows) support `mode: warn` (applying `workdir` and `StdioEnv`) and fail closed under `mode: enforce` when Linux-only controls are requested.
