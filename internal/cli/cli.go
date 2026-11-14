package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Guilherme-Ciano/tollkeeper/internal/app"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/devissuer"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
	"github.com/Guilherme-Ciano/tollkeeper/internal/ratelimit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/telemetry"
)

var (
	ErrPolicyFixtures = errors.New("policy fixtures failed")
	ErrUnhealthy      = errors.New("health check failed")
	ErrVerify         = errors.New("audit verification failed")
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

func printf(w io.Writer, format string, args ...any) error {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func loadConfig(path string) (config.Config, error) {
	cfg, err := config.Load(path, os.LookupEnv)
	if err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("%s:\n%w", path, err)
	}
	return cfg, nil
}

func Root(info BuildInfo, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "tollkeeper",
		Short:         "MCP gateway with OAuth resource server, CEL policies, GCRA rate limits and a verifiable audit log",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(serveCmd(info), versionCmd(info), configCmd(), policyCmd(), auditCmd(), devIssuerCmd(), healthCmd())
	return root
}

func versionCmd(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printf(
				cmd.OutOrStdout(),
				"tollkeeper %s (commit %s, built %s)\n",
				info.Version,
				info.Commit,
				info.Date,
			)
		},
	}
}

func serveCmd(info BuildInfo) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the gateway",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(path)
			if err != nil {
				return err
			}
			log := telemetry.NewLogger(cmd.ErrOrStderr(), cfg.Telemetry.LogLevel, cfg.Telemetry.LogFormat)
			slog.SetDefault(log)
			log.Info("config loaded", slog.String("path", path), slog.String("sha256", cfg.Digest))
			if cfg.Audit.RecordArgs == config.RecordArgsFull {
				log.Warn("audit.record_args=full stores raw tool arguments, which may contain personal data")
			}
			a, err := app.Build(cmd.Context(), cfg, log, info.Version)
			if err != nil {
				return err
			}
			return a.Run(cmd.Context())
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", "tollkeeper.yaml", "config file")
	return cmd
}

func configCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Configuration tools"}
	var path string
	validate := &cobra.Command{
		Use:   "validate",
		Short: "Validate a config file, compile its policies and rate limits",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(path)
			if err != nil {
				return err
			}
			if _, err := policy.New(cfg.Policy); err != nil {
				return err
			}
			if _, err := ratelimit.New(cfg.RateLimits, ratelimit.NewStore(nil)); err != nil {
				return err
			}
			return printf(cmd.OutOrStdout(), "%s: OK (%d upstreams, %d policy rules, %d rate limit rules)\n",
				path, len(cfg.Upstreams), len(cfg.Policy.Rules), len(cfg.RateLimits.Rules))
		},
	}
	validate.Flags().StringVarP(&path, "config", "c", "tollkeeper.yaml", "config file")
	cmd.AddCommand(validate)
	return cmd
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Policy tools"}
	var path, fixtures string
	test := &cobra.Command{
		Use:   "test",
		Short: "Run table-driven policy fixtures against the config's policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(path)
			if err != nil {
				return err
			}
			eng, err := policy.New(cfg.Policy)
			if err != nil {
				return err
			}
			f, err := os.Open(fixtures)
			if err != nil {
				return fmt.Errorf("open fixtures: %w", err)
			}
			defer f.Close()
			ff, err := policy.ParseFixtures(f)
			if err != nil {
				return err
			}
			results, err := eng.RunFixtures(cmd.Context(), ff, cfg.Server.NamespaceSeparator)
			if err != nil {
				return err
			}
			failed := 0
			out := cmd.OutOrStdout()
			for _, r := range results {
				if r.Pass {
					fmt.Fprintf(out, "PASS  %s (%s via %s)\n", r.Name, r.Got.Effect, r.Got.Rule)
					continue
				}
				failed++
				fmt.Fprintf(out, "FAIL  %s: %s\n", r.Name, r.Detail)
			}
			fmt.Fprintf(out, "%d passed, %d failed\n", len(results)-failed, failed)
			if failed > 0 {
				return fmt.Errorf("%w: %d of %d", ErrPolicyFixtures, failed, len(results))
			}
			return nil
		},
	}
	test.Flags().StringVarP(&path, "config", "c", "tollkeeper.yaml", "config file")
	test.Flags().StringVarP(&fixtures, "fixtures", "f", "policies_test.yaml", "fixture file")
	cmd.AddCommand(test)
	return cmd
}

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit log tools"}
	cmd.AddCommand(verifyCmd(), keygenCmd())
	return cmd
}

type verifyOpts struct {
	file         string
	pubkey       string
	chainID      string
	maxUnsigned  uint64
	noSignatures bool
}

func verifyCmd() *cobra.Command {
	var o verifyOpts
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Recompute the hash chain and check Ed25519 checkpoints",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd.OutOrStdout(), o)
		},
	}
	verify.Flags().StringVarP(&o.file, "file", "f", "audit.jsonl", "audit JSONL file")
	verify.Flags().StringVar(&o.pubkey, "pubkey", "", "Ed25519 public key (PEM); required unless --no-signatures")
	verify.Flags().StringVar(&o.chainID, "chain-id", "", "expected chain id")
	verify.Flags().
		Uint64Var(&o.maxUnsigned, "max-unsigned", 1000, "maximum records allowed after the last signed checkpoint")
	verify.Flags().
		BoolVar(&o.noSignatures, "no-signatures", false, "only check the hash chain; it does not prove authenticity")
	return verify
}

func checkSignatures(rep audit.Report, o verifyOpts) error {
	if o.chainID != "" && rep.Records > 0 && rep.ChainID != o.chainID {
		return fmt.Errorf("%w: chain id %q, expected %q", ErrVerify, rep.ChainID, o.chainID)
	}
	if o.noSignatures || rep.Records == 0 {
		return nil
	}
	if rep.Checkpoints == 0 {
		return fmt.Errorf(
			"%w: no signed checkpoint in %d records; the chain could have been rewritten",
			ErrVerify,
			rep.Records,
		)
	}
	if rep.UnsignedTail > o.maxUnsigned {
		return fmt.Errorf("%w: %d records after the last signed checkpoint (seq %d) exceed --max-unsigned %d",
			ErrVerify, rep.UnsignedTail, rep.LastSignedSeq, o.maxUnsigned)
	}
	return nil
}

func runVerify(out io.Writer, o verifyOpts) error {
	if o.pubkey == "" && !o.noSignatures {
		return fmt.Errorf("%w: pass --pubkey, or --no-signatures to check only the hash chain", ErrVerify)
	}
	f, err := os.Open(o.file)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	var pub []byte
	if o.pubkey != "" {
		k, err := audit.LoadPublicKey(o.pubkey)
		if err != nil {
			return err
		}
		pub = k
	}
	rep, err := audit.Verify(f, pub)
	if err != nil {
		return errors.Join(printf(out, "FAIL %s after %d valid records\n", err, rep.Records), err)
	}
	if err := checkSignatures(rep, o); err != nil {
		return errors.Join(printf(out, "FAIL %s\n", err), err)
	}
	if err := printf(
		out,
		"OK chain=%s records=%d events=%d checkpoints=%d last_seq=%d last_hash=%s unsigned_tail=%d\n",
		rep.ChainID,
		rep.Records,
		rep.Events,
		rep.Checkpoints,
		rep.LastSeq,
		rep.LastHash,
		rep.UnsignedTail,
	); err != nil {
		return err
	}
	if rep.Gaps > 0 {
		if err := printf(
			out,
			"WARN %d gap records cover %d dropped events\n",
			rep.Gaps,
			rep.DroppedEvents,
		); err != nil {
			return err
		}
	}
	if o.noSignatures {
		return printf(out, "WARN signatures not checked: the hash chain alone does not prove authenticity\n")
	}
	return nil
}

func keygenCmd() *cobra.Command {
	var dir string
	var ifMissing bool
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 checkpoint signing key pair",
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, pub, err := audit.GenerateKeyPair()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return fmt.Errorf("create key dir: %w", err)
			}
			privPath, pubPath := filepath.Join(dir, "audit-ed25519.pem"), filepath.Join(dir, "audit-ed25519.pub")
			if _, err := os.Stat(privPath); err == nil && ifMissing {
				return printf(cmd.OutOrStdout(), "%s exists, keeping it\n", privPath)
			}
			if err := writeNew(privPath, priv, 0o600); err != nil {
				return err
			}
			if err := writeNew(pubPath, pub, 0o644); err != nil {
				return err
			}
			return printf(cmd.OutOrStdout(), "wrote %s and %s\n", privPath, pubPath)
		},
	}
	keygen.Flags().StringVarP(&dir, "out-dir", "o", ".", "output directory")
	keygen.Flags().BoolVar(&ifMissing, "if-missing", false, "do nothing when the key already exists")
	return keygen
}

func writeNew(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Close())
}

func devIssuerCmd() *cobra.Command {
	var path string
	var insecure bool
	cmd := &cobra.Command{
		Use:   "dev-issuer",
		Short: "Run the built-in DEV ONLY OAuth 2.1 authorization server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return RunDevIssuer(cmd.Context(), path, insecure, cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", "devissuer.yaml", "dev issuer config")
	cmd.Flags().BoolVar(&insecure, "i-know-this-is-insecure", false, "allow binding a non-loopback address")
	return cmd
}

func RunDevIssuer(ctx context.Context, path string, insecure bool, stderr io.Writer) error {
	log := telemetry.NewLogger(stderr, "info", "json")
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open dev issuer config: %w", err)
	}
	cfg, err := devissuer.ParseConfig(f)
	_ = f.Close()
	if err != nil {
		return err
	}
	if err := devissuer.CheckListen(cfg.Listen, insecure); err != nil {
		return err
	}
	log.WarnContext(
		ctx,
		"DEV ONLY OAuth issuer: auto-approves logins, never expose it",
		slog.String("issuer", cfg.Issuer),
		slog.String("listen", cfg.Listen),
	)
	iss, err := devissuer.New(cfg, nil, log)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           iss.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		return fmt.Errorf("dev issuer: %w", err)
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			return fmt.Errorf("dev issuer shutdown: %w", err)
		}
		return nil
	}
}

func healthCmd() *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Probe a health endpoint (for distroless container healthchecks)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 3*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
			if err != nil {
				return fmt.Errorf("health request: %w", err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrUnhealthy, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%w: status %d", ErrUnhealthy, resp.StatusCode)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "url", "http://127.0.0.1:9090/readyz", "URL to probe")
	return cmd
}
