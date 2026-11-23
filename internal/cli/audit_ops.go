package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit/pgsink"
)

func runVerifyAllChains(out io.Writer, o verifyOpts) error {
	if o.postgres == "" {
		return fmt.Errorf("%w: --all-chains requires --postgres", ErrVerify)
	}
	if o.chainID != "" {
		return fmt.Errorf("%w: --all-chains and --chain-id are mutually exclusive", ErrVerify)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	sink, err := pgsink.Connect(ctx, o.postgres)
	if err != nil {
		cancel()
		return fmt.Errorf("%w: %w", ErrSource, err)
	}
	chains, err := sink.ListChains(ctx)
	sink.Close()
	cancel()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSource, err)
	}
	if len(chains) == 0 {
		err := fmt.Errorf("%w: no audit chains found in postgres", ErrVerify)
		return errors.Join(printf(out, "FAIL %s\n", err), err)
	}
	var errs []error
	for _, id := range chains {
		perChain := o
		perChain.allChains = false
		perChain.chainID = id
		if err := runVerify(out, perChain); err != nil {
			errs = append(errs, fmt.Errorf("chain %s: %w", id, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return printf(out, "SUMMARY chains=%d status=ok\n", len(chains))
}

func archiveCmd() *cobra.Command {
	var file, outDir, pubkey, pubkeyDir string
	var noSignatures bool
	var retainFor time.Duration
	var maxArchives int
	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Verify, compress, manifest and prune an audit log file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runArchive(cmd.OutOrStdout(), archiveCLIOpts{
				file:         file,
				outDir:       outDir,
				pubkey:       pubkey,
				pubkeyDir:    pubkeyDir,
				noSignatures: noSignatures,
				retainFor:    retainFor,
				maxArchives:  maxArchives,
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "audit.jsonl", "audit JSONL file")
	cmd.Flags().StringVarP(&outDir, "out-dir", "o", "audit-archives", "archive output directory")
	cmd.Flags().StringVar(&pubkey, "pubkey", "", "checkpoint public key (Ed25519 or ECDSA P-256 PEM)")
	cmd.Flags().StringVar(&pubkeyDir, "pubkey-dir", "", "directory of trusted checkpoint public keys (.pub/.pem)")
	cmd.Flags().BoolVar(&noSignatures, "no-signatures", false, "verify only the hash chain before archiving")
	cmd.Flags().DurationVar(&retainFor, "retain-for", 0, "prune archives older than this duration (0 keeps all)")
	cmd.Flags().IntVar(&maxArchives, "max-archives", 0, "maximum number of archives to retain (0 keeps all)")
	return cmd
}

type archiveCLIOpts struct {
	file         string
	outDir       string
	pubkey       string
	pubkeyDir    string
	noSignatures bool
	retainFor    time.Duration
	maxArchives  int
}

func loadCLIKeySet(pubkey, pubkeyDir string) (*audit.KeySet, error) {
	var ks *audit.KeySet
	if pubkeyDir != "" {
		loaded, err := audit.LoadKeySetDir(pubkeyDir)
		if err != nil {
			return nil, err
		}
		ks = loaded
	}
	if pubkey != "" {
		k, err := audit.LoadAnyPublicKey(pubkey)
		if err != nil {
			return nil, err
		}
		if ks == nil {
			return audit.NewKeySet(k)
		}
		if err := ks.Add(k); err != nil {
			return nil, err
		}
	}
	if ks == nil {
		return nil, ErrVerify
	}
	return ks, nil
}

func runArchive(out io.Writer, o archiveCLIOpts) error {
	if o.pubkey == "" && o.pubkeyDir == "" && !o.noSignatures {
		return fmt.Errorf("%w: pass --pubkey or --pubkey-dir, or --no-signatures", ErrVerify)
	}
	var vo audit.VerifyOptions
	if !o.noSignatures {
		ks, err := loadCLIKeySet(o.pubkey, o.pubkeyDir)
		if err != nil {
			return err
		}
		vo.Keys = ks
	}
	res, err := audit.Archive(audit.ArchiveOptions{
		SourcePath:    o.file,
		DestDir:       o.outDir,
		VerifyOptions: vo,
		MaxAge:        o.retainFor,
		MaxArchives:   o.maxArchives,
	})
	if err != nil {
		return err
	}
	m := res.Manifest
	return printf(
		out,
		"ARCHIVED chain=%s records=%d last_seq=%d file=%s sha256=%s pruned=%d\n",
		m.ChainID,
		m.Records,
		m.LastSeq,
		m.ArchiveFile,
		m.ArchiveSHA256,
		res.Pruned,
	)
}

func watchCmd() *cobra.Command {
	var file, pubkey, pubkeyDir, chainID string
	var noSignatures, once bool
	var interval time.Duration
	var maxUnsigned uint64
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously verify an audit log chain and report tampering or truncation",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWatch(cmd.Context(), cmd.OutOrStdout(), watchCLIOpts{
				file:         file,
				pubkey:       pubkey,
				pubkeyDir:    pubkeyDir,
				chainID:      chainID,
				noSignatures: noSignatures,
				once:         once,
				interval:     interval,
				maxUnsigned:  maxUnsigned,
			})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "audit.jsonl", "audit JSONL file")
	cmd.Flags().StringVar(&pubkey, "pubkey", "", "checkpoint public key (Ed25519 or ECDSA P-256 PEM)")
	cmd.Flags().StringVar(&pubkeyDir, "pubkey-dir", "", "directory of trusted checkpoint public keys (.pub/.pem)")
	cmd.Flags().StringVar(&chainID, "chain-id", "", "expected chain id")
	cmd.Flags().BoolVar(&noSignatures, "no-signatures", false, "verify only the hash chain")
	cmd.Flags().DurationVar(&interval, "interval", 30*time.Second, "verification interval")
	cmd.Flags().Uint64Var(&maxUnsigned, "max-unsigned", 1000, "maximum unsigned tail records allowed (0 disables)")
	cmd.Flags().BoolVar(&once, "once", false, "run one verification pass and exit")
	return cmd
}

type watchCLIOpts struct {
	file         string
	pubkey       string
	pubkeyDir    string
	chainID      string
	noSignatures bool
	once         bool
	interval     time.Duration
	maxUnsigned  uint64
}

func runWatch(ctx context.Context, out io.Writer, o watchCLIOpts) error {
	if o.pubkey == "" && o.pubkeyDir == "" && !o.noSignatures {
		return fmt.Errorf("%w: pass --pubkey or --pubkey-dir, or --no-signatures", ErrVerify)
	}
	var vo audit.VerifyOptions
	if !o.noSignatures {
		ks, err := loadCLIKeySet(o.pubkey, o.pubkeyDir)
		if err != nil {
			return err
		}
		vo.Keys = ks
	}
	w := audit.NewWatchdog(audit.WatchdogOptions{
		Path:          o.file,
		ChainID:       o.chainID,
		VerifyOptions: vo,
		Interval:      o.interval,
		MaxUnsigned:   o.maxUnsigned,
		OnResult: func(st audit.WatchStatus) {
			if st.Healthy {
				if err := printf(
					out,
					"OK chain=%s records=%d last_seq=%d unsigned_tail=%d\n",
					st.ChainID,
					st.Records,
					st.LastSeq,
					st.UnsignedTail,
				); err != nil {
					return
				}
				return
			}
			if err := printf(
				out,
				"FAIL chain=%s last_seq=%d error=%s\n",
				st.ChainID,
				st.LastSeq,
				st.Error,
			); err != nil {
				return
			}
		},
	})
	if o.once {
		st := w.Check(ctx)
		if !st.Healthy {
			return fmt.Errorf("%w: %s", ErrVerify, st.Error)
		}
		return nil
	}
	w.Run(ctx)
	return nil
}
