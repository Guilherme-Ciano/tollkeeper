package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Guilherme-Ciano/tollkeeper/internal/approval"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

const (
	cmdKeygen = "keygen"
	cmdVerify = "verify"
)

func approvalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval",
		Short: "Generate keys, sign, and verify stateless human approval tokens (tk-approval+jwt)",
	}
	cmd.AddCommand(approvalKeygenCmd(), approvalSignCmd(), approvalVerifyCmd())
	return cmd
}

func writeNamedKeyPair(dir, stem string, ifMissing bool, out io.Writer) error {
	priv, pub, err := audit.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	privPath := filepath.Join(dir, stem+".pem")
	pubPath := filepath.Join(dir, stem+".pub")
	if _, err := os.Stat(privPath); err == nil && ifMissing {
		return printf(out, "%s exists, keeping it\n", privPath)
	}
	if err := writeNew(privPath, priv, 0o600); err != nil {
		return err
	}
	if err := writeNew(pubPath, pub, 0o644); err != nil {
		return err
	}
	return printf(out, "wrote %s and %s\n", privPath, pubPath)
}

func mustMarkRequired(cmd *cobra.Command, names ...string) {
	for _, n := range names {
		if err := cmd.MarkFlagRequired(n); err != nil {
			panic(err)
		}
	}
}

func approvalKeygenCmd() *cobra.Command {
	var dir string
	var ifMissing bool
	cmd := &cobra.Command{
		Use:   cmdKeygen,
		Short: "Generate an Ed25519 key pair for signing human approval tokens",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeNamedKeyPair(dir, "approval-ed25519", ifMissing, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&dir, "out-dir", "o", ".", "output directory")
	cmd.Flags().BoolVar(&ifMissing, "if-missing", false, "do nothing when the key already exists")
	return cmd
}

func approvalSignCmd() *cobra.Command {
	var keyPath, approver, aud, iss, sub, tenant, tool, argsRaw, reason, jti string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a stateless argument-bound approval token for a specific tool call",
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := audit.LoadPrivateKey(keyPath)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			if ttl <= 0 {
				ttl = 5 * time.Minute
			}
			argsHash := approval.CanonicalArgsHash(json.RawMessage(argsRaw))
			tok, err := approval.Sign(priv, approval.Claims{
				JTI:       jti,
				Issuer:    iss,
				Audience:  aud,
				Subject:   sub,
				Tenant:    tenant,
				Approver:  approver,
				Tool:      tool,
				ArgsHash:  argsHash,
				Reason:    reason,
				IssuedAt:  now.Unix(),
				ExpiresAt: now.Add(ttl).Unix(),
			})
			if err != nil {
				return err
			}
			return printf(cmd.OutOrStdout(), "%s\n", tok)
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "Ed25519 private key PEM file (required)")
	cmd.Flags().StringVar(&approver, "approver", "", "human approver identity (required)")
	cmd.Flags().StringVar(&aud, "aud", "", "gateway public URL or auth.resource audience (required)")
	cmd.Flags().StringVar(&iss, "iss", "", "optional approval issuer identifier")
	cmd.Flags().StringVar(&sub, "sub", "", "caller subject (principal.sub)")
	cmd.Flags().StringVar(&tenant, "tenant", "", "optional caller tenant")
	cmd.Flags().StringVar(&tool, "tool", "", "qualified tool name (required)")
	cmd.Flags().StringVar(&argsRaw, "args", "{}", "JSON tool arguments to bind")
	cmd.Flags().StringVar(&reason, "reason", "", "optional approval reason or ticket ID")
	cmd.Flags().StringVar(&jti, "id", "", "optional explicit approval ID (defaults to random)")
	cmd.Flags().DurationVar(&ttl, "ttl", 5*time.Minute, "approval token lifetime")
	mustMarkRequired(cmd, "key", "approver", "aud", "tool")
	return cmd
}

func approvalVerifyCmd() *cobra.Command {
	var token, pubPath, aud, iss, sub, tenant, tool, argsRaw string
	var maxTTL time.Duration
	cmd := &cobra.Command{
		Use:   cmdVerify,
		Short: "Verify a stateless approval token against an operation and public key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ks, err := approval.LoadKeySet([]string{pubPath}, "")
			if err != nil {
				return err
			}
			v := approval.NewVerifier(approval.VerifierOptions{
				Keys:     ks,
				Issuer:   iss,
				Audience: aud,
				MaxTTL:   maxTTL,
			})
			res, err := v.Verify(approval.VerifyRequest{
				Token:   token,
				Subject: sub,
				Tenant:  tenant,
				Tool:    tool,
				Args:    json.RawMessage(argsRaw),
			})
			if err != nil {
				return err
			}
			return printf(
				cmd.OutOrStdout(),
				"OK id=%s approver=%s args_hash=%s expires=%s\n",
				res.ID,
				res.Approver,
				res.ArgsHash,
				res.ExpiresAt.UTC().Format(time.RFC3339),
			)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "approval JWT token (required)")
	cmd.Flags().StringVar(&pubPath, "pubkey", "", "Ed25519 public key PEM file (required)")
	cmd.Flags().StringVar(&aud, "aud", "", "expected gateway audience")
	cmd.Flags().StringVar(&iss, "iss", "", "optional expected issuer")
	cmd.Flags().StringVar(&sub, "sub", "", "expected caller subject")
	cmd.Flags().StringVar(&tenant, "tenant", "", "optional expected tenant")
	cmd.Flags().StringVar(&tool, "tool", "", "expected qualified tool name (required)")
	cmd.Flags().StringVar(&argsRaw, "args", "{}", "JSON tool arguments to verify")
	cmd.Flags().DurationVar(&maxTTL, "max-ttl", approval.DefaultMaxTTL, "maximum accepted approval lifetime")
	mustMarkRequired(cmd, "token", "pubkey", "tool")
	return cmd
}
