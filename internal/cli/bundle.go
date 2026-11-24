package cli

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/bundle"
)

func bundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Sign and verify Ed25519-authenticated configuration and tool-pin bundles",
	}
	cmd.AddCommand(bundleKeygenCmd(), bundleSignCmd(), bundleVerifyCmd())
	return cmd
}

func bundleKeygenCmd() *cobra.Command {
	var dir string
	var ifMissing bool
	cmd := &cobra.Command{
		Use:   cmdKeygen,
		Short: "Generate an Ed25519 key pair for signing configuration bundles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeNamedKeyPair(dir, "bundle-ed25519", ifMissing, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&dir, "out-dir", "o", ".", "output directory")
	cmd.Flags().BoolVar(&ifMissing, "if-missing", false, "do nothing when the key already exists")
	return cmd
}

func bundleSignCmd() *cobra.Command {
	var keyPath, cfgPath, pinsPath, outPath, bundleID string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a config file (and optional pins lockfile) into an Ed25519 bundle manifest",
		RunE: func(cmd *cobra.Command, _ []string) error {
			priv, err := audit.LoadPrivateKey(keyPath)
			if err != nil {
				return err
			}
			m, err := bundle.Sign(priv, bundle.SignOptions{
				BundleID:   bundleID,
				ConfigPath: cfgPath,
				PinsPath:   pinsPath,
				TTL:        ttl,
			})
			if err != nil {
				return err
			}
			if err := bundle.WriteManifest(outPath, m); err != nil {
				return err
			}
			return printf(
				cmd.OutOrStdout(),
				"signed bundle %s (key_id=%s) -> %s\n",
				m.BundleID,
				m.KeyID,
				outPath,
			)
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "Ed25519 private key PEM file (required)")
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "tollkeeper.yaml", "config file to sign")
	cmd.Flags().StringVar(&pinsPath, "pins", "", "optional tool pin lockfile to include")
	cmd.Flags().StringVar(&bundleID, "id", "", "bundle identifier (defaults to timestamp)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "optional bundle expiration duration")
	cmd.Flags().StringVarP(&outPath, "out", "o", "bundle.sig.json", "output manifest file")
	mustMarkRequired(cmd, "key")
	return cmd
}

func bundleVerifyCmd() *cobra.Command {
	var manifestPath, pubPath, pubDir, cfgPath, pinsPath string
	var requirePins bool
	cmd := &cobra.Command{
		Use:   cmdVerify,
		Short: "Verify a signed bundle manifest against config and pins files",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var files []string
			if pubPath != "" {
				files = []string{pubPath}
			}
			keys, err := bundle.LoadPublicKeys(files, pubDir)
			if err != nil {
				return err
			}
			res, err := bundle.Verify(bundle.VerifyOptions{
				ManifestPath: manifestPath,
				ConfigPath:   cfgPath,
				PinsPath:     pinsPath,
				RequirePins:  requirePins,
				Keys:         keys,
			})
			if err != nil {
				return err
			}
			return printf(
				cmd.OutOrStdout(),
				"OK bundle=%s key_id=%s config=%s\n",
				res.BundleID,
				res.KeyID,
				res.ConfigDigest,
			)
		},
	}
	cmd.Flags().StringVar(&manifestPath, "manifest", "bundle.sig.json", "signed bundle manifest file")
	cmd.Flags().StringVar(&pubPath, "pubkey", "", "Ed25519 public key PEM file")
	cmd.Flags().StringVar(&pubDir, "pubkey-dir", "", "directory of trusted Ed25519 public keys")
	cmd.Flags().StringVarP(&cfgPath, "config", "c", "tollkeeper.yaml", "config file to verify")
	cmd.Flags().StringVar(&pinsPath, "pins", "", "optional pins lockfile to verify")
	cmd.Flags().BoolVar(&requirePins, "require-pins", false, "fail if manifest does not cover pins")
	return cmd
}
