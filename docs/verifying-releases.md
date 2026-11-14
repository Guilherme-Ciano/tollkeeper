# Verifying a release

tollkeeper sells a verifiable audit trail, so its own delivery chain is verifiable too. Every release published by [`release.yml`](../.github/workflows/release.yml) carries:

| Artifact | What it proves | Produced by |
|---|---|---|
| `checksums.txt` | Integrity of every archive | GoReleaser |
| `checksums.txt.sigstore.json` | The checksum file was signed by this repository's release workflow, with no long-lived key | cosign keyless (Sigstore, GitHub OIDC) |
| `*.sbom.json` | Exact dependency set of each archive | Syft |
| SLSA build provenance attestation | Which commit, workflow and runner built each archive and the container image | `actions/attest-build-provenance` |
| Container image signature | The GHCR image digest was signed by the same workflow | cosign keyless |

Replace `v1.0.0` and the archive name with the release you downloaded.

## 1. Checksums and their signature

```bash
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Guilherme-Ciano/tollkeeper/.github/workflows/release.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

```bash
sha256sum --ignore-missing -c checksums.txt
```

## 2. SLSA build provenance

```bash
gh attestation verify tollkeeper_1.0.0_linux_amd64.tar.gz --repo Guilherme-Ciano/tollkeeper
```

```bash
gh attestation verify oci://ghcr.io/guilherme-ciano/tollkeeper:1.0.0 --repo Guilherme-Ciano/tollkeeper
```

## 3. Container image signature

```bash
cosign verify ghcr.io/guilherme-ciano/tollkeeper:1.0.0 \
  --certificate-identity-regexp '^https://github.com/Guilherme-Ciano/tollkeeper/.github/workflows/release.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A failure in any step means the artifact did not come from this repository's release workflow. Do not run it, and report it as described in [SECURITY.md](../SECURITY.md).
