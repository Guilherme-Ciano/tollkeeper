package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

const (
	defaultVaultMount = "transit"
	vaultTypeEd25519  = "ed25519"
	vaultTypeP256     = "ecdsa-p256"
)

type VaultOptions struct {
	Address         string
	Mount           string
	KeyID           string
	Token           string
	Namespace       string
	Timeout         time.Duration
	BlockPrivateIPs bool
	Client          *http.Client
}

type VaultSigner struct {
	client    *http.Client
	address   string
	mount     string
	vaultKey  string
	token     string
	namespace string
	version   int
	keyID     string
	pub       crypto.PublicKey
	alg       string
}

type vaultKeyResp struct {
	Data struct {
		Type          string `json:"type"`
		LatestVersion int    `json:"latest_version"`
		Keys          map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	} `json:"data"`
}

type vaultSignReq struct {
	Input               string `json:"input"`
	KeyVersion          int    `json:"key_version"`
	HashAlgorithm       string `json:"hash_algorithm,omitempty"`
	MarshalingAlgorithm string `json:"marshaling_algorithm,omitempty"`
}

type vaultSignResp struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}

func NewVaultSigner(ctx context.Context, opts VaultOptions) (*VaultSigner, error) {
	if strings.TrimSpace(opts.Address) == "" || strings.TrimSpace(opts.KeyID) == "" ||
		strings.TrimSpace(opts.Token) == "" {
		return nil, fmt.Errorf("vault address, key_id and token are required: %w", ErrConfig)
	}
	mount := strings.Trim(opts.Mount, "/")
	if mount == "" {
		mount = defaultVaultMount
	}
	s := &VaultSigner{
		client:    newHTTPClient(opts.Timeout, opts.BlockPrivateIPs, opts.Client),
		address:   strings.TrimRight(opts.Address, "/"),
		mount:     mount,
		vaultKey:  opts.KeyID,
		token:     opts.Token,
		namespace: opts.Namespace,
	}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *VaultSigner) KeyID() string               { return s.keyID }
func (s *VaultSigner) PublicKey() crypto.PublicKey { return s.pub }
func (s *VaultSigner) Algorithm() string           { return s.alg }

func (s *VaultSigner) keyURL(op string) string {
	return s.address + "/v1/" + s.mount + "/" + op + "/" + url.PathEscape(s.vaultKey)
}

func (s *VaultSigner) doRequest(ctx context.Context, method, endpoint string, body []byte) ([]byte, error) {
	var r bytes.Reader
	var req *http.Request
	var err error
	if body != nil {
		r.Reset(body)
		req, err = http.NewRequestWithContext(ctx, method, endpoint, &r)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, http.NoBody)
	}
	if err != nil {
		return nil, fmt.Errorf("build vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)
	if s.namespace != "" {
		req.Header.Set("X-Vault-Namespace", s.namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault status %d: %w", resp.StatusCode, ErrBadResponse)
	}
	return raw, nil
}

func (s *VaultSigner) loadPublicKey(ctx context.Context) error {
	raw, err := s.doRequest(ctx, http.MethodGet, s.keyURL("keys"), nil)
	if err != nil {
		return fmt.Errorf("fetch vault transit key: %w", err)
	}
	var parsed vaultKeyResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("decode vault transit key: %w", err)
	}
	ver := parsed.Data.LatestVersion
	if ver < 1 {
		return fmt.Errorf("vault key has invalid latest_version %d: %w", ver, ErrBadResponse)
	}
	entry, ok := parsed.Data.Keys[strconv.Itoa(ver)]
	if !ok || strings.TrimSpace(entry.PublicKey) == "" {
		return fmt.Errorf("vault key version %d missing public_key: %w", ver, ErrBadResponse)
	}
	pub, err := parseVaultPublicKey(parsed.Data.Type, entry.PublicKey)
	if err != nil {
		return err
	}
	keyID, err := audit.KeyIDFor(pub)
	if err != nil {
		return err
	}
	alg, err := audit.AlgorithmFor(pub)
	if err != nil {
		return err
	}
	s.version = ver
	s.pub = pub
	s.keyID = keyID
	s.alg = alg
	return nil
}

func parseVaultPublicKey(keyType, raw string) (crypto.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	switch keyType {
	case vaultTypeEd25519:
		if strings.HasPrefix(trimmed, "-----BEGIN") {
			return audit.ParseAnyPublicKey([]byte(trimmed))
		}
		b, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid vault ed25519 public key: %w", ErrBadResponse)
		}
		return ed25519.PublicKey(b), nil
	case vaultTypeP256:
		if strings.HasPrefix(trimmed, "-----BEGIN") {
			return audit.ParseAnyPublicKey([]byte(trimmed))
		}
		b, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("decode vault p256 public key: %w", err)
		}
		return audit.ParsePublicKeyDER(b)
	default:
		return nil, fmt.Errorf("unsupported vault key type %q: %w", keyType, audit.ErrUnsupportedKey)
	}
}

func (s *VaultSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	payload := vaultSignReq{
		Input:      base64.StdEncoding.EncodeToString(msg),
		KeyVersion: s.version,
	}
	if s.alg == audit.AlgECDSAP256 {
		payload.HashAlgorithm = "sha2-256"
		payload.MarshalingAlgorithm = "asn1"
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode vault sign request: %w", err)
	}
	raw, err := s.doRequest(ctx, http.MethodPost, s.keyURL("sign"), body)
	if err != nil {
		return nil, fmt.Errorf("vault transit sign: %w", err)
	}
	var parsed vaultSignResp
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode vault sign response: %w", err)
	}
	sig := parsed.Data.Signature
	idx := strings.LastIndexByte(sig, ':')
	if idx < 0 || idx+1 >= len(sig) {
		return nil, fmt.Errorf("malformed vault signature prefix: %w", ErrBadResponse)
	}
	decoded, err := base64.StdEncoding.DecodeString(sig[idx+1:])
	if err != nil {
		return nil, fmt.Errorf("decode vault signature: %w", err)
	}
	return decoded, nil
}
