package audit

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	ErrMalformed      = errors.New("malformed audit data")
	ErrKeyType        = errors.New("key is not ed25519")
	ErrUnsupportedKey = errors.New("unsupported audit key type (expected ed25519 or ecdsa p-256)")
	ErrNoSigner       = errors.New("audit checkpoint signer is not configured")
	ErrSameKey        = errors.New("next signing key matches the active key")
	ErrBackpressure   = errors.New("audit buffer full")
	ErrClosed         = errors.New("audit log closed")
	ErrSinkFailed     = errors.New("audit sink failing")
	ErrCorrupt        = errors.New("audit log tail may be inconsistent; writes stopped")
	ErrKeyExposed     = errors.New("signing key is readable by group or others")
	ErrAnchorQueue    = errors.New("audit anchor queue full")
	ErrAnchorStale    = errors.New("anchor covers a checkpoint too far behind the head")
	ErrAnchorForeign  = errors.New("anchor covers a checkpoint of another chain")
)

func GenerateKeyPair() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return privPEM, pubPEM, nil
}

func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key: %w", ErrMalformed)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrKeyType
	}
	return priv, nil
}

func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("public key: %w", ErrMalformed)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, ErrKeyType
	}
	return pub, nil
}

func checkKeyMode(mode fs.FileMode, goos string) error {
	if goos == "windows" || mode.Perm()&0o077 == 0 {
		return nil
	}
	return fmt.Errorf("%w: mode %#o, want 0600 or stricter", ErrKeyExposed, mode.Perm())
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat signing key: %w", err)
	}
	if err := checkKeyMode(info.Mode(), runtime.GOOS); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	return ParsePrivateKey(data)
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return ParsePublicKey(data)
}

func LoadAnyPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	return ParseAnyPublicKey(data)
}

func LoadKeySetDir(dir string) (*KeySet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read key directory: %w", err)
	}
	ks, err := NewKeySet()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".pub" && ext != ".pem" {
			continue
		}
		pub, err := LoadAnyPublicKey(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		if err := ks.Add(pub); err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
	}
	if ks.Len() == 0 {
		return nil, fmt.Errorf("no .pub or .pem public keys found in %s: %w", dir, ErrMalformed)
	}
	return ks, nil
}
