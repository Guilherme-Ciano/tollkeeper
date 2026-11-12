package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	ErrMalformed    = errors.New("malformed audit data")
	ErrKeyType      = errors.New("key is not ed25519")
	ErrBackpressure = errors.New("audit buffer full")
	ErrClosed       = errors.New("audit log closed")
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

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
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
