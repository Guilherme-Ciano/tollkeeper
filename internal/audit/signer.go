package audit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"maps"
)

const (
	AlgEd25519   = "ed25519"
	AlgECDSAP256 = "ecdsa-p256-sha256"

	keyRotateDomain = "tollkeeper-keyrot-v1"
)

type CheckpointSigner interface {
	KeyID() string
	PublicKey() crypto.PublicKey
	Algorithm() string
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

type LocalSigner struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

func NewLocalSigner(key ed25519.PrivateKey) (*LocalSigner, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrKeyType
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrKeyType
	}
	return &LocalSigner{
		priv:  key,
		pub:   pub,
		keyID: KeyID(pub),
	}, nil
}

func (s *LocalSigner) KeyID() string {
	return s.keyID
}

func (s *LocalSigner) PublicKey() crypto.PublicKey {
	return s.pub
}

func (s *LocalSigner) Algorithm() string {
	return AlgEd25519
}

func (s *LocalSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}

func KeyIDFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", ErrUnsupportedKey
		}
		return KeyID(k), nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() {
			return "", ErrUnsupportedKey
		}
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return "", fmt.Errorf("marshal ecdsa public key: %w", err)
		}
		sum := sha256.Sum256(der)
		return hex.EncodeToString(sum[:8]), nil
	default:
		return "", ErrUnsupportedKey
	}
}

func AlgorithmFor(pub crypto.PublicKey) (string, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", ErrUnsupportedKey
		}
		return AlgEd25519, nil
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() {
			return "", ErrUnsupportedKey
		}
		return AlgECDSAP256, nil
	default:
		return "", ErrUnsupportedKey
	}
}

func MarshalPublicKeyDER(pub crypto.PublicKey) ([]byte, error) {
	if _, err := AlgorithmFor(pub); err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return der, nil
}

func ParsePublicKeyDER(der []byte) (crypto.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	if _, err := AlgorithmFor(k); err != nil {
		return nil, err
	}
	return k, nil
}

func ParseAnyPublicKey(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("public key: %w", ErrMalformed)
	}
	return ParsePublicKeyDER(block.Bytes)
}

type KeySet struct {
	keys map[string]crypto.PublicKey
}

func NewKeySet(pubs ...crypto.PublicKey) (*KeySet, error) {
	ks := &KeySet{keys: make(map[string]crypto.PublicKey, len(pubs))}
	for _, pub := range pubs {
		if pub == nil {
			continue
		}
		if err := ks.Add(pub); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

func (ks *KeySet) Add(pub crypto.PublicKey) error {
	id, err := KeyIDFor(pub)
	if err != nil {
		return err
	}
	if ks.keys == nil {
		ks.keys = make(map[string]crypto.PublicKey)
	}
	ks.keys[id] = pub
	return nil
}

func (ks *KeySet) Lookup(id string) (crypto.PublicKey, bool) {
	if ks == nil {
		return nil, false
	}
	pub, ok := ks.keys[id]
	return pub, ok
}

func (ks *KeySet) Len() int {
	if ks == nil {
		return 0
	}
	return len(ks.keys)
}

func (ks *KeySet) Clone() *KeySet {
	if ks == nil {
		return nil
	}
	return &KeySet{keys: maps.Clone(ks.keys)}
}

func SignCheckpointWith(
	ctx context.Context,
	s CheckpointSigner,
	chainID string,
	seq uint64,
	hashHex string,
) (*Checkpoint, error) {
	if s == nil {
		return nil, ErrNoSigner
	}
	msg, err := checkpointMessage(chainID, seq, hashHex)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("sign checkpoint: %w", err)
	}
	alg := s.Algorithm()
	if alg == AlgEd25519 {
		alg = ""
	}
	return &Checkpoint{
		CoversSeq:  seq,
		CoversHash: hashHex,
		KeyID:      s.KeyID(),
		Algorithm:  alg,
		Signature:  hex.EncodeToString(sig),
	}, nil
}

func verifySignature(pub crypto.PublicKey, alg string, msg, sig []byte) bool {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if alg != "" && alg != AlgEd25519 {
			return false
		}
		if len(k) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(k, msg, sig)
	case *ecdsa.PublicKey:
		if k == nil || k.Curve != elliptic.P256() || alg != AlgECDSAP256 {
			return false
		}
		digest := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(k, digest[:], sig)
	default:
		return false
	}
}

func VerifyCheckpointAny(pub crypto.PublicKey, chainID string, c *Checkpoint) bool {
	msg, err := checkpointMessage(chainID, c.CoversSeq, c.CoversHash)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil {
		return false
	}
	return verifySignature(pub, c.Algorithm, msg, sig)
}

func keyRotationMessage(chainID, prevKeyID, newKeyID, newAlg string, newPubDER []byte) []byte {
	n := len(keyRotateDomain) + 1 + len(chainID) + 1 + len(prevKeyID) + 1 +
		len(newKeyID) + 1 + len(newAlg) + 1 + len(newPubDER)
	msg := make([]byte, 0, n)
	msg = append(msg, keyRotateDomain...)
	msg = append(msg, 0)
	msg = append(msg, chainID...)
	msg = append(msg, 0)
	msg = append(msg, prevKeyID...)
	msg = append(msg, 0)
	msg = append(msg, newKeyID...)
	msg = append(msg, 0)
	msg = append(msg, newAlg...)
	msg = append(msg, 0)
	msg = append(msg, newPubDER...)
	return msg
}

func SignKeyRotation(ctx context.Context, prev, next CheckpointSigner, chainID string) (*KeyRotation, error) {
	if prev == nil || next == nil {
		return nil, ErrNoSigner
	}
	newPubDER, err := MarshalPublicKeyDER(next.PublicKey())
	if err != nil {
		return nil, err
	}
	newID, err := KeyIDFor(next.PublicKey())
	if err != nil {
		return nil, err
	}
	if newID != next.KeyID() {
		return nil, fmt.Errorf("signer key id %q disagrees with public key %q: %w", next.KeyID(), newID, ErrMalformed)
	}
	newAlg, err := AlgorithmFor(next.PublicKey())
	if err != nil {
		return nil, err
	}
	msg := keyRotationMessage(chainID, prev.KeyID(), newID, newAlg, newPubDER)
	sig, err := prev.Sign(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("sign key rotation: %w", err)
	}
	prevAlg := prev.Algorithm()
	if prevAlg == AlgEd25519 {
		prevAlg = ""
	}
	return &KeyRotation{
		PrevKeyID:       prev.KeyID(),
		PrevAlgorithm:   prevAlg,
		NewKeyID:        newID,
		NewAlgorithm:    newAlg,
		NewPublicKeyDER: newPubDER,
		Signature:       hex.EncodeToString(sig),
	}, nil
}

func VerifyKeyRotation(prevPub crypto.PublicKey, chainID string, kr *KeyRotation) (crypto.PublicKey, error) {
	if kr == nil || len(kr.NewPublicKeyDER) == 0 {
		return nil, ErrMalformed
	}
	prevID, err := KeyIDFor(prevPub)
	if err != nil {
		return nil, err
	}
	if prevID != kr.PrevKeyID {
		return nil, fmt.Errorf("prev key id %q does not match %q: %w", kr.PrevKeyID, prevID, ErrMalformed)
	}
	newPub, err := ParsePublicKeyDER(kr.NewPublicKeyDER)
	if err != nil {
		return nil, err
	}
	newID, err := KeyIDFor(newPub)
	if err != nil {
		return nil, err
	}
	if newID != kr.NewKeyID {
		return nil, fmt.Errorf("new key id %q does not match public key %q: %w", kr.NewKeyID, newID, ErrMalformed)
	}
	newAlg, err := AlgorithmFor(newPub)
	if err != nil {
		return nil, err
	}
	if newAlg != kr.NewAlgorithm {
		return nil, fmt.Errorf("new algorithm %q does not match key %q: %w", kr.NewAlgorithm, newAlg, ErrMalformed)
	}
	sig, err := hex.DecodeString(kr.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode rotation signature: %w", ErrMalformed)
	}
	msg := keyRotationMessage(chainID, kr.PrevKeyID, kr.NewKeyID, kr.NewAlgorithm, kr.NewPublicKeyDER)
	if !verifySignature(prevPub, kr.PrevAlgorithm, msg, sig) {
		return nil, ErrTampered
	}
	return newPub, nil
}
