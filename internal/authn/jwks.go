package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const (
	useSig       = "sig"
	maxJWKSBytes = 256 << 10
	maxKeys      = 64
)

var (
	ErrKeysUnavailable = errors.New("signing keys unavailable")
	ErrUnknownKey      = errors.New("unknown signing key")
	ErrUnsupportedKey  = errors.New("unsupported jwk")
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type KeySet struct {
	OnError  func(error)
	url      string
	client   *http.Client
	minRetry time.Duration
	now      func() time.Time
	group    singleflight.Group

	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
}

func NewKeySet(url string, client *http.Client, minRetry time.Duration) *KeySet {
	return &KeySet{
		url:      url,
		client:   client,
		minRetry: minRetry,
		now:      time.Now,
		keys:     map[string]crypto.PublicKey{},
	}
}

func (k *KeySet) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	k.mu.RLock()
	key, ok := k.keys[kid]
	k.mu.RUnlock()
	if ok {
		return key, nil
	}
	if err := k.refresh(ctx, false); err != nil {
		return nil, err
	}
	k.mu.RLock()
	key, ok = k.keys[kid]
	k.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("kid %q: %w", kid, ErrUnknownKey)
	}
	return key, nil
}

func (k *KeySet) Refresh(ctx context.Context) error {
	return k.refresh(ctx, true)
}

func (k *KeySet) refresh(ctx context.Context, force bool) error {
	k.mu.RLock()
	recent := k.now().Sub(k.lastTry) < k.minRetry
	empty := len(k.keys) == 0
	k.mu.RUnlock()
	if recent && !force {
		if empty {
			return ErrKeysUnavailable
		}
		return nil
	}
	_, err, _ := k.group.Do("refresh", func() (any, error) {
		return nil, k.fetch(context.WithoutCancel(ctx))
	})
	if err != nil {
		return fmt.Errorf("refresh jwks: %w", err)
	}
	return nil
}

func (k *KeySet) fetch(ctx context.Context) error {
	k.mu.Lock()
	k.lastTry = k.now()
	k.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, http.NoBody)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeysUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrKeysUnavailable, resp.StatusCode)
	}
	var set JWKSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return fmt.Errorf("%w: decode: %w", ErrKeysUnavailable, err)
	}
	keys := make(map[string]crypto.PublicKey, len(set.Keys))
	for idx := range set.Keys {
		j := set.Keys[idx]
		if len(keys) >= maxKeys {
			break
		}
		if j.Use != "" && j.Use != useSig {
			continue
		}
		pub, err := ParseJWK(j)
		if err != nil {
			continue
		}
		keys[j.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("%w: no usable keys", ErrKeysUnavailable)
	}
	k.mu.Lock()
	k.keys = keys
	k.fetchedAt = k.now()
	k.mu.Unlock()
	return nil
}

func (k *KeySet) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := k.Refresh(ctx); err != nil && k.OnError != nil {
				k.OnError(err)
			}
		}
	}
}

func b64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
	}
	return b, nil
}

func ParseJWK(j JWK) (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := b64(j.N)
		if err != nil {
			return nil, err
		}
		e, err := b64(j.E)
		if err != nil {
			return nil, err
		}
		if len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, fmt.Errorf("%w: rsa key too small or bad exponent", ErrUnsupportedKey)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		return parseEC(j)
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("%w: okp curve %q", ErrUnsupportedKey, j.Crv)
		}
		x, err := b64(j.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: ed25519 size", ErrUnsupportedKey)
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("%w: kty %q", ErrUnsupportedKey, j.Kty)
	}
}

func parseEC(j JWK) (crypto.PublicKey, error) {
	var curve elliptic.Curve
	switch j.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("%w: ec curve %q", ErrUnsupportedKey, j.Crv)
	}
	x, err := b64(j.X)
	if err != nil {
		return nil, err
	}
	y, err := b64(j.Y)
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) != size || len(y) != size {
		return nil, fmt.Errorf("%w: ec coordinate size", ErrUnsupportedKey)
	}
	uncompressed := append([]byte{4}, append(x, y...)...)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
	}
	return pub, nil
}

func EncodeJWK(kid string, pub crypto.PublicKey) (JWK, error) {
	enc := base64.RawURLEncoding.EncodeToString
	switch p := pub.(type) {
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", Kid: kid, Use: useSig, Alg: "EdDSA", X: enc(p)}, nil
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return JWK{}, fmt.Errorf("%w: only P-256 encoding supported", ErrUnsupportedKey)
		}
		raw, err := p.Bytes()
		if err != nil {
			return JWK{}, fmt.Errorf("%w: %w", ErrUnsupportedKey, err)
		}
		return JWK{
			Kty: "EC",
			Crv: "P-256",
			Kid: kid,
			Use: useSig,
			Alg: "ES256",
			X:   enc(raw[1:33]),
			Y:   enc(raw[33:]),
		}, nil
	default:
		return JWK{}, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}
