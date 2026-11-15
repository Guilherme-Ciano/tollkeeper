package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

var (
	ErrUntrustedTimestamp = errors.New("timestamp not signed by a trusted timestamp authority")
	ErrNoProvenTime       = errors.New("anchor has no witnessed or timestamped time")
)

const maxTimestampBytes = 64 << 10

type TimestampAuthority struct {
	URI           string
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate
	ValidFrom     time.Time
	ValidUntil    time.Time
}

func (a TimestampAuthority) validAt(t time.Time) bool {
	if !a.ValidFrom.IsZero() && t.Before(a.ValidFrom) {
		return false
	}
	return a.ValidUntil.IsZero() || !t.After(a.ValidUntil)
}

func newAuthority(uri string, chain []*x509.Certificate, from, until time.Time) (TimestampAuthority, error) {
	if len(chain) == 0 {
		return TimestampAuthority{}, fmt.Errorf("%w: empty timestamp authority chain", ErrBadTrust)
	}
	root := chain[len(chain)-1]
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return TimestampAuthority{}, fmt.Errorf("%w: timestamp authority chain must end in a self-signed CA",
			ErrBadTrust)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return TimestampAuthority{
		URI: uri, Roots: roots, Intermediates: chain[:len(chain)-1], ValidFrom: from, ValidUntil: until,
	}, nil
}

func parseCertChain(data []byte) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: unexpected PEM block %q in a certificate chain", ErrBadTrust, block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate: %w", ErrBadTrust, err)
		}
		chain = append(chain, c)
	}
	return chain, nil
}

func (t *Trust) HasTimestampAuthority() bool {
	return len(t.tsas) > 0
}

func (t *Trust) WithTimestampAuthorities(from *Trust) *Trust {
	out := *t
	out.tsas = from.tsas
	return &out
}

func (t *Trust) RequireTime() *Trust {
	out := *t
	out.requireTime = true
	return &out
}

type TimestampClient struct {
	url  string
	http *http.Client
}

func NewTimestampClient(rawURL string, rt http.RoundTripper) (*TimestampClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil || !SafeURL(u) {
		return nil, fmt.Errorf("%w: timestamp authority url must be https (http only for loopback) with no "+
			"credentials, query or fragment", ErrBadTrust)
	}
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &TimestampClient{url: u.String(), http: &http.Client{
		Transport:     rt,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *TimestampClient) Timestamp(ctx context.Context, statement []byte) ([]byte, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, fmt.Errorf("timestamp nonce: %w", err)
	}
	query, err := timestamp.CreateRequest(bytes.NewReader(statement),
		&timestamp.RequestOptions{Hash: crypto.SHA512, Certificates: true, Nonce: nonce})
	if err != nil {
		return nil, fmt.Errorf("timestamp request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("timestamp request: %w", err)
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("User-Agent", "tollkeeper")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: timestamp authority: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTimestampBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read timestamp: %w", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp, nil)
	}
	if len(data) > maxTimestampBytes {
		return nil, fmt.Errorf("%w: timestamp response too large", ErrInvalidReceipt)
	}
	ts, err := timestamp.ParseResponse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: timestamp response: %w", ErrInvalidReceipt, err)
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return nil, fmt.Errorf("%w: timestamp nonce does not match the request", ErrInvalidReceipt)
	}
	return ts.RawToken, nil
}

func (v *ReceiptVerifier) verifyTimestamp(token, digest []byte) (time.Time, error) {
	if len(v.trust.tsas) == 0 {
		return time.Time{}, fmt.Errorf("%w: no timestamp authority in the trust material", ErrUntrustedTimestamp)
	}
	ts, err := timestamp.Parse(token)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrInvalidReceipt, err)
	}
	if ts.HashAlgorithm != crypto.SHA512 || !bytes.Equal(ts.HashedMessage, digest) {
		return time.Time{}, fmt.Errorf("%w: timestamp covers another message", ErrDigestMismatch)
	}
	var errs []error
	for i := range v.trust.tsas {
		if err := verifyToken(token, ts.Time, &v.trust.tsas[i]); err != nil {
			errs = append(errs, err)
			continue
		}
		return ts.Time.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%w: %w", ErrUntrustedTimestamp, errors.Join(errs...))
}

func verifyToken(token []byte, at time.Time, a *TimestampAuthority) error {
	if !a.validAt(at) {
		return fmt.Errorf("authority %s not valid at %s", a.URI, at.UTC().Format(time.RFC3339))
	}
	p7, err := pkcs7.Parse(token)
	if err != nil {
		return fmt.Errorf("parse token: %w", err)
	}
	if len(p7.Certificates) == 0 {
		p7.Certificates = append(p7.Certificates, a.Intermediates...)
	}
	intermediates := x509.NewCertPool()
	for _, c := range a.Intermediates {
		intermediates.AddCert(c)
	}
	if err := p7.VerifyWithOpts(x509.VerifyOptions{
		Roots: a.Roots, Intermediates: intermediates, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	signer := p7.GetOnlySigner()
	if signer == nil || !hasTimestampingEKU(signer) {
		return errors.New("signer certificate lacks the timeStamping extended key usage")
	}
	return nil
}

func hasTimestampingEKU(c *x509.Certificate) bool {
	return slices.Contains(c.ExtKeyUsage, x509.ExtKeyUsageTimeStamping)
}

func VerifyTimestampToken(t *Trust, token []byte, ref audit.CheckpointRef) (time.Time, error) {
	digest, err := audit.AnchorDigest(ref.ChainID, ref.Seq, ref.Hash)
	if err != nil {
		return time.Time{}, err
	}
	return NewReceiptVerifier(t).verifyTimestamp(token, digest[:])
}
