package anchor

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxResponseBytes  = 1 << 20
	keyDetailsEd25519 = "PKIX_ED25519_PH"
	hashSHA512        = "SHA2_512"
	entryKind         = "hashedrekord"
	entryAPIVersion   = "0.0.2"
	entriesPath       = "/api/v2/log/entries"
	checkpointPath    = "/api/v2/checkpoint"
)

type CreateEntryRequest struct {
	HashedRekord HashedRekordRequest `json:"hashedRekordRequestV002"`
}

type HashedRekordRequest struct {
	Digest    []byte    `json:"digest"`
	Signature Signature `json:"signature"`
}

type Signature struct {
	Content  []byte   `json:"content"`
	Verifier Verifier `json:"verifier"`
}

type Verifier struct {
	PublicKey  *PublicKey `json:"publicKey,omitempty"`
	KeyDetails string     `json:"keyDetails"`
}

type PublicKey struct {
	RawBytes []byte `json:"rawBytes"`
}

type TransparencyLogEntry struct {
	LogIndex          int64          `json:"logIndex,string"`
	KindVersion       KindVersion    `json:"kindVersion"`
	InclusionProof    InclusionProof `json:"inclusionProof"`
	CanonicalizedBody []byte         `json:"canonicalizedBody"`
}

type KindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

type InclusionProof struct {
	LogIndex   int64           `json:"logIndex,string"`
	Hashes     [][]byte        `json:"hashes"`
	Checkpoint CheckpointField `json:"checkpoint"`
}

type CheckpointField struct {
	Envelope string `json:"envelope"`
}

type LoggedEntry struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Spec       LoggedSpec `json:"spec"`
}

type LoggedSpec struct {
	HashedRekord *LoggedHashedRekord `json:"hashedRekordV002"`
}

type LoggedHashedRekord struct {
	Data      LoggedData `json:"data"`
	Signature Signature  `json:"signature"`
}

type LoggedData struct {
	Algorithm string `json:"algorithm"`
	Digest    []byte `json:"digest"`
}

type Submission struct {
	Digest       [sha512.Size]byte
	Signature    []byte
	PublicKeyDER []byte
}

type Receipt struct {
	LogIndex   uint64
	Entry      []byte
	Proof      [][]byte
	Checkpoint string
}

type HTTPError struct {
	Status     int
	RetryAfter time.Duration
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("rekor status %d: %s", e.Status, e.Message)
}

func (e *HTTPError) Unwrap() error {
	switch {
	case e.Status == http.StatusRequestTimeout, e.Status == http.StatusTooManyRequests, e.Status >= 500:
		return ErrUnavailable
	default:
		return ErrRejected
	}
}

type Client struct {
	base      *url.URL
	http      *http.Client
	userAgent string
}

func NewClient(rawURL, userAgent string, rt http.RoundTripper) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(rawURL, "/"))
	if err != nil || !SafeURL(u) {
		return nil, fmt.Errorf("%w: rekor url must be https (http only for loopback) with no credentials, "+
			"query or fragment", ErrBadTrust)
	}
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Client{
		base:      u,
		userAgent: userAgent,
		http: &http.Client{
			Transport:     rt,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func SafeURL(u *url.URL) bool {
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		return host == "localhost" || (ip != nil && ip.IsLoopback())
	default:
		return false
	}
}

func (c *Client) Origin() string {
	return c.base.Host
}

func (c *Client) endpoint(path string) string {
	return c.base.String() + path
}

func (c *Client) Submit(ctx context.Context, s Submission) (Receipt, error) {
	body, err := json.Marshal(CreateEntryRequest{HashedRekord: HashedRekordRequest{
		Digest: s.Digest[:],
		Signature: Signature{
			Content:  s.Signature,
			Verifier: Verifier{PublicKey: &PublicKey{RawBytes: s.PublicKeyDER}, KeyDetails: keyDetailsEd25519},
		},
	}})
	if err != nil {
		return Receipt{}, fmt.Errorf("encode rekor request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(entriesPath), bytes.NewReader(body))
	if err != nil {
		return Receipt{}, fmt.Errorf("rekor request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: read response: %w", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return Receipt{}, statusError(resp, data)
	}
	if len(data) > maxResponseBytes {
		return Receipt{}, fmt.Errorf("%w: response larger than %d bytes", ErrInvalidReceipt, maxResponseBytes)
	}
	return decodeReceipt(data)
}

func decodeReceipt(data []byte) (Receipt, error) {
	var tle TransparencyLogEntry
	if err := json.Unmarshal(data, &tle); err != nil {
		return Receipt{}, fmt.Errorf("%w: %w", ErrInvalidReceipt, err)
	}
	if tle.LogIndex < 0 || len(tle.CanonicalizedBody) == 0 || tle.InclusionProof.Checkpoint.Envelope == "" {
		return Receipt{}, fmt.Errorf("%w: incomplete entry", ErrInvalidReceipt)
	}
	if tle.KindVersion.Kind != entryKind || tle.KindVersion.Version != entryAPIVersion {
		return Receipt{}, fmt.Errorf("%w: entry kind %s/%s", ErrInvalidReceipt, tle.KindVersion.Kind,
			tle.KindVersion.Version)
	}
	index := uint64(tle.LogIndex)
	return Receipt{
		LogIndex:   index,
		Entry:      tle.CanonicalizedBody,
		Proof:      tle.InclusionProof.Hashes,
		Checkpoint: tle.InclusionProof.Checkpoint.Envelope,
	}, nil
}

func statusError(resp *http.Response, data []byte) error {
	e := &HTTPError{Status: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &body) == nil && body.Message != "" {
		e.Message = truncate(body.Message, 256)
	}
	if s := resp.Header.Get("Retry-After"); s != "" {
		if secs, err := strconv.Atoi(s); err == nil && secs > 0 {
			e.RetryAfter = min(time.Duration(secs)*time.Second, time.Hour)
		}
	}
	return e
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (c *Client) Checkpoint(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(checkpointPath), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("rekor request: %w", err)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("%w: read checkpoint: %w", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", statusError(resp, data)
	}
	return string(data), nil
}

func IsRetryable(err error) bool {
	return errors.Is(err, ErrUnavailable) || errors.Is(err, context.DeadlineExceeded)
}
