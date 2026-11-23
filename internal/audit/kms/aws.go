package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
)

const (
	awsKMSService      = "kms"
	awsKMSContentType  = "application/x-amz-json-1.1"
	awsKMSSigningAlg   = "ECDSA_SHA_256"
	awsTargetGetPubKey = "TrentService.GetPublicKey"
	awsTargetSign      = "TrentService.Sign"
)

type AWSOptions struct {
	Region          string
	KeyID           string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Timeout         time.Duration
	BlockPrivateIPs bool
	Clock           func() time.Time
	Client          *http.Client
}

type AWSSigner struct {
	client          *http.Client
	endpoint        *url.URL
	region          string
	awsKeyID        string
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
	clock           func() time.Time
	keyID           string
	pub             crypto.PublicKey
	alg             string
}

type awsGetPublicKeyReq struct {
	KeyID string `json:"KeyId"`
}

type awsGetPublicKeyResp struct {
	PublicKey         string   `json:"PublicKey"`
	SigningAlgorithms []string `json:"SigningAlgorithms"`
}

type awsSignReq struct {
	KeyID            string `json:"KeyId"`
	Message          string `json:"Message"`
	MessageType      string `json:"MessageType"`
	SigningAlgorithm string `json:"SigningAlgorithm"`
}

type awsSignResp struct {
	Signature string `json:"Signature"`
}

func NewAWSSigner(ctx context.Context, opts AWSOptions) (*AWSSigner, error) {
	if strings.TrimSpace(opts.Region) == "" || strings.TrimSpace(opts.KeyID) == "" ||
		strings.TrimSpace(opts.AccessKeyID) == "" || strings.TrimSpace(opts.SecretAccessKey) == "" {
		return nil, fmt.Errorf("aws region, key_id, access_key_id and secret_access_key are required: %w", ErrConfig)
	}
	rawEndpoint := strings.TrimSpace(opts.Endpoint)
	if rawEndpoint == "" {
		rawEndpoint = "https://kms." + opts.Region + ".amazonaws.com"
	}
	parsedURL, err := url.Parse(rawEndpoint)
	if err != nil || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid aws kms endpoint %q: %w", rawEndpoint, ErrConfig)
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	s := &AWSSigner{
		client:          newHTTPClient(opts.Timeout, opts.BlockPrivateIPs, opts.Client),
		endpoint:        parsedURL,
		region:          opts.Region,
		awsKeyID:        opts.KeyID,
		accessKeyID:     opts.AccessKeyID,
		secretAccessKey: opts.SecretAccessKey,
		sessionToken:    opts.SessionToken,
		clock:           clock,
	}
	if err := s.loadPublicKey(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *AWSSigner) KeyID() string               { return s.keyID }
func (s *AWSSigner) PublicKey() crypto.PublicKey { return s.pub }
func (s *AWSSigner) Algorithm() string           { return s.alg }

func (s *AWSSigner) loadPublicKey(ctx context.Context) error {
	body, err := json.Marshal(awsGetPublicKeyReq{KeyID: s.awsKeyID})
	if err != nil {
		return fmt.Errorf("encode aws GetPublicKey: %w", err)
	}
	raw, err := s.doKMS(ctx, awsTargetGetPubKey, body)
	if err != nil {
		return fmt.Errorf("aws kms GetPublicKey: %w", err)
	}
	var resp awsGetPublicKeyResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("decode aws GetPublicKey: %w", err)
	}
	if len(resp.SigningAlgorithms) > 0 && !slices.Contains(resp.SigningAlgorithms, awsKMSSigningAlg) {
		return fmt.Errorf("aws kms key does not support %s: %w", awsKMSSigningAlg, audit.ErrUnsupportedKey)
	}
	der, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return fmt.Errorf("decode aws kms public key: %w", err)
	}
	pub, err := audit.ParsePublicKeyDER(der)
	if err != nil {
		return err
	}
	alg, err := audit.AlgorithmFor(pub)
	if err != nil {
		return err
	}
	if alg != audit.AlgECDSAP256 {
		return fmt.Errorf("aws kms key must be ecdsa p-256, got %s: %w", alg, audit.ErrUnsupportedKey)
	}
	keyID, err := audit.KeyIDFor(pub)
	if err != nil {
		return err
	}
	s.pub = pub
	s.alg = alg
	s.keyID = keyID
	return nil
}

func (s *AWSSigner) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	body, err := json.Marshal(awsSignReq{
		KeyID:            s.awsKeyID,
		Message:          base64.StdEncoding.EncodeToString(digest[:]),
		MessageType:      "DIGEST",
		SigningAlgorithm: awsKMSSigningAlg,
	})
	if err != nil {
		return nil, fmt.Errorf("encode aws Sign: %w", err)
	}
	raw, err := s.doKMS(ctx, awsTargetSign, body)
	if err != nil {
		return nil, fmt.Errorf("aws kms Sign: %w", err)
	}
	var resp awsSignResp
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode aws Sign: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("decode aws kms signature: %w", ErrBadResponse)
	}
	return sig, nil
}

func (s *AWSSigner) doKMS(ctx context.Context, target string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build aws kms request: %w", err)
	}
	signV4Request(req, body, target, s.region, s.accessKeyID, s.secretAccessKey, s.sessionToken, s.clock().UTC())
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws kms request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := readBody(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aws kms status %d: %w", resp.StatusCode, ErrBadResponse)
	}
	return raw, nil
}

func signV4Request(
	req *http.Request,
	body []byte,
	target, region, accessKey, secretKey, sessionToken string,
	now time.Time,
) {
	amzDate := now.Format("20060102T150405Z")
	dateStamp := amzDate[:8]
	payloadSum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(payloadSum[:])

	req.Header.Set("Content-Type", awsKMSContentType)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Target", target)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	host := req.URL.Host
	var canonHeaders strings.Builder
	var signedHeaders string
	canonHeaders.WriteString("content-type:" + awsKMSContentType + "\n")
	canonHeaders.WriteString("host:" + host + "\n")
	canonHeaders.WriteString("x-amz-date:" + amzDate + "\n")
	if sessionToken != "" {
		canonHeaders.WriteString("x-amz-security-token:" + sessionToken + "\n")
		canonHeaders.WriteString("x-amz-target:" + target + "\n")
		signedHeaders = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target"
	} else {
		canonHeaders.WriteString("x-amz-target:" + target + "\n")
		signedHeaders = "content-type;host;x-amz-date;x-amz-target"
	}

	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		canonicalURI,
		"",
		canonHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	crSum := sha256.Sum256([]byte(canonicalRequest))
	scope := dateStamp + "/" + region + "/" + awsKMSService + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(crSum[:])

	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, awsKMSService)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	auth := "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	req.Header.Set("Authorization", auth)
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
