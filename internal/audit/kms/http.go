package kms

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/netguard"
)

const (
	defaultTimeout   = 10 * time.Second
	maxResponseBytes = 1 << 20
)

var (
	ErrRedirectBlocked = errors.New("kms client refuses http redirects")
	ErrBadResponse     = errors.New("unexpected kms response")
	ErrConfig          = errors.New("invalid kms signer configuration")
)

func newHTTPClient(timeout time.Duration, blockPrivateIPs bool, override *http.Client) *http.Client {
	if override != nil {
		return override
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	dialer := netguard.Dialer(timeout, 30*time.Second, blockPrivateIPs)
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			IdleConnTimeout:       60 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirectBlocked
		},
	}
}

func readBody(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read kms response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("kms response exceeds %d bytes: %w", maxResponseBytes, ErrBadResponse)
	}
	return data, nil
}
