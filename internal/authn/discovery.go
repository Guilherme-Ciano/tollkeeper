package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const maxDiscoveryBytes = 64 << 10

var ErrDiscovery = errors.New("oidc metadata discovery failed")

type DiscoveryMetadata struct {
	Issuer                string   `json:"issuer"`
	JWKSURI               string   `json:"jwks_uri"`
	TokenEndpoint         string   `json:"token_endpoint"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	DPoPSigningAlgValues  []string `json:"dpop_signing_alg_values_supported"`
}

func DiscoverMetadata(
	ctx context.Context,
	issuer string,
	client *http.Client,
	allowInsecure bool,
) (DiscoveryMetadata, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(issuer), "/")
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return DiscoveryMetadata{}, fmt.Errorf("%w: invalid issuer %q", ErrDiscovery, issuer)
	}
	if u.Scheme != schemeHTTPS && !allowInsecure {
		return DiscoveryMetadata{}, fmt.Errorf("%w: plain http discovery requires allow_insecure_jwks", ErrDiscovery)
	}
	if client == nil {
		client = &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	candidates := []string{
		trimmed + "/.well-known/openid-configuration",
		trimmed + "/.well-known/oauth-authorization-server",
	}
	var lastErr error
	for _, endpoint := range candidates {
		meta, derr := fetchDiscoveryDoc(ctx, client, endpoint, trimmed, allowInsecure)
		if derr == nil {
			return meta, nil
		}
		lastErr = derr
	}
	return DiscoveryMetadata{}, lastErr
}

func fetchDiscoveryDoc(
	ctx context.Context,
	client *http.Client,
	endpoint, wantIssuer string,
	allowInsecure bool,
) (DiscoveryMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return DiscoveryMetadata{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return DiscoveryMetadata{}, fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return DiscoveryMetadata{}, fmt.Errorf("%w: %s returned status %d", ErrDiscovery, endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes+1))
	if err != nil || len(body) > maxDiscoveryBytes {
		return DiscoveryMetadata{}, fmt.Errorf("%w: unreadable metadata response", ErrDiscovery)
	}
	var meta DiscoveryMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return DiscoveryMetadata{}, fmt.Errorf("%w: malformed json: %w", ErrDiscovery, err)
	}
	if strings.TrimRight(meta.Issuer, "/") != wantIssuer {
		return DiscoveryMetadata{}, fmt.Errorf(
			"%w: metadata issuer %q does not match configured issuer %q",
			ErrDiscovery,
			meta.Issuer,
			wantIssuer,
		)
	}
	jwksURL, err := url.Parse(meta.JWKSURI)
	if err != nil || jwksURL.Host == "" || (jwksURL.Scheme != schemeHTTPS && !allowInsecure) {
		return DiscoveryMetadata{}, fmt.Errorf("%w: invalid jwks_uri %q", ErrDiscovery, meta.JWKSURI)
	}
	return meta, nil
}
