package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	dpopTyp              = "dpop+jwt"
	defaultDPoPMaxAge    = 60 * time.Second
	defaultDPoPLeeway    = 30 * time.Second
	defaultDPoPNonceTTL  = 5 * time.Minute
	maxDPoPReplayEntries = 50_000
)

var (
	ErrInvalidDPoP   = errors.New("invalid dpop proof")
	ErrUseDPoPNonce  = errors.New("dpop nonce required")
	ErrDPoPReplayed  = errors.New("dpop proof replayed")
	ErrDPoPRequired  = errors.New("dpop proof required")
	ErrDPoPForbidden = errors.New("dpop-bound token requires dpop authorization scheme")
)

func DefaultDPoPAlgorithms() []string {
	return []string{"ES256", "ES384", "EdDSA", "RS256", "PS256"}
}

type DPoPOptions struct {
	Algorithms    []string
	MaxAge        time.Duration
	Leeway        time.Duration
	NonceRequired bool
	NonceTTL      time.Duration
	NonceKey      []byte
	TargetURL     string
	MaxReplay     int
	Now           func() time.Time
}

type DPoPVerifier struct {
	algs          []string
	maxAge        time.Duration
	leeway        time.Duration
	nonceRequired bool
	nonceTTL      time.Duration
	nonceKey      []byte
	targetHTU     string
	maxReplay     int
	now           func() time.Time

	mu   sync.Mutex
	seen map[string]time.Time
}

func NewDPoPVerifier(o DPoPOptions) *DPoPVerifier {
	algs := slices.Clone(o.Algorithms)
	if len(algs) == 0 {
		algs = DefaultDPoPAlgorithms()
	}
	maxAge := o.MaxAge
	if maxAge <= 0 {
		maxAge = defaultDPoPMaxAge
	}
	leeway := o.Leeway
	if leeway <= 0 {
		leeway = defaultDPoPLeeway
	}
	nonceTTL := o.NonceTTL
	if nonceTTL <= 0 {
		nonceTTL = defaultDPoPNonceTTL
	}
	nonceKey := slices.Clone(o.NonceKey)
	if len(nonceKey) < 32 {
		nonceKey = make([]byte, 32)
		_, _ = rand.Read(nonceKey)
	}
	maxReplay := o.MaxReplay
	if maxReplay <= 0 {
		maxReplay = maxDPoPReplayEntries
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	targetHTU := ""
	if o.TargetURL != "" {
		if norm, err := canonicalHTU(o.TargetURL); err == nil {
			targetHTU = norm
		}
	}
	return &DPoPVerifier{
		algs:          algs,
		maxAge:        maxAge,
		leeway:        leeway,
		nonceRequired: o.NonceRequired,
		nonceTTL:      nonceTTL,
		nonceKey:      nonceKey,
		targetHTU:     targetHTU,
		maxReplay:     maxReplay,
		now:           now,
		seen:          map[string]time.Time{},
	}
}

func (v *DPoPVerifier) Algorithms() []string {
	return slices.Clone(v.algs)
}

func (v *DPoPVerifier) NonceRequired() bool {
	return v.nonceRequired
}

func (v *DPoPVerifier) IssueNonce() string {
	return v.nonceForBucket(v.currentBucket())
}

func (v *DPoPVerifier) currentBucket() int64 {
	sec := v.now().Unix()
	step := max(int64(v.nonceTTL/time.Second), 1)
	if sec < 0 {
		return 0
	}
	return sec / step
}

func (v *DPoPVerifier) nonceForBucket(bucket int64) string {
	b := strconv.AppendInt(nil, bucket, 10)
	mac := hmac.New(sha256.New, v.nonceKey)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (v *DPoPVerifier) validNonce(nonce string) bool {
	if nonce == "" {
		return false
	}
	cur := v.currentBucket()
	cand := v.nonceForBucket(cur)
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(cand)) == 1 {
		return true
	}
	if cur > 0 {
		prev := v.nonceForBucket(cur - 1)
		return subtle.ConstantTimeCompare([]byte(nonce), []byte(prev)) == 1
	}
	return false
}

type dpopHeaderJWK struct {
	JWK
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	DP string `json:"dp,omitempty"`
	DQ string `json:"dq,omitempty"`
	QI string `json:"qi,omitempty"`
	K  string `json:"k,omitempty"`
}

func (j dpopHeaderJWK) hasPrivateMaterial() bool {
	return j.D != "" || j.P != "" || j.Q != "" || j.DP != "" || j.DQ != "" || j.QI != "" || j.K != ""
}

func JWKThumbprint(j JWK) (string, error) {
	var canonical []byte
	var err error
	switch j.Kty {
	case "EC":
		if j.Crv == "" || j.X == "" || j.Y == "" {
			return "", fmt.Errorf("%w: incomplete EC jwk", ErrInvalidDPoP)
		}
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{Crv: j.Crv, Kty: j.Kty, X: j.X, Y: j.Y})
	case ktyOKP:
		if j.Crv == "" || j.X == "" {
			return "", fmt.Errorf("%w: incomplete OKP jwk", ErrInvalidDPoP)
		}
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{Crv: j.Crv, Kty: j.Kty, X: j.X})
	case "RSA":
		if j.E == "" || j.N == "" {
			return "", fmt.Errorf("%w: incomplete RSA jwk", ErrInvalidDPoP)
		}
		canonical, err = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{E: j.E, Kty: j.Kty, N: j.N})
	default:
		return "", fmt.Errorf("%w: unsupported jwk kty %q", ErrInvalidDPoP, j.Kty)
	}
	if err != nil {
		return "", fmt.Errorf("%w: encode jwk thumbprint: %w", ErrInvalidDPoP, err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (v *DPoPVerifier) Verify(r *http.Request, accessToken, expectedJKT string) (string, error) {
	vals := r.Header.Values("DPoP")
	if len(vals) == 0 {
		return "", ErrDPoPRequired
	}
	if len(vals) > 1 {
		return "", fmt.Errorf("%w: multiple DPoP headers", ErrInvalidDPoP)
	}
	rawProof := strings.TrimSpace(vals[0])
	if rawProof == "" {
		return "", ErrDPoPRequired
	}
	jkt, claims, err := v.parseProof(rawProof)
	if err != nil {
		return "", err
	}
	if expectedJKT != "" && subtle.ConstantTimeCompare([]byte(jkt), []byte(expectedJKT)) != 1 {
		return "", fmt.Errorf("%w: jwk thumbprint mismatch", ErrInvalidDPoP)
	}
	if err := v.verifyClaims(r, accessToken, claims, jkt); err != nil {
		return "", err
	}
	return jkt, nil
}

func (v *DPoPVerifier) parseProof(raw string) (string, jwt.MapClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods(v.algs),
		jwt.WithStrictDecoding(),
		jwt.WithTimeFunc(v.now),
	)
	var jkt string
	claims := jwt.MapClaims{}
	_, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		typ, ok := t.Header["typ"].(string)
		if !ok || !strings.EqualFold(typ, dpopTyp) {
			return nil, fmt.Errorf("%w: typ must be %s", ErrInvalidDPoP, dpopTyp)
		}
		rawJWK, ok := t.Header["jwk"]
		if !ok || rawJWK == nil {
			return nil, fmt.Errorf("%w: missing jwk header", ErrInvalidDPoP)
		}
		jwkBytes, err := json.Marshal(rawJWK)
		if err != nil {
			return nil, fmt.Errorf("%w: marshal jwk header: %w", ErrInvalidDPoP, err)
		}
		var hj dpopHeaderJWK
		if err := json.Unmarshal(jwkBytes, &hj); err != nil {
			return nil, fmt.Errorf("%w: decode jwk header: %w", ErrInvalidDPoP, err)
		}
		if hj.hasPrivateMaterial() {
			return nil, fmt.Errorf("%w: jwk header must not contain private parameters", ErrInvalidDPoP)
		}
		pub, err := ParseJWK(hj.JWK)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidDPoP, err)
		}
		thumb, err := JWKThumbprint(hj.JWK)
		if err != nil {
			return "", err
		}
		jkt = thumb
		return pub, nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("%w: %w", ErrInvalidDPoP, err)
	}
	return jkt, claims, nil
}

func (v *DPoPVerifier) verifyClaims(r *http.Request, accessToken string, claims jwt.MapClaims, jkt string) error {
	htm := claimString(claims, "htm")
	if htm == "" || htm != r.Method {
		return fmt.Errorf("%w: htm %q does not match %s", ErrInvalidDPoP, htm, r.Method)
	}
	if err := v.checkHTU(r, claimString(claims, "htu")); err != nil {
		return err
	}
	if err := v.checkIAT(claims); err != nil {
		return err
	}
	ath := claimString(claims, "ath")
	wantATH := AccessTokenHash(accessToken)
	if ath == "" || subtle.ConstantTimeCompare([]byte(ath), []byte(wantATH)) != 1 {
		return fmt.Errorf("%w: ath mismatch", ErrInvalidDPoP)
	}
	if v.nonceRequired && !v.validNonce(claimString(claims, "nonce")) {
		return ErrUseDPoPNonce
	}
	jti := claimString(claims, "jti")
	if jti == "" || len(jti) > 256 {
		return fmt.Errorf("%w: missing or oversized jti", ErrInvalidDPoP)
	}
	return v.recordJTI(jkt + ":" + jti)
}

func (v *DPoPVerifier) checkHTU(r *http.Request, rawHTU string) error {
	got, err := canonicalHTU(rawHTU)
	if err != nil {
		return fmt.Errorf("%w: invalid htu", ErrInvalidDPoP)
	}
	want := v.targetHTU
	if want == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = schemeHTTPS
		}
		want = scheme + "://" + strings.ToLower(r.Host) + r.URL.Path
	}
	if got != want {
		return fmt.Errorf("%w: htu %q does not match %q", ErrInvalidDPoP, got, want)
	}
	return nil
}

func (v *DPoPVerifier) checkIAT(claims jwt.MapClaims) error {
	iat, err := claims.GetIssuedAt()
	if err != nil || iat == nil {
		return fmt.Errorf("%w: missing iat", ErrInvalidDPoP)
	}
	now := v.now()
	if iat.After(now.Add(v.leeway)) {
		return fmt.Errorf("%w: proof issued in the future", ErrInvalidDPoP)
	}
	if now.Sub(iat.Time) > v.maxAge+v.leeway {
		return fmt.Errorf("%w: proof expired", ErrInvalidDPoP)
	}
	return nil
}

func (v *DPoPVerifier) recordJTI(key string) error {
	now := v.now()
	expires := now.Add(v.maxAge + v.leeway)
	v.mu.Lock()
	defer v.mu.Unlock()
	if exp, ok := v.seen[key]; ok && now.Before(exp) {
		return ErrDPoPReplayed
	}
	if len(v.seen) >= v.maxReplay {
		for k, exp := range v.seen {
			if !now.Before(exp) {
				delete(v.seen, k)
			}
		}
		for k := range v.seen {
			if len(v.seen) < v.maxReplay {
				break
			}
			delete(v.seen, k)
		}
	}
	v.seen[key] = expires
	return nil
}

func canonicalHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrInvalidDPoP
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path, nil
}
