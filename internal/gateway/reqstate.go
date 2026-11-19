package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	statePrefix     = "tk1."
	MinStateKeyLen  = 32
	DefaultStateTTL = 10 * time.Minute
	maxStateToken   = 256 << 10
)

var ErrRequestState = errors.New("invalid or expired requestState")

type statePayload struct {
	Upstream string `json:"u"`
	Tool     string `json:"t"`
	Subject  string `json:"s,omitempty"`
	ClientID string `json:"c,omitempty"`
	Inner    string `json:"i"`
	Expires  int64  `json:"e"`
}

type stateSealer struct {
	key []byte
	ttl time.Duration
}

func newStateSealer(key []byte, ttl time.Duration) *stateSealer {
	if ttl <= 0 {
		ttl = DefaultStateTTL
	}
	if key == nil {
		key = []byte(rand.Text() + rand.Text())
	}
	return &stateSealer{key: key, ttl: ttl}
}

func (s *stateSealer) mac(body string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(body))
	return m.Sum(nil)
}

func (s *stateSealer) seal(p statePayload, now time.Time) (string, error) {
	p.Expires = now.Add(s.ttl).Unix()
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode request state: %w", err)
	}
	body := statePrefix + base64.RawURLEncoding.EncodeToString(b)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.mac(body)), nil
}

func (s *stateSealer) open(token string, now time.Time) (statePayload, error) {
	var p statePayload
	if len(token) > maxStateToken {
		return p, ErrRequestState
	}
	i := strings.LastIndexByte(token, '.')
	if i < 0 || !strings.HasPrefix(token, statePrefix) {
		return p, ErrRequestState
	}
	body := token[:i]
	sig, err := base64.RawURLEncoding.DecodeString(token[i+1:])
	if err != nil || !hmac.Equal(sig, s.mac(body)) {
		return p, ErrRequestState
	}
	raw, err := base64.RawURLEncoding.DecodeString(body[len(statePrefix):])
	if err != nil || json.Unmarshal(raw, &p) != nil || now.Unix() >= p.Expires {
		return statePayload{}, ErrRequestState
	}
	return p, nil
}
