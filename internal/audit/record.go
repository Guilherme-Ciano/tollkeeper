package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	DecisionAllow       = "allow"
	DecisionDeny        = "deny"
	DecisionStepUp      = "step_up"
	DecisionRateLimited = "rate_limited"
	DecisionRejected    = "rejected"
	DecisionGap         = "audit_gap"

	PhaseIntent   = "intent"
	PhaseOutcome  = "outcome"
	PhaseDecision = "decision"

	checkpointDomain = "tollkeeper-ckpt-v1"
)

const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

type Event struct {
	Phase           string          `json:"phase"`
	RequestID       string          `json:"request_id"`
	TraceID         string          `json:"trace_id,omitempty"`
	Subject         string          `json:"sub,omitempty"`
	ClientID        string          `json:"client_id,omitempty"`
	ClientName      string          `json:"client_name,omitempty"`
	ClientVersion   string          `json:"client_version,omitempty"`
	ProtocolVersion string          `json:"protocol_version,omitempty"`
	Method          string          `json:"method"`
	Tool            string          `json:"tool,omitempty"`
	Upstream        string          `json:"upstream,omitempty"`
	Decision        string          `json:"decision"`
	Rule            string          `json:"rule,omitempty"`
	Reason          string          `json:"reason,omitempty"`
	ArgsHash        string          `json:"args_hash,omitempty"`
	Args            json.RawMessage `json:"args,omitempty"`
	ResultType      string          `json:"result_type,omitempty"`
	IsError         bool            `json:"is_error,omitempty"`
	ResultHash      string          `json:"result_hash,omitempty"`
	Error           string          `json:"error,omitempty"`
	LatencyMicros   int64           `json:"latency_us,omitempty"`
	UpstreamMicros  int64           `json:"upstream_us,omitempty"`
	PinHash         string          `json:"pin_hash,omitempty"`
	Dropped         uint64          `json:"dropped,omitempty"`
}

type Checkpoint struct {
	CoversSeq  uint64 `json:"covers_seq"`
	CoversHash string `json:"covers_hash"`
	KeyID      string `json:"key_id"`
	Signature  string `json:"sig"`
}

type Body struct {
	Seq        uint64      `json:"seq"`
	TS         int64       `json:"ts"`
	ChainID    string      `json:"chain_id"`
	Prev       string      `json:"prev"`
	Event      *Event      `json:"event,omitempty"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

type Record struct {
	Body json.RawMessage `json:"body"`
	Hash string          `json:"hash"`
}

func ChainHash(prevHex string, body []byte) (string, error) {
	prev, err := hex.DecodeString(prevHex)
	if err != nil || len(prev) != sha256.Size {
		return "", fmt.Errorf("prev hash %q: %w", prevHex, ErrMalformed)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Seal(b *Body) (Record, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return Record{}, fmt.Errorf("encode record %d: %w", b.Seq, err)
	}
	hash, err := ChainHash(b.Prev, raw)
	if err != nil {
		return Record{}, err
	}
	return Record{Body: raw, Hash: hash}, nil
}

func checkpointMessage(chainID string, seq uint64, hashHex string) ([]byte, error) {
	h, err := hex.DecodeString(hashHex)
	if err != nil || len(h) != sha256.Size {
		return nil, fmt.Errorf("checkpoint hash %q: %w", hashHex, ErrMalformed)
	}
	msg := make([]byte, 0, len(checkpointDomain)+1+len(chainID)+1+8+len(h))
	msg = append(msg, checkpointDomain...)
	msg = append(msg, 0)
	msg = append(msg, chainID...)
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint64(msg, seq)
	msg = append(msg, h...)
	return msg, nil
}

func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func SignCheckpoint(key ed25519.PrivateKey, chainID string, seq uint64, hashHex string) (*Checkpoint, error) {
	msg, err := checkpointMessage(chainID, seq, hashHex)
	if err != nil {
		return nil, err
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrKeyType
	}
	return &Checkpoint{
		CoversSeq:  seq,
		CoversHash: hashHex,
		KeyID:      KeyID(pub),
		Signature:  hex.EncodeToString(ed25519.Sign(key, msg)),
	}, nil
}

func VerifyCheckpoint(pub ed25519.PublicKey, chainID string, c *Checkpoint) bool {
	msg, err := checkpointMessage(chainID, c.CoversSeq, c.CoversHash)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
