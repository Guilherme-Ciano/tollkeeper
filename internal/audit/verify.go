package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"
)

type Report struct {
	ChainID       string
	Records       uint64
	Events        uint64
	Checkpoints   uint64
	KeyRotations  uint64
	Gaps          uint64
	DroppedEvents uint64
	LastSeq       uint64
	LastHash      string
	LastSignedSeq uint64
	UnsignedTail  uint64

	Anchors            uint64
	UnverifiedAnchors  uint64
	LastAnchoredSeq    uint64
	RecordsAfterAnchor uint64
	LastAnchorLog      string
	LastAnchorIndex    uint64
	LastAnchorTime     time.Time
	MaxAnchorDelay     time.Duration
}

type AnchorEvidence struct {
	Log           string
	LogIndex      uint64
	TreeSize      uint64
	Witnesses     int
	WitnessedAt   time.Time
	TimestampedAt time.Time
}

func (e AnchorEvidence) ProvenAt() time.Time {
	switch {
	case e.WitnessedAt.IsZero():
		return e.TimestampedAt
	case e.TimestampedAt.IsZero(), e.WitnessedAt.Before(e.TimestampedAt):
		return e.WitnessedAt
	default:
		return e.TimestampedAt
	}
}

type AnchorVerifier interface {
	VerifyAnchor(chainID string, a *Anchor, covered CheckpointRef, pub ed25519.PublicKey) (AnchorEvidence, error)
}

type VerifyOptions struct {
	PublicKey ed25519.PublicKey
	Keys      *KeySet
	Anchors   AnchorVerifier
}

var ErrAnchorNeedsKey = errors.New("verifying anchors requires the checkpoint public key")

const MaxClockStep = time.Minute

type VerifyError struct {
	Line   int
	Seq    uint64
	Reason string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("line %d (seq %d): %s", e.Line, e.Seq, e.Reason)
}

func (e *VerifyError) Unwrap() error {
	return ErrTampered
}

var ErrTampered = errors.New("audit chain verification failed")

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("trailing data: %w", ErrMalformed)
	}
	return nil
}

type ringEntry struct {
	ref    CheckpointRef
	nextTS int64
}

type checkpointRing struct {
	refs []ringEntry
}

func (c *checkpointRing) add(ref CheckpointRef) {
	if len(c.refs) >= 2*MaxAnchorLagCheckpoints {
		c.refs = append(c.refs[:0], c.refs[len(c.refs)-MaxAnchorLagCheckpoints:]...)
	}
	c.refs = append(c.refs, ringEntry{ref: ref, nextTS: math.MaxInt64})
}

func (c *checkpointRing) next(ts int64) {
	if n := len(c.refs); n > 0 && c.refs[n-1].nextTS == math.MaxInt64 {
		c.refs[n-1].nextTS = ts
	}
}

func (c *checkpointRing) find(seq uint64) (ringEntry, bool) {
	i, ok := slices.BinarySearchFunc(c.refs, seq, func(e ringEntry, s uint64) int {
		r := e.ref
		switch {
		case r.Seq < s:
			return -1
		case r.Seq > s:
			return 1
		default:
			return 0
		}
	})
	if !ok || len(c.refs)-1-i >= MaxAnchorLagCheckpoints {
		return ringEntry{}, false
	}
	return c.refs[i], true
}

type verifier struct {
	keys    *KeySet
	anchors AnchorVerifier
	rep     Report
	prev    string
	lineNo  int
	ckpts   checkpointRing
	firstTS int64
	lastTS  int64
	witSeq  uint64
}

func Verify(r io.Reader, pub ed25519.PublicKey) (Report, error) {
	return VerifyWith(r, VerifyOptions{PublicKey: pub})
}

func resolveVerifyKeys(o VerifyOptions) (*KeySet, error) {
	if o.Keys != nil {
		ks := o.Keys.Clone()
		if o.PublicKey != nil {
			if err := ks.Add(o.PublicKey); err != nil {
				return nil, err
			}
		}
		return ks, nil
	}
	return NewKeySet(o.PublicKey)
}

func VerifyWith(r io.Reader, o VerifyOptions) (Report, error) {
	var ks *KeySet
	if o.Keys != nil || o.PublicKey != nil {
		var err error
		ks, err = resolveVerifyKeys(o)
		if err != nil {
			return Report{}, err
		}
	}
	if o.Anchors != nil && (ks == nil || ks.Len() == 0) {
		return Report{}, ErrAnchorNeedsKey
	}
	v := &verifier{keys: ks, anchors: o.Anchors, prev: ZeroHash}
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			v.lineNo++
			if verr := v.line(line, err == nil); verr != nil {
				return v.rep, verr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return v.rep, fmt.Errorf("read audit log: %w", err)
		}
	}
	v.rep.LastHash = v.prev
	v.rep.UnsignedTail = v.rep.LastSeq - v.rep.LastSignedSeq
	v.rep.RecordsAfterAnchor = v.rep.LastSeq - v.rep.LastAnchoredSeq
	return v.rep, nil
}

func (v *verifier) fail(seq uint64, format string, args ...any) error {
	return &VerifyError{Line: v.lineNo, Seq: seq, Reason: fmt.Sprintf(format, args...)}
}

func (v *verifier) line(line []byte, terminated bool) error {
	expect := v.rep.LastSeq + 1
	if !terminated {
		return v.fail(expect, "truncated line without newline")
	}
	var rec Record
	if err := strictDecode(line, &rec); err != nil {
		return v.fail(expect, "malformed record: %v", err)
	}
	var body Body
	if err := strictDecode(rec.Body, &body); err != nil {
		return v.fail(expect, "malformed body: %v", err)
	}
	if body.Seq != expect {
		return v.fail(body.Seq, "sequence gap: expected seq %d", expect)
	}
	if v.rep.Records == 0 {
		v.rep.ChainID = body.ChainID
	} else if body.ChainID != v.rep.ChainID {
		return v.fail(body.Seq, "chain id changed from %q to %q", v.rep.ChainID, body.ChainID)
	}
	if body.Prev != v.prev {
		return v.fail(body.Seq, "prev hash does not link to seq %d", body.Seq-1)
	}
	want, err := ChainHash(body.Prev, rec.Body)
	if err != nil {
		return v.fail(body.Seq, "%v", err)
	}
	if want != rec.Hash {
		return v.fail(body.Seq, "hash mismatch: record content was modified")
	}
	if v.rep.Records > 0 && body.TS < v.lastTS-int64(MaxClockStep) {
		return v.fail(body.Seq, "timestamp goes back %s from the previous record",
			time.Duration(v.lastTS-body.TS))
	}
	if v.rep.Records == 0 {
		v.firstTS = body.TS
	}
	v.lastTS = max(v.lastTS, body.TS)
	v.ckpts.next(body.TS)
	if body.kinds() != 1 {
		return v.fail(body.Seq, "record must hold exactly one of event, checkpoint, anchor or key_rotation")
	}
	if err := v.account(&body, rec.Hash); err != nil {
		return err
	}
	v.prev = rec.Hash
	v.rep.Records++
	v.rep.LastSeq = body.Seq
	return nil
}

func (v *verifier) account(body *Body, hash string) error {
	switch {
	case body.Event != nil:
		v.rep.Events++
		if body.Event.Decision == DecisionGap {
			v.rep.Gaps++
			v.rep.DroppedEvents += body.Event.Dropped
		}
		return nil
	case body.Anchor != nil:
		return v.anchor(body)
	case body.KeyRotation != nil:
		return v.keyRotation(body)
	}
	if err := v.checkpoint(body); err != nil {
		return err
	}
	v.ckpts.add(CheckpointRef{ChainID: body.ChainID, Seq: body.Seq, Hash: hash, TS: body.TS})
	return nil
}

func (v *verifier) keyRotation(body *Body) error {
	kr := body.KeyRotation
	if v.keys != nil {
		prevPub, ok := v.keys.Lookup(kr.PrevKeyID)
		if !ok {
			return v.fail(body.Seq, "key rotation signed by unknown key %s", kr.PrevKeyID)
		}
		newPub, err := VerifyKeyRotation(prevPub, body.ChainID, kr)
		if err != nil {
			return v.fail(body.Seq, "invalid key rotation: %v", err)
		}
		if err := v.keys.Add(newPub); err != nil {
			return v.fail(body.Seq, "register rotated key: %v", err)
		}
	}
	v.rep.KeyRotations++
	return nil
}

func (v *verifier) anchor(body *Body) error {
	a := body.Anchor
	entry, ok := v.ckpts.find(a.CoversSeq)
	covered := entry.ref
	if !ok || covered.Hash != a.CoversHash {
		return v.fail(body.Seq, "anchor covers an unknown or different checkpoint at seq %d", a.CoversSeq)
	}
	var anchorPub ed25519.PublicKey
	if v.keys != nil {
		pub, ok := v.keys.Lookup(a.KeyID)
		if !ok {
			return v.fail(body.Seq, "anchor signed by unknown key %s", a.KeyID)
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return v.fail(body.Seq, "anchor key %s is not ed25519", a.KeyID)
		}
		anchorPub = edPub
	}
	v.rep.Anchors++
	if v.anchors == nil {
		v.rep.UnverifiedAnchors++
		return nil
	}
	ev, err := v.anchors.VerifyAnchor(body.ChainID, a, covered, anchorPub)
	if err != nil {
		return v.fail(body.Seq, "anchor for seq %d: %v", a.CoversSeq, err)
	}
	if a.CoversSeq >= v.rep.LastAnchoredSeq {
		v.rep.LastAnchoredSeq = a.CoversSeq
		v.rep.LastAnchorLog = ev.Log
		v.rep.LastAnchorIndex = ev.LogIndex
	}
	if at := ev.ProvenAt(); !at.IsZero() {
		return v.witnessed(body.Seq, covered, at)
	}
	return nil
}

func (v *verifier) witnessed(seq uint64, covered CheckpointRef, at time.Time) error {
	if at.UnixNano() < covered.TS-int64(MaxClockStep) {
		return v.fail(seq, "checkpoint at seq %d is dated after its anchor time", covered.Seq)
	}
	if covered.Seq <= v.witSeq {
		return nil
	}
	start := v.firstTS
	if v.witSeq > 0 {
		if prev, ok := v.ckpts.find(v.witSeq); ok && prev.nextTS != math.MaxInt64 {
			start = prev.nextTS
		}
	}
	v.witSeq = covered.Seq
	if at.After(v.rep.LastAnchorTime) {
		v.rep.LastAnchorTime = at
	}
	v.rep.MaxAnchorDelay = max(v.rep.MaxAnchorDelay, at.Sub(time.Unix(0, start)))
	return nil
}

func (v *verifier) checkpoint(body *Body) error {
	ck := body.Checkpoint
	if ck.CoversSeq != body.Seq-1 || ck.CoversHash != body.Prev {
		return v.fail(body.Seq, "checkpoint does not cover the preceding record")
	}
	if v.keys != nil {
		pub, ok := v.keys.Lookup(ck.KeyID)
		if !ok {
			return v.fail(body.Seq, "checkpoint signed by unknown key %s", ck.KeyID)
		}
		if !VerifyCheckpointAny(pub, body.ChainID, ck) {
			return v.fail(body.Seq, "invalid checkpoint signature")
		}
		v.rep.LastSignedSeq = body.Seq
	}
	v.rep.Checkpoints++
	return nil
}
