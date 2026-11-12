package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type Report struct {
	ChainID       string
	Records       uint64
	Events        uint64
	Checkpoints   uint64
	Gaps          uint64
	DroppedEvents uint64
	LastSeq       uint64
	LastHash      string
	LastSignedSeq uint64
	UnsignedTail  uint64
}

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

type verifier struct {
	pub    ed25519.PublicKey
	rep    Report
	prev   string
	lineNo int
}

func Verify(r io.Reader, pub ed25519.PublicKey) (Report, error) {
	v := &verifier{pub: pub, prev: ZeroHash}
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
	if (body.Event == nil) == (body.Checkpoint == nil) {
		return v.fail(body.Seq, "record must hold exactly one of event or checkpoint")
	}
	if err := v.account(&body); err != nil {
		return err
	}
	v.prev = rec.Hash
	v.rep.Records++
	v.rep.LastSeq = body.Seq
	return nil
}

func (v *verifier) account(body *Body) error {
	if body.Event != nil {
		v.rep.Events++
		if body.Event.Decision == DecisionGap {
			v.rep.Gaps++
			v.rep.DroppedEvents += body.Event.Dropped
		}
		return nil
	}
	ck := body.Checkpoint
	if ck.CoversSeq != body.Seq-1 || ck.CoversHash != body.Prev {
		return v.fail(body.Seq, "checkpoint does not cover the preceding record")
	}
	if v.pub != nil {
		if ck.KeyID != KeyID(v.pub) {
			return v.fail(body.Seq, "checkpoint signed by unknown key %s", ck.KeyID)
		}
		if !VerifyCheckpoint(v.pub, body.ChainID, ck) {
			return v.fail(body.Seq, "invalid checkpoint signature")
		}
		v.rep.LastSignedSeq = body.Seq
	}
	v.rep.Checkpoints++
	return nil
}
