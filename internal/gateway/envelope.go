package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
)

var (
	ErrBatch        = errors.New("batch requests are not supported")
	ErrEnvelope     = errors.New("malformed JSON-RPC envelope")
	ErrDuplicateKey = errors.New("duplicate or case-variant key")
)

type Envelope struct {
	ID              json.RawMessage
	Method          string
	Name            string
	Arguments       json.RawMessage
	ProtocolVersion string
	ClientName      string
	ClientVersion   string
	TraceParent     string
	HasParams       bool
}

func (e *Envelope) IsNotification() bool {
	return len(e.ID) == 0
}

func openObject(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	d, ok := tok.(json.Delim)
	switch {
	case ok && d == '{':
		return nil
	case ok && d == '[':
		return ErrBatch
	default:
		return fmt.Errorf("%w: expected object", ErrEnvelope)
	}
}

func checkKey(folded map[string]struct{}, known []string, k string) error {
	lk := foldKey(k)
	if _, dup := folded[lk]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateKey, k)
	}
	for _, kn := range known {
		if strings.EqualFold(k, kn) && k != kn {
			return fmt.Errorf("%w: %q", ErrDuplicateKey, k)
		}
	}
	folded[lk] = struct{}{}
	return nil
}

func strictObject(raw []byte, known ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := openObject(dec); err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{}
	folded := map[string]struct{}{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEnvelope, err)
		}
		k, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("%w: non-string key", ErrEnvelope)
		}
		if err := checkKey(folded, known, k); err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEnvelope, err)
		}
		out[k] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvelope, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrEnvelope)
	}
	return out, nil
}

const MaxArgumentTokens = 100_000

var ErrTooComplex = errors.New("arguments too complex")

func foldKey(s string) string {
	return strings.Map(func(r rune) rune {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			m = min(m, f)
		}
		return m
	}, s)
}

type frame struct {
	object bool
	expect bool
	first  string
	keys   map[string]struct{}
}

func (f *frame) addKey(k string) error {
	folded := foldKey(k)
	switch {
	case f.keys == nil && f.first == "":
		f.first = folded
		return nil
	case f.keys == nil:
		if folded == f.first {
			return fmt.Errorf("%w: %q", ErrDuplicateKey, k)
		}
		f.keys = map[string]struct{}{f.first: {}}
	}
	if _, dup := f.keys[folded]; dup {
		return fmt.Errorf("%w: %q", ErrDuplicateKey, k)
	}
	f.keys[folded] = struct{}{}
	return nil
}

func RejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []frame
	for tokens := 0; ; tokens++ {
		if tokens > MaxArgumentTokens {
			return fmt.Errorf("%w: more than %d JSON tokens", ErrTooComplex, MaxArgumentTokens)
		}
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEnvelope, err)
		}
		if err := step(&stack, tok); err != nil {
			return err
		}
	}
}

func step(stack *[]frame, tok json.Token) error {
	var top *frame
	if n := len(*stack); n > 0 {
		top = &(*stack)[n-1]
	}
	if d, ok := tok.(json.Delim); ok {
		switch d {
		case '{', '[':
			if top != nil && top.object {
				top.expect = true
			}
			*stack = append(*stack, frame{object: d == '{', expect: true})
		case '}', ']':
			*stack = (*stack)[:len(*stack)-1]
		}
		return nil
	}
	if top == nil || !top.object {
		return nil
	}
	if !top.expect {
		top.expect = true
		return nil
	}
	k, ok := tok.(string)
	if !ok {
		return fmt.Errorf("%w: non-string key", ErrEnvelope)
	}
	top.expect = false
	return top.addKey(k)
}

func stringField(m map[string]json.RawMessage, k string) (string, error) {
	raw, ok := m[k]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%w: %s must be a string", ErrEnvelope, k)
	}
	return s, nil
}

func lenientString(m map[string]json.RawMessage, k string) string {
	s, err := stringField(m, k)
	if err != nil {
		return ""
	}
	return s
}

func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null"
}

func ParseEnvelope(body []byte) (Envelope, error) {
	var env Envelope
	top, err := strictObject(body, "jsonrpc", "id", "method", "params")
	if err != nil {
		return env, err
	}
	if err := env.readTop(top); err != nil {
		return env, err
	}
	params, ok := top["params"]
	if !ok || isNull(params) {
		return env, nil
	}
	env.HasParams = true
	p, err := strictObject(params, "name", "uri", "arguments", "_meta", "requestState", "inputResponses")
	if err != nil {
		if errors.Is(err, ErrBatch) {
			return env, fmt.Errorf("%w: params must be an object", ErrEnvelope)
		}
		return env, err
	}
	err = env.readParams(p)
	return env, err
}

func (e *Envelope) readTop(top map[string]json.RawMessage) error {
	ver, err := stringField(top, "jsonrpc")
	if err != nil || ver != "2.0" {
		return fmt.Errorf("%w: jsonrpc must be \"2.0\"", ErrEnvelope)
	}
	if e.Method, err = stringField(top, "method"); err != nil || e.Method == "" {
		return fmt.Errorf("%w: method required", ErrEnvelope)
	}
	if id, ok := top["id"]; ok && !isNull(id) {
		t := bytes.TrimSpace(id)
		if t[0] != '"' && (t[0] < '0' || t[0] > '9') && t[0] != '-' {
			return fmt.Errorf("%w: id must be a string or number", ErrEnvelope)
		}
		e.ID = t
	}
	return nil
}

func (e *Envelope) readParams(p map[string]json.RawMessage) error {
	var err error
	switch e.Method {
	case MethodToolsCall, "prompts/get":
		e.Name, err = stringField(p, "name")
	case "resources/read":
		e.Name, err = stringField(p, "uri")
	}
	if err != nil {
		return err
	}
	if strings.ContainsFunc(e.Name, unicode.IsControl) {
		return fmt.Errorf("%w: control character in name", ErrEnvelope)
	}
	if a, ok := p["arguments"]; ok && !isNull(a) {
		t := bytes.TrimSpace(a)
		if t[0] != '{' {
			return fmt.Errorf("%w: arguments must be an object", ErrEnvelope)
		}
		if err := RejectDuplicateKeys(t); err != nil {
			return fmt.Errorf("arguments: %w", err)
		}
		e.Arguments = t
	}
	if meta, ok := p["_meta"]; ok && !isNull(meta) {
		if err := e.readMeta(meta); err != nil {
			return err
		}
	}
	if e.Method == "initialize" {
		e.readInitialize(p)
	}
	return nil
}

func (e *Envelope) readMeta(raw json.RawMessage) error {
	m, err := strictObject(raw)
	if err != nil {
		return fmt.Errorf("%w: _meta: %w", ErrEnvelope, err)
	}
	e.ProtocolVersion = lenientString(m, "io.modelcontextprotocol/protocolVersion")
	e.TraceParent = lenientString(m, "traceparent")
	if ci, ok := m["io.modelcontextprotocol/clientInfo"]; ok {
		var info struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(ci, &info) == nil {
			e.ClientName, e.ClientVersion = info.Name, info.Version
		}
	}
	return nil
}

func (e *Envelope) readInitialize(p map[string]json.RawMessage) {
	e.ProtocolVersion = lenientString(p, "protocolVersion")
	if ci, ok := p["clientInfo"]; ok {
		var info struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(ci, &info) == nil {
			e.ClientName, e.ClientVersion = info.Name, info.Version
		}
	}
}
