package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

const MaxNameLen = 128

var (
	ErrBadName   = errors.New("invalid tool name")
	ErrNotFound  = errors.New("tool not found")
	ErrMaxTools  = errors.New("catalog tool limit reached")
	ErrDuplicate = errors.New("duplicate tool name from upstream")
)

type Annotations struct {
	Title       string `json:"title,omitempty"`
	ReadOnly    bool   `json:"readOnlyHint"`
	Destructive bool   `json:"destructiveHint"`
	Idempotent  bool   `json:"idempotentHint"`
	OpenWorld   bool   `json:"openWorldHint"`
}

type Tool struct {
	Name        string
	Upstream    string
	Original    string
	Description string
	Annotations Annotations
	Pin         string
	Descriptor  json.RawMessage
}

type Naming struct {
	Separator string
}

func validChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' ||
		r == '.'
}

func (n Naming) Qualify(upstream, name string) (string, error) {
	if name == "" || strings.Contains(name, n.Separator) {
		return "", fmt.Errorf("%w: %q from %s", ErrBadName, name, upstream)
	}
	for _, r := range name {
		if !validChar(r) {
			return "", fmt.Errorf("%w: %q from %s contains %q", ErrBadName, name, upstream, r)
		}
	}
	q := upstream + n.Separator + name
	if len(q) > MaxNameLen {
		return "", fmt.Errorf("%w: %q exceeds %d characters", ErrBadName, q, MaxNameLen)
	}
	return q, nil
}

func (n Naming) Split(qualified string) (upstream, name string, ok bool) {
	upstream, name, ok = strings.Cut(qualified, n.Separator)
	if !ok || upstream == "" || name == "" {
		return "", "", false
	}
	return upstream, name, true
}

func PinHash(original, description string, inputSchema, outputSchema json.RawMessage, a Annotations) string {
	h := sha256.New()
	for _, part := range [][]byte{[]byte(original), []byte(description), inputSchema, outputSchema} {
		fmt.Fprintf(h, "%d:", len(part))
		h.Write(part)
	}
	fmt.Fprintf(h, "%q|%t|%t|%t|%t", a.Title, a.ReadOnly, a.Destructive, a.Idempotent, a.OpenWorld)
	return hex.EncodeToString(h.Sum(nil))
}

type Snapshot struct {
	Version uint64
	tools   []Tool
	index   map[string]int
}

func (s *Snapshot) Lookup(name string) (Tool, bool) {
	if s == nil {
		return Tool{}, false
	}
	i, ok := s.index[name]
	if !ok {
		return Tool{}, false
	}
	return s.tools[i], true
}

func (s *Snapshot) Tools() []Tool {
	if s == nil {
		return nil
	}
	return slices.Clone(s.tools)
}

func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.tools)
}

type Delta struct {
	Upserted []Tool
	Removed  []string
}

func (d Delta) Empty() bool {
	return len(d.Upserted) == 0 && len(d.Removed) == 0
}

type Catalog struct {
	maxTools int
	mu       sync.Mutex
	snap     atomic.Pointer[Snapshot]
}

func New(maxTools int) *Catalog {
	c := &Catalog{maxTools: maxTools}
	c.snap.Store(&Snapshot{index: map[string]int{}})
	return c
}

func (c *Catalog) Snapshot() *Snapshot {
	return c.snap.Load()
}

func (c *Catalog) Lookup(name string) (Tool, bool) {
	return c.snap.Load().Lookup(name)
}

func (c *Catalog) Replace(upstream string, tools []Tool) (Delta, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.snap.Load()
	incoming := make(map[string]Tool, len(tools))
	for i := range tools {
		t := &tools[i]
		if t.Upstream != upstream {
			return Delta{}, fmt.Errorf("%w: %s belongs to %s", ErrBadName, t.Name, t.Upstream)
		}
		if _, dup := incoming[t.Name]; dup {
			return Delta{}, fmt.Errorf("%w: %s", ErrDuplicate, t.Name)
		}
		incoming[t.Name] = *t
	}
	var d Delta
	next := make([]Tool, 0, len(prev.tools)+len(tools))
	for i := range prev.tools {
		t := &prev.tools[i]
		if t.Upstream != upstream {
			next = append(next, *t)
			continue
		}
		if _, keep := incoming[t.Name]; !keep {
			d.Removed = append(d.Removed, t.Name)
		}
	}
	for i := range tools {
		t := &tools[i]
		old, existed := prev.Lookup(t.Name)
		if !existed || old.Pin != t.Pin {
			d.Upserted = append(d.Upserted, *t)
		}
		next = append(next, *t)
	}
	if c.maxTools > 0 && len(next) > c.maxTools {
		return Delta{}, fmt.Errorf("%w: %d > %d", ErrMaxTools, len(next), c.maxTools)
	}
	slices.SortFunc(next, func(a, b Tool) int { return strings.Compare(a.Name, b.Name) })
	slices.Sort(d.Removed)
	idx := make(map[string]int, len(next))
	for i := range next {
		idx[next[i].Name] = i
	}
	if !d.Empty() {
		c.snap.Store(&Snapshot{Version: prev.Version + 1, tools: next, index: idx})
	}
	return d, nil
}
