package catalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/yosida95/uritemplate/v3"
)

type Kind string

const (
	KindPrompt   Kind = "prompt"
	KindResource Kind = "resource"
	KindTemplate Kind = "template"

	MaxURILen = 2048
)

var ErrMaxEntries = errors.New("directory entry limit reached")

type Entry struct {
	Kind       Kind
	Name       string
	Upstream   string
	Original   string
	Descriptor json.RawMessage
}

type entryKey struct {
	kind Kind
	name string
}

type compiledTemplate struct {
	entry int
	tmpl  *uritemplate.Template
}

type DirSnapshot struct {
	Version   uint64
	entries   []Entry
	index     map[entryKey]int
	templates []compiledTemplate
}

func (s *DirSnapshot) Lookup(kind Kind, name string) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	i, ok := s.index[entryKey{kind, name}]
	if !ok {
		return Entry{}, false
	}
	return s.entries[i], true
}

func (s *DirSnapshot) Entries(kind Kind) []Entry {
	if s == nil {
		return nil
	}
	var out []Entry
	for i := range s.entries {
		if s.entries[i].Kind == kind {
			out = append(out, s.entries[i])
		}
	}
	return out
}

func (s *DirSnapshot) Resource(uri string) (Entry, bool) {
	if e, ok := s.Lookup(KindResource, uri); ok {
		return e, true
	}
	if s == nil || len(uri) > MaxURILen {
		return Entry{}, false
	}
	for _, t := range s.templates {
		if t.tmpl.Match(uri) != nil {
			return s.entries[t.entry], true
		}
	}
	return Entry{}, false
}

func (s *DirSnapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

type Directory struct {
	max  int
	mu   sync.Mutex
	snap atomic.Pointer[DirSnapshot]
}

func NewDirectory(maxEntries int) *Directory {
	d := &Directory{max: maxEntries}
	d.snap.Store(&DirSnapshot{index: map[entryKey]int{}})
	return d
}

func (d *Directory) Snapshot() *DirSnapshot {
	return d.snap.Load()
}

func validEntry(e *Entry) error {
	switch e.Kind {
	case KindPrompt:
		if e.Name == "" || len(e.Name) > MaxNameLen {
			return fmt.Errorf("%w: prompt %q", ErrBadName, e.Name)
		}
	case KindResource, KindTemplate:
		if e.Name == "" || len(e.Name) > MaxURILen || strings.ContainsFunc(e.Name, isControl) {
			return fmt.Errorf("%w: uri %q", ErrBadName, e.Name)
		}
		if e.Kind == KindTemplate {
			if _, err := uritemplate.New(e.Name); err != nil {
				return fmt.Errorf("%w: template %q: %w", ErrBadName, e.Name, err)
			}
		}
	default:
		return fmt.Errorf("%w: kind %q", ErrBadName, e.Kind)
	}
	return nil
}

func (d *Directory) Replace(upstream string, entries []Entry) (changed bool, rejected []error, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	prev := d.snap.Load()
	next := make([]Entry, 0, len(prev.entries)+len(entries))
	seen := map[entryKey]bool{}
	for i := range prev.entries {
		if e := prev.entries[i]; e.Upstream != upstream {
			next = append(next, e)
			seen[entryKey{e.Kind, e.Name}] = true
		}
	}
	for i := range entries {
		e := entries[i]
		e.Upstream = upstream
		k := entryKey{e.Kind, e.Name}
		switch verr := validEntry(&e); {
		case verr != nil:
			rejected = append(rejected, verr)
			continue
		case seen[k]:
			rejected = append(rejected, fmt.Errorf("%w: %s %s", ErrDuplicate, e.Kind, e.Name))
			continue
		}
		seen[k] = true
		next = append(next, e)
	}
	if d.max > 0 && len(next) > d.max {
		return false, rejected, fmt.Errorf("%w: %d > %d", ErrMaxEntries, len(next), d.max)
	}
	slices.SortFunc(next, func(a, b Entry) int {
		if c := strings.Compare(string(a.Kind), string(b.Kind)); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	if equalEntries(prev.entries, next) {
		return false, rejected, nil
	}
	snap := &DirSnapshot{Version: prev.Version + 1, entries: next, index: make(map[entryKey]int, len(next))}
	for i := range next {
		snap.index[entryKey{next[i].Kind, next[i].Name}] = i
		if next[i].Kind != KindTemplate {
			continue
		}
		t, terr := uritemplate.New(next[i].Name)
		if terr != nil {
			continue
		}
		snap.templates = append(snap.templates, compiledTemplate{entry: i, tmpl: t})
	}
	d.snap.Store(snap)
	return true, rejected, nil
}

func equalEntries(a, b []Entry) bool {
	return slices.EqualFunc(a, b, func(x, y Entry) bool {
		return x.Kind == y.Kind && x.Name == y.Name && x.Upstream == y.Upstream && x.Original == y.Original &&
			bytes.Equal(x.Descriptor, y.Descriptor)
	})
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}
