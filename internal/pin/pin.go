package pin

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
)

const lockfileVersion = 1

type Mode string

const (
	ModeOff     Mode = "off"
	ModeWarn    Mode = "warn"
	ModeEnforce Mode = "enforce"
)

func (m Mode) Valid() bool {
	return m == ModeOff || m == ModeWarn || m == ModeEnforce
}

type Status string

const (
	StatusApproved Status = "approved"
	StatusNew      Status = "new"
	StatusChanged  Status = "changed"
)

var (
	ErrVersion = errors.New("unsupported pin lockfile version")
	ErrEntry   = errors.New("invalid pin lockfile entry")
)

type Entry struct {
	Upstream    string          `json:"upstream"`
	Pin         string          `json:"pin"`
	Description string          `json:"description"`
	Descriptor  json.RawMessage `json:"descriptor,omitempty"`
	ApprovedAt  time.Time       `json:"approved_at"`
	ApprovedBy  string          `json:"approved_by,omitempty"`
}

type Lockfile struct {
	Version int              `json:"version"`
	Tools   map[string]Entry `json:"tools"`
}

func Empty() Lockfile {
	return Lockfile{Version: lockfileVersion, Tools: map[string]Entry{}}
}

func (l Lockfile) Status(t catalog.Tool) Status {
	e, ok := l.Tools[t.Name]
	switch {
	case !ok:
		return StatusNew
	case e.Pin != t.Pin || e.Upstream != t.Upstream:
		return StatusChanged
	default:
		return StatusApproved
	}
}

func (l Lockfile) Approve(t catalog.Tool, by string, at time.Time) Lockfile {
	next := Lockfile{Version: lockfileVersion, Tools: make(map[string]Entry, len(l.Tools)+1)}
	for k, v := range l.Tools {
		next.Tools[k] = v
	}
	next.Tools[t.Name] = Entry{
		Upstream:    t.Upstream,
		Pin:         t.Pin,
		Description: t.Description,
		Descriptor:  t.Descriptor,
		ApprovedAt:  at.UTC(),
		ApprovedBy:  by,
	}
	return next
}

func (l Lockfile) Names() []string {
	out := make([]string, 0, len(l.Tools))
	for k := range l.Tools {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func Parse(data []byte) (Lockfile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var l Lockfile
	if err := dec.Decode(&l); err != nil {
		return Lockfile{}, fmt.Errorf("parse pin lockfile: %w", err)
	}
	if l.Version != lockfileVersion {
		return Lockfile{}, fmt.Errorf("%w: %d", ErrVersion, l.Version)
	}
	if l.Tools == nil {
		l.Tools = map[string]Entry{}
	}
	for name, e := range l.Tools {
		if name == "" || e.Upstream == "" || e.Pin == "" {
			return Lockfile{}, fmt.Errorf("%w: %q", ErrEntry, name)
		}
	}
	return l, nil
}

func Read(path string) (Lockfile, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Empty(), nil
	}
	if err != nil {
		return Lockfile{}, fmt.Errorf("read pin lockfile: %w", err)
	}
	return Parse(data)
}

func Encode(l Lockfile) ([]byte, error) {
	if l.Tools == nil {
		l.Tools = map[string]Entry{}
	}
	l.Version = lockfileVersion
	out, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode pin lockfile: %w", err)
	}
	return append(out, '\n'), nil
}

func Write(path string, l Lockfile) error {
	data, err := Encode(l)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("write pin lockfile: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write pin lockfile: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("write pin lockfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync pin lockfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close pin lockfile: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace pin lockfile: %w", err)
	}
	return nil
}

type Guard struct {
	mode   Mode
	path   string
	mu     sync.Mutex
	digest [sha256.Size]byte
	lock   atomic.Pointer[Lockfile]
}

func NewGuard(mode Mode, path string) (*Guard, error) {
	g := &Guard{mode: mode, path: path}
	empty := Empty()
	g.lock.Store(&empty)
	if mode == ModeOff || path == "" {
		return g, nil
	}
	if _, err := g.Reload(); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *Guard) Mode() Mode {
	return g.mode
}

func (g *Guard) Lockfile() Lockfile {
	return *g.lock.Load()
}

func (g *Guard) Status(t catalog.Tool) Status {
	return g.lock.Load().Status(t)
}

func (g *Guard) Blocks(t catalog.Tool) bool {
	return g.mode == ModeEnforce && g.Status(t) != StatusApproved
}

func (g *Guard) Reload() (bool, error) {
	if g.mode == ModeOff || g.path == "" {
		return false, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	data, err := os.ReadFile(g.path)
	if errors.Is(err, fs.ErrNotExist) {
		data = nil
	} else if err != nil {
		return false, fmt.Errorf("read pin lockfile: %w", err)
	}
	sum := sha256.Sum256(data)
	if sum == g.digest {
		return false, nil
	}
	l := Empty()
	if data != nil {
		if l, err = Parse(data); err != nil {
			return false, err
		}
	}
	g.digest = sum
	g.lock.Store(&l)
	return true, nil
}

type Report struct {
	Mode  Mode         `json:"mode"`
	Tools []ToolReport `json:"tools"`
}

type ToolReport struct {
	Name                string          `json:"name"`
	Upstream            string          `json:"upstream"`
	Status              Status          `json:"status"`
	Pin                 string          `json:"pin"`
	ApprovedPin         string          `json:"approved_pin,omitempty"`
	Description         string          `json:"description"`
	ApprovedDescription string          `json:"approved_description,omitempty"`
	Descriptor          json.RawMessage `json:"descriptor"`
}

func BuildReport(mode Mode, l Lockfile, tools []catalog.Tool) Report {
	r := Report{Mode: mode, Tools: make([]ToolReport, 0, len(tools))}
	for i := range tools {
		t := &tools[i]
		tr := ToolReport{
			Name:        t.Name,
			Upstream:    t.Upstream,
			Status:      l.Status(*t),
			Pin:         t.Pin,
			Description: t.Description,
			Descriptor:  t.Descriptor,
		}
		if e, ok := l.Tools[t.Name]; ok {
			tr.ApprovedPin = e.Pin
			tr.ApprovedDescription = e.Description
		}
		r.Tools = append(r.Tools, tr)
	}
	sort.Slice(r.Tools, func(i, j int) bool { return r.Tools[i].Name < r.Tools[j].Name })
	return r
}

func (tr ToolReport) Tool() catalog.Tool {
	return catalog.Tool{
		Name:        tr.Name,
		Upstream:    tr.Upstream,
		Description: tr.Description,
		Pin:         tr.Pin,
		Descriptor:  tr.Descriptor,
	}
}
