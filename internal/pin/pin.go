package pin

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
	ErrExposed    = errors.New("pin lockfile is writable by group or others")
	ErrVersion    = errors.New("unsupported pin lockfile version")
	ErrEntry      = errors.New("invalid pin lockfile entry")
	ErrConcurrent = errors.New("pin lockfile changed since it was read")
)

type Entry struct {
	Upstream    string          `json:"upstream"`
	Pin         string          `json:"pin"`
	Description string          `json:"description"`
	Descriptor  json.RawMessage `json:"descriptor,omitempty"`
	Original    string          `json:"original,omitempty"`
	Definition  json.RawMessage `json:"definition,omitempty"`
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
	maps.Copy(next.Tools, l.Tools)
	next.Tools[t.Name] = Entry{
		Upstream:    t.Upstream,
		Pin:         t.Pin,
		Description: t.Description,
		Descriptor:  t.Descriptor,
		Original:    t.Original,
		Definition:  t.Definition,
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
	l, _, err := ReadVersioned(path)
	return l, err
}

func ReadVersioned(path string) (Lockfile, [sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Empty(), sha256.Sum256(nil), nil
	}
	if err != nil {
		return Lockfile{}, [sha256.Size]byte{}, fmt.Errorf("read pin lockfile: %w", err)
	}
	l, err := Parse(data)
	return l, sha256.Sum256(data), err
}

func WriteIfUnchanged(path string, l Lockfile, read [sha256.Size]byte) error {
	_, current, err := ReadVersioned(path)
	if err != nil && !errors.Is(err, ErrVersion) && !errors.Is(err, ErrEntry) {
		return err
	}
	if current != read {
		return ErrConcurrent
	}
	return Write(path, l)
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
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync pin lockfile directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("sync pin lockfile directory: %w", err)
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
	l := *g.lock.Load()
	l.Tools = maps.Clone(l.Tools)
	return l
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
	if info, err := os.Stat(g.path); err == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return false, fmt.Errorf("%w: %s has mode %#o", ErrExposed, g.path, info.Mode().Perm())
	}
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
	Original            string          `json:"original"`
	Definition          json.RawMessage `json:"definition"`
	ApprovedDefinition  json.RawMessage `json:"approved_definition,omitempty"`
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
			Original:    t.Original,
			Definition:  t.Definition,
		}
		if e, ok := l.Tools[t.Name]; ok {
			tr.ApprovedPin = e.Pin
			tr.ApprovedDescription = e.Description
			tr.ApprovedDefinition = e.Definition
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
		Original:    tr.Original,
		Description: tr.Description,
		Pin:         tr.Pin,
		Descriptor:  tr.Descriptor,
		Definition:  tr.Definition,
	}
}

var ErrReportMismatch = errors.New("pin report does not match the definition it carries")

func (tr ToolReport) Verify() error {
	if catalog.PinHash(tr.Original, tr.Definition) != tr.Pin {
		return fmt.Errorf("%w: %s pin", ErrReportMismatch, tr.Name)
	}
	var def, served map[string]any
	if err := json.Unmarshal(tr.Definition, &def); err != nil {
		return fmt.Errorf("%w: %s definition: %w", ErrReportMismatch, tr.Name, err)
	}
	if err := json.Unmarshal(tr.Descriptor, &served); err != nil {
		return fmt.Errorf("%w: %s descriptor: %w", ErrReportMismatch, tr.Name, err)
	}
	if def["name"] != tr.Original {
		return fmt.Errorf("%w: %s original name", ErrReportMismatch, tr.Name)
	}
	delete(def, "name")
	delete(served, "name")
	if !reflect.DeepEqual(def, served) {
		return fmt.Errorf("%w: %s serves a different descriptor than it pins", ErrReportMismatch, tr.Name)
	}
	if d, _ := def["description"].(string); d != tr.Description {
		return fmt.Errorf("%w: %s description", ErrReportMismatch, tr.Name)
	}
	return nil
}
