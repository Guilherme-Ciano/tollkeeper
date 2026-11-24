package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/adminui"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/pin"
)

const (
	adminContentJSON      = "application/json"
	defaultAuditPageLimit = 100
	maxAuditPageLimit     = 500
	maxAuditTailBytes     = 2 << 20
)

type adminErrorResponse struct {
	Error string `json:"error"`
}

type overviewAuthDTO struct {
	Mode     string `json:"mode"`
	Provider string `json:"provider"`
	DPoPMode string `json:"dpop_mode"`
}

type overviewPinningDTO struct {
	Mode     string `json:"mode"`
	File     string `json:"file"`
	Approved int    `json:"approved"`
	New      int    `json:"new"`
	Changed  int    `json:"changed"`
	Total    int    `json:"total"`
}

type overviewPolicyDTO struct {
	Default string `json:"default"`
	Rules   int    `json:"rules"`
	Tenants int    `json:"tenants"`
}

type overviewRateLimitsDTO struct {
	Store string `json:"store"`
	Rules int    `json:"rules"`
}

type overviewWatchdogDTO struct {
	Enabled      bool   `json:"enabled"`
	Checked      bool   `json:"checked,omitempty"`
	Healthy      bool   `json:"healthy,omitempty"`
	Records      uint64 `json:"records,omitempty"`
	Checkpoints  uint64 `json:"checkpoints,omitempty"`
	LastSeq      uint64 `json:"last_seq,omitempty"`
	UnsignedTail uint64 `json:"unsigned_tail,omitempty"`
	Error        string `json:"error,omitempty"`
	VerifiedAt   string `json:"verified_at,omitempty"`
}

type overviewAuditDTO struct {
	Enabled         bool                `json:"enabled"`
	ChainID         string              `json:"chain_id"`
	Path            string              `json:"path"`
	RecordArgs      string              `json:"record_args"`
	OTLPEnabled     bool                `json:"otlp_enabled"`
	SIEMEnabled     bool                `json:"siem_enabled"`
	SIEMFormat      string              `json:"siem_format"`
	PostgresEnabled bool                `json:"postgres_enabled"`
	AnchorEnabled   bool                `json:"anchor_enabled"`
	Watchdog        overviewWatchdogDTO `json:"watchdog"`
}

type overviewCatalogDTO struct {
	Tools     int    `json:"tools"`
	Prompts   int    `json:"prompts"`
	Resources int    `json:"resources"`
	Templates int    `json:"templates"`
	Version   uint64 `json:"version"`
}

type overviewUpstreamsDTO struct {
	Total  int `json:"total"`
	Ready  int `json:"ready"`
	Synced int `json:"synced"`
}

type overviewBundleDTO struct {
	Enabled  bool   `json:"enabled"`
	Verified bool   `json:"verified"`
	BundleID string `json:"bundle_id,omitempty"`
	KeyID    string `json:"key_id,omitempty"`
}

type overviewApprovalsDTO struct {
	Enabled   bool   `json:"enabled"`
	Header    string `json:"header,omitempty"`
	SingleUse bool   `json:"single_use,omitempty"`
}

type overviewIdempotencyDTO struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"`
	Header  string `json:"header,omitempty"`
}

type overviewResponse struct {
	Version         string                 `json:"version"`
	Ready           bool                   `json:"ready"`
	PublicURL       string                 `json:"public_url"`
	AdminListen     string                 `json:"admin_listen"`
	ConfigDigest    string                 `json:"config_digest"`
	StampProvenance bool                   `json:"stamp_provenance"`
	TasksEnabled    bool                   `json:"tasks_enabled"`
	Auth            overviewAuthDTO        `json:"auth"`
	Pinning         overviewPinningDTO     `json:"pinning"`
	Policy          overviewPolicyDTO      `json:"policy"`
	RateLimits      overviewRateLimitsDTO  `json:"rate_limits"`
	Idempotency     overviewIdempotencyDTO `json:"idempotency"`
	Approvals       overviewApprovalsDTO   `json:"approvals"`
	Bundle          overviewBundleDTO      `json:"bundle"`
	Audit           overviewAuditDTO       `json:"audit"`
	Catalog         overviewCatalogDTO     `json:"catalog"`
	Upstreams       overviewUpstreamsDTO   `json:"upstreams"`
}

type auditEventsResponse struct {
	Enabled      bool             `json:"enabled"`
	Path         string           `json:"path"`
	TotalScanned int              `json:"total_scanned"`
	Events       []auditEventView `json:"events"`
}

func (a *App) registerAdminUI(mux *http.ServeMux) {
	ui := adminui.Handler()
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		if !a.adminUIEnabled() {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})
	mux.HandleFunc("GET /ui/{path...}", func(w http.ResponseWriter, r *http.Request) {
		if !a.adminUIEnabled() {
			http.NotFound(w, r)
			return
		}
		ui.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /api/overview", a.apiOverview)
	mux.HandleFunc("GET /api/policy", a.apiPolicyGet)
	mux.HandleFunc("POST /api/policy/validate", a.apiPolicyValidate)
	mux.HandleFunc("GET /api/pins", a.apiPins)
	mux.HandleFunc("POST /api/simulate", a.apiSimulate)
	mux.HandleFunc("GET /api/audit/events", a.apiAuditEvents)
}

func (a *App) adminUIEnabled() bool {
	return a.cfg.Pinning.ReportToken != "" || config.Loopback(a.cfg.Server.AdminListen)
}

func (a *App) requireAdminAPI(w http.ResponseWriter, r *http.Request) bool {
	if !a.adminUIEnabled() {
		http.NotFound(w, r)
		return false
	}
	if !a.adminReportAllowed(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tollkeeper-admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *App) writeAdminJSON(ctx context.Context, w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", adminContentJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		a.log.DebugContext(ctx, "admin api write failed", slog.String("error", err.Error()))
	}
}

func (a *App) apiOverview(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAPI(w, r) {
		return
	}
	snap := a.catalog.Snapshot()
	tools := snap.Tools()
	dirSnap := a.directory.Snapshot()
	prompts := len(dirSnap.Entries(catalog.KindPrompt))
	resources := len(dirSnap.Entries(catalog.KindResource))
	templates := len(dirSnap.Entries(catalog.KindTemplate))
	var readyUp, syncedUp int
	for _, u := range a.upstreams {
		if u.Up() {
			readyUp++
		}
		if a.serving(u) {
			syncedUp++
		}
	}
	a.reloadMu.Lock()
	pol := a.cfg.Policy
	rlRules := len(a.cfg.RateLimits.Rules)
	digest := a.cfg.Digest
	bStatus := a.bundleStatus
	a.reloadMu.Unlock()

	bundleDTO := overviewBundleDTO{Enabled: a.cfg.Bundle.Enabled}
	if bStatus != nil {
		bundleDTO.Verified = true
		bundleDTO.BundleID = bStatus.BundleID
		bundleDTO.KeyID = bStatus.KeyID
	}

	a.writeAdminJSON(r.Context(), w, http.StatusOK, overviewResponse{
		Version:         a.version,
		Ready:           a.ready.Load(),
		PublicURL:       a.cfg.Server.PublicURL,
		AdminListen:     a.cfg.Server.AdminListen,
		ConfigDigest:    digest,
		StampProvenance: a.cfg.Server.StampProvenance,
		TasksEnabled:    a.cfg.Server.TasksEnabled,
		Auth: overviewAuthDTO{
			Mode:     a.cfg.Auth.Mode,
			Provider: a.cfg.Auth.Provider,
			DPoPMode: a.cfg.Auth.DPoP.Mode,
		},
		Pinning: a.pinSummary(tools),
		Policy: overviewPolicyDTO{
			Default: pol.Default,
			Rules:   len(pol.Rules),
			Tenants: len(pol.Tenants),
		},
		RateLimits: overviewRateLimitsDTO{
			Store: a.cfg.RateLimits.Store,
			Rules: rlRules,
		},
		Idempotency: overviewIdempotencyDTO{
			Enabled: a.cfg.Idempotency.Enabled,
			Mode:    a.cfg.Idempotency.Mode,
			Header:  a.cfg.Idempotency.Header,
		},
		Approvals: overviewApprovalsDTO{
			Enabled:   a.cfg.Approvals.Enabled,
			Header:    a.cfg.Approvals.Header,
			SingleUse: a.cfg.Approvals.SingleUse,
		},
		Bundle: bundleDTO,
		Audit:  a.auditSummary(),
		Catalog: overviewCatalogDTO{
			Tools:     len(tools),
			Prompts:   prompts,
			Resources: resources,
			Templates: templates,
			Version:   snap.Version,
		},
		Upstreams: overviewUpstreamsDTO{
			Total:  len(a.upstreams),
			Ready:  readyUp,
			Synced: syncedUp,
		},
	})
}

func (a *App) pinSummary(tools []catalog.Tool) overviewPinningDTO {
	out := overviewPinningDTO{
		Mode:  string(pin.ModeOff),
		File:  a.cfg.Pinning.File,
		Total: len(tools),
	}
	if a.pins == nil {
		return out
	}
	out.Mode = string(a.pins.Mode())
	rep := pin.BuildReport(a.pins.Mode(), a.pins.Lockfile(), tools)
	for i := range rep.Tools {
		switch rep.Tools[i].Status {
		case pin.StatusApproved:
			out.Approved++
		case pin.StatusNew:
			out.New++
		case pin.StatusChanged:
			out.Changed++
		}
	}
	return out
}

func (a *App) auditSummary() overviewAuditDTO {
	wd := overviewWatchdogDTO{Enabled: a.watchdog != nil}
	if a.watchdog != nil {
		if st, ok := a.watchdog.Status(); ok {
			wd.Checked = true
			wd.Healthy = st.Healthy
			wd.Records = st.Records
			wd.Checkpoints = st.Checkpoints
			wd.LastSeq = st.LastSeq
			wd.UnsignedTail = st.UnsignedTail
			wd.Error = st.Error
			wd.VerifiedAt = st.VerifiedAt.UTC().Format(time.RFC3339)
		}
	}
	return overviewAuditDTO{
		Enabled:         a.cfg.Audit.Enabled,
		ChainID:         a.cfg.Audit.ChainID,
		Path:            a.cfg.Audit.Path,
		RecordArgs:      a.cfg.Audit.RecordArgs,
		OTLPEnabled:     a.otlp != nil,
		SIEMEnabled:     a.siem != nil,
		SIEMFormat:      a.cfg.Audit.SIEM.Format,
		PostgresEnabled: a.auditPG != nil,
		AnchorEnabled:   a.anchorer != nil,
		Watchdog:        wd,
	}
}

func (a *App) apiPins(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAPI(w, r) {
		return
	}
	if a.pins == nil {
		a.writeAdminJSON(r.Context(), w, http.StatusOK, pin.Report{Mode: pin.ModeOff, Tools: []pin.ToolReport{}})
		return
	}
	report := pin.BuildReport(a.pins.Mode(), a.pins.Lockfile(), a.catalog.Snapshot().Tools())
	a.writeAdminJSON(r.Context(), w, http.StatusOK, report)
}

type auditEventFilter struct {
	limit    int
	decision string
	phase    string
	kind     string
	tenant   string
	sub      string
	tool     string
	query    string
}

type auditEventView struct {
	Seq     uint64          `json:"seq"`
	TS      string          `json:"ts"`
	ChainID string          `json:"chain_id"`
	Kind    string          `json:"kind"`
	Hash    string          `json:"hash"`
	Prev    string          `json:"prev"`
	Event   *audit.Event    `json:"event,omitempty"`
	Summary string          `json:"summary"`
	Raw     json.RawMessage `json:"raw"`
}

func parseAuditFilter(r *http.Request) auditEventFilter {
	q := r.URL.Query()
	limit := defaultAuditPageLimit
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = min(v, maxAuditPageLimit)
	}
	return auditEventFilter{
		limit:    limit,
		decision: strings.ToLower(strings.TrimSpace(q.Get("decision"))),
		phase:    strings.ToLower(strings.TrimSpace(q.Get("phase"))),
		kind:     strings.ToLower(strings.TrimSpace(q.Get("kind"))),
		tenant:   strings.ToLower(strings.TrimSpace(q.Get("tenant"))),
		sub:      strings.ToLower(strings.TrimSpace(q.Get("sub"))),
		tool:     strings.ToLower(strings.TrimSpace(q.Get("tool"))),
		query:    strings.ToLower(strings.TrimSpace(q.Get("q"))),
	}
}

func (a *App) apiAuditEvents(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAPI(w, r) {
		return
	}
	if !a.cfg.Audit.Enabled || a.cfg.Audit.Path == "" {
		a.writeAdminJSON(r.Context(), w, http.StatusOK, auditEventsResponse{
			Enabled: false,
			Path:    a.cfg.Audit.Path,
			Events:  []auditEventView{},
		})
		return
	}
	f := parseAuditFilter(r)
	events, scanned, err := readRecentAuditEvents(a.cfg.Audit.Path, f)
	if err != nil {
		a.writeAdminJSON(r.Context(), w, http.StatusInternalServerError, adminErrorResponse{Error: err.Error()})
		return
	}
	a.writeAdminJSON(r.Context(), w, http.StatusOK, auditEventsResponse{
		Enabled:      true,
		Path:         a.cfg.Audit.Path,
		TotalScanned: scanned,
		Events:       events,
	})
}

func readRecentAuditEvents(path string, f auditEventFilter) (events []auditEventView, scanned int, err error) {
	data, err := readFileTail(path, maxAuditTailBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []auditEventView{}, 0, nil
		}
		return nil, 0, err
	}
	lines := bytes.Split(data, []byte{'\n'})
	out := make([]auditEventView, 0, defaultAuditPageLimit)
	for i := len(lines) - 1; i >= 0 && len(out) < f.limit; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		v, ok := decodeAuditLine(line)
		if !ok {
			continue
		}
		scanned++
		if matchesAuditFilter(&v, f) {
			out = append(out, v)
		}
	}
	return out, scanned, nil
}

func readFileTail(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat audit log: %w", err)
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}
	offset := max(size-maxBytes, 0)
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek audit log: %w", err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes))
	if err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	if offset > 0 {
		if nl := bytes.IndexByte(data, '\n'); nl >= 0 {
			data = data[nl+1:]
		}
	}
	return data, nil
}

func decodeAuditLine(line []byte) (auditEventView, bool) {
	var rec audit.Record
	if err := json.Unmarshal(line, &rec); err != nil || len(rec.Body) == 0 {
		return auditEventView{}, false
	}
	var body audit.Body
	if err := json.Unmarshal(rec.Body, &body); err != nil {
		return auditEventView{}, false
	}
	kind, summary := classifyAuditBody(&body)
	return auditEventView{
		Seq:     body.Seq,
		TS:      time.Unix(0, body.TS).UTC().Format(time.RFC3339Nano),
		ChainID: body.ChainID,
		Kind:    kind,
		Hash:    rec.Hash,
		Prev:    body.Prev,
		Event:   body.Event,
		Summary: summary,
		Raw:     bytes.Clone(line),
	}, true
}

func classifyAuditBody(b *audit.Body) (kind, summary string) {
	switch {
	case b.Event != nil:
		e := b.Event
		if e.Tool != "" {
			return audit.KindEvent, e.Phase + " " + e.Tool + " -> " + e.Decision
		}
		return audit.KindEvent, e.Phase + " " + e.Method + " -> " + e.Decision
	case b.Checkpoint != nil:
		return audit.KindCheckpoint, "checkpoint covers seq " + strconv.FormatUint(
			b.Checkpoint.CoversSeq,
			10,
		) + " (" + b.Checkpoint.KeyID + ")"
	case b.Anchor != nil:
		return audit.KindAnchor, "rekor anchor covers seq " + strconv.FormatUint(b.Anchor.CoversSeq, 10)
	case b.KeyRotation != nil:
		return audit.KindKeyRotation, "key rotated " + b.KeyRotation.PrevKeyID + " -> " + b.KeyRotation.NewKeyID
	default:
		return "unknown", ""
	}
}

func matchesAuditFilter(v *auditEventView, f auditEventFilter) bool {
	if f.kind != "" && !strings.EqualFold(v.Kind, f.kind) {
		return false
	}
	if f.decision != "" || f.phase != "" || f.tenant != "" || f.sub != "" || f.tool != "" {
		if v.Event == nil {
			return false
		}
		if !matchesEventFields(v.Event, f) {
			return false
		}
	}
	if f.query != "" && !strings.Contains(strings.ToLower(string(v.Raw)), f.query) {
		return false
	}
	return true
}

func matchesEventFields(e *audit.Event, f auditEventFilter) bool {
	if f.decision != "" && !strings.EqualFold(e.Decision, f.decision) {
		return false
	}
	if f.phase != "" && !strings.EqualFold(e.Phase, f.phase) {
		return false
	}
	if f.tenant != "" && !strings.Contains(strings.ToLower(e.Tenant), f.tenant) {
		return false
	}
	if f.sub != "" && !strings.Contains(strings.ToLower(e.Subject), f.sub) {
		return false
	}
	if f.tool != "" && !strings.Contains(strings.ToLower(e.Tool), f.tool) {
		return false
	}
	return true
}
