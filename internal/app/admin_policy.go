package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/pin"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
)

const (
	maxAdminAPIBody = 256 << 10
	kindPrompt      = "prompt"
	kindResource    = "resource"
	kindTemplate    = "template"
)

type policyDTO struct {
	Default string                     `json:"default"           yaml:"default"`
	Rules   []ruleDTO                  `json:"rules"             yaml:"rules"`
	Tenants map[string]tenantPolicyDTO `json:"tenants,omitempty" yaml:"tenants,omitempty"`
}

type tenantPolicyDTO struct {
	Default string    `json:"default,omitempty" yaml:"default,omitempty"`
	Rules   []ruleDTO `json:"rules"             yaml:"rules"`
}

type ruleDTO struct {
	Name      string      `json:"name"                yaml:"name"`
	Subjects  subjectsDTO `json:"subjects"            yaml:"subjects,omitempty"`
	Tools     []string    `json:"tools,omitempty"     yaml:"tools,omitempty"`
	Prompts   []string    `json:"prompts,omitempty"   yaml:"prompts,omitempty"`
	Resources []string    `json:"resources,omitempty" yaml:"resources,omitempty"`
	When      string      `json:"when,omitempty"      yaml:"when,omitempty"`
	Mode      string      `json:"mode,omitempty"      yaml:"mode,omitempty"`
	Effect    string      `json:"effect"              yaml:"effect"`
	OnDeny    onDenyDTO   `json:"on_deny"             yaml:"on_deny,omitempty"`
}

type subjectsDTO struct {
	Subs      []string `json:"subs,omitempty"       yaml:"subs,omitempty"`
	ClientIDs []string `json:"client_ids,omitempty" yaml:"client_ids,omitempty"`
	Actors    []string `json:"actors,omitempty"     yaml:"actors,omitempty"`
	Tenants   []string `json:"tenants,omitempty"    yaml:"tenants,omitempty"`
	RolesAny  []string `json:"roles_any,omitempty"  yaml:"roles_any,omitempty"`
	GroupsAny []string `json:"groups_any,omitempty" yaml:"groups_any,omitempty"`
	ScopesAny []string `json:"scopes_any,omitempty" yaml:"scopes_any,omitempty"`
	ScopesAll []string `json:"scopes_all,omitempty" yaml:"scopes_all,omitempty"`
}

type onDenyDTO struct {
	StepUpScopes []string `json:"step_up_scopes,omitempty" yaml:"step_up_scopes,omitempty"`
	ACRValues    []string `json:"acr_values,omitempty"     yaml:"acr_values,omitempty"`
	MaxAge       string   `json:"max_age,omitempty"        yaml:"max_age,omitempty"`
	RequireDPoP  bool     `json:"require_dpop,omitempty"   yaml:"require_dpop,omitempty"`
}

type policyDocYAML struct {
	Policy policyDTO `yaml:"policy"`
}

type policyGetResponse struct {
	Policy       policyDTO `json:"policy"`
	YAML         string    `json:"yaml"`
	ConfigDigest string    `json:"config_digest"`
}

type policyValidateResponse struct {
	Valid          bool       `json:"valid"`
	Rules          int        `json:"rules,omitempty"`
	Tenants        int        `json:"tenants,omitempty"`
	Policy         *policyDTO `json:"policy,omitempty"`
	NormalizedYAML string     `json:"normalized_yaml,omitempty"`
	Errors         []string   `json:"errors,omitempty"`
}

type simulateShadowDTO struct {
	Rule   string `json:"rule"`
	Effect string `json:"effect"`
}

type simulateStepUpDTO struct {
	Scopes      []string `json:"scopes,omitempty"`
	ACRValues   []string `json:"acr_values,omitempty"`
	MaxAge      string   `json:"max_age,omitempty"`
	RequireDPoP bool     `json:"require_dpop,omitempty"`
}

type simulateResponse struct {
	Decision       string             `json:"decision"`
	Rule           string             `json:"rule"`
	Reason         string             `json:"reason"`
	Visible        bool               `json:"visible"`
	CatalogMatched bool               `json:"catalog_matched"`
	PinStatus      string             `json:"pin_status"`
	PinBlocked     bool               `json:"pin_blocked"`
	Steps          []simulateStepDTO  `json:"steps"`
	Shadow         *simulateShadowDTO `json:"shadow,omitempty"`
	StepUp         *simulateStepUpDTO `json:"step_up,omitempty"`
}

func policyToDTO(p config.Policy) policyDTO {
	def := p.Default
	if def == "" {
		def = config.EffectDeny
	}
	out := policyDTO{
		Default: def,
		Rules:   rulesToDTO(p.Rules),
	}
	if len(p.Tenants) > 0 {
		out.Tenants = make(map[string]tenantPolicyDTO, len(p.Tenants))
		for id, tp := range p.Tenants {
			out.Tenants[id] = tenantPolicyDTO{
				Default: tp.Default,
				Rules:   rulesToDTO(tp.Rules),
			}
		}
	}
	return out
}

func rulesToDTO(in []config.Rule) []ruleDTO {
	out := make([]ruleDTO, 0, len(in))
	for i := range in {
		r := &in[i]
		maxAge := ""
		if r.OnDeny.MaxAge > 0 {
			maxAge = r.OnDeny.MaxAge.String()
		}
		out = append(out, ruleDTO{
			Name:      r.Name,
			Subjects:  subjectsDTO(r.Subjects),
			Tools:     r.Tools,
			Prompts:   r.Prompts,
			Resources: r.Resources,
			When:      r.When,
			Mode:      r.Mode,
			Effect:    r.Effect,
			OnDeny: onDenyDTO{
				StepUpScopes: r.OnDeny.StepUpScopes,
				ACRValues:    r.OnDeny.ACRValues,
				MaxAge:       maxAge,
				RequireDPoP:  r.OnDeny.RequireDPoP,
			},
		})
	}
	return out
}

func dtoToPolicy(d policyDTO) (config.Policy, error) {
	def := d.Default
	if def == "" {
		def = config.EffectDeny
	}
	rules, err := dtoToRules("policy.rules", d.Rules)
	if err != nil {
		return config.Policy{}, err
	}
	out := config.Policy{Default: def, Rules: rules}
	if len(d.Tenants) > 0 {
		out.Tenants = make(map[string]config.TenantPolicy, len(d.Tenants))
		for id, tp := range d.Tenants {
			trules, terr := dtoToRules("policy.tenants."+id+".rules", tp.Rules)
			if terr != nil {
				return config.Policy{}, terr
			}
			out.Tenants[id] = config.TenantPolicy{Default: tp.Default, Rules: trules}
		}
	}
	return out, nil
}

func dtoToRules(prefix string, in []ruleDTO) ([]config.Rule, error) {
	out := make([]config.Rule, 0, len(in))
	for i := range in {
		r := &in[i]
		var maxAge time.Duration
		if strings.TrimSpace(r.OnDeny.MaxAge) != "" {
			d, err := time.ParseDuration(strings.TrimSpace(r.OnDeny.MaxAge))
			if err != nil {
				return nil, fmt.Errorf("%s[%d].on_deny.max_age: %w", prefix, i, err)
			}
			maxAge = d
		}
		out = append(out, config.Rule{
			Name:      r.Name,
			Subjects:  config.Subjects(r.Subjects),
			Tools:     r.Tools,
			Prompts:   r.Prompts,
			Resources: r.Resources,
			When:      r.When,
			Mode:      r.Mode,
			Effect:    r.Effect,
			OnDeny: config.OnDeny{
				StepUpScopes: r.OnDeny.StepUpScopes,
				ACRValues:    r.OnDeny.ACRValues,
				MaxAge:       maxAge,
				RequireDPoP:  r.OnDeny.RequireDPoP,
			},
		})
	}
	return out, nil
}

func renderPolicyYAML(d policyDTO) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(policyDocYAML{Policy: d}); err != nil {
		return "", fmt.Errorf("encode policy yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("close policy yaml encoder: %w", err)
	}
	return buf.String(), nil
}

func parsePolicyYAML(raw string) (policyDTO, error) {
	var probe map[string]any
	if err := yaml.Unmarshal([]byte(raw), &probe); err != nil {
		return policyDTO{}, fmt.Errorf("parse yaml: %w", err)
	}
	if _, hasTop := probe["policy"]; hasTop {
		var doc policyDocYAML
		dec := yaml.NewDecoder(strings.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&doc); err != nil {
			return policyDTO{}, fmt.Errorf("decode policy yaml: %w", err)
		}
		return doc.Policy, nil
	}
	var dto policyDTO
	dec := yaml.NewDecoder(strings.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&dto); err != nil {
		return policyDTO{}, fmt.Errorf("decode policy yaml: %w", err)
	}
	return dto, nil
}

func compileDraftPolicy(rawYAML string, draft *policyDTO) (policyDTO, config.Policy, *policy.Engine, error) {
	var dto policyDTO
	switch {
	case strings.TrimSpace(rawYAML) != "":
		var err error
		dto, err = parsePolicyYAML(rawYAML)
		if err != nil {
			return policyDTO{}, config.Policy{}, nil, err
		}
	case draft != nil:
		dto = *draft
	default:
		return policyDTO{}, config.Policy{}, nil, errors.New("policy yaml or json object is required")
	}
	cfgPol, err := dtoToPolicy(dto)
	if err != nil {
		return policyDTO{}, config.Policy{}, nil, err
	}
	if err := config.ValidatePolicy(cfgPol); err != nil {
		return policyDTO{}, config.Policy{}, nil, err
	}
	eng, err := policy.New(cfgPol)
	if err != nil {
		return policyDTO{}, config.Policy{}, nil, err
	}
	return policyToDTO(cfgPol), cfgPol, eng, nil
}

func (a *App) apiPolicyGet(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAPI(w, r) {
		return
	}
	a.reloadMu.Lock()
	pol := a.cfg.Policy
	digest := a.cfg.Digest
	a.reloadMu.Unlock()

	dto := policyToDTO(pol)
	rendered, err := renderPolicyYAML(dto)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.writeAdminJSON(r.Context(), w, http.StatusOK, policyGetResponse{
		Policy:       dto,
		YAML:         rendered,
		ConfigDigest: digest,
	})
}

type policyValidateRequest struct {
	YAML   string     `json:"yaml"`
	Policy *policyDTO `json:"policy"`
}

func (a *App) apiPolicyValidate(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAPI(w, r) {
		return
	}
	var req policyValidateRequest
	if err := decodeAdminBody(w, r, &req); err != nil {
		a.writeAdminJSON(r.Context(), w, http.StatusBadRequest, policyValidateResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		})
		return
	}
	dto, cfgPol, _, err := compileDraftPolicy(req.YAML, req.Policy)
	if err != nil {
		errs := strings.Split(strings.TrimSpace(err.Error()), "\n")
		a.writeAdminJSON(r.Context(), w, http.StatusOK, policyValidateResponse{
			Valid:  false,
			Errors: errs,
		})
		return
	}
	normalized, rerr := renderPolicyYAML(dto)
	if rerr != nil {
		a.writeAdminJSON(r.Context(), w, http.StatusInternalServerError, policyValidateResponse{
			Valid:  false,
			Errors: []string{rerr.Error()},
		})
		return
	}
	a.writeAdminJSON(r.Context(), w, http.StatusOK, policyValidateResponse{
		Valid:          true,
		Rules:          len(cfgPol.Rules),
		Tenants:        len(cfgPol.Tenants),
		Policy:         &dto,
		NormalizedYAML: normalized,
	})
}

type simulatePrincipalReq struct {
	Sub            string         `json:"sub"`
	ClientID       string         `json:"client_id"`
	Tenant         string         `json:"tenant"`
	Actor          string         `json:"actor"`
	Scopes         []string       `json:"scopes"`
	Roles          []string       `json:"roles"`
	Groups         []string       `json:"groups"`
	ACR            string         `json:"acr"`
	AMR            []string       `json:"amr"`
	AuthAgeSeconds *int64         `json:"auth_age_seconds"`
	DPoP           bool           `json:"dpop"`
	JKT            string         `json:"jkt"`
	Claims         map[string]any `json:"claims"`
}

type simulateAnnotationsReq struct {
	ReadOnly    *bool `json:"readOnlyHint"`
	Destructive *bool `json:"destructiveHint"`
	Idempotent  *bool `json:"idempotentHint"`
	OpenWorld   *bool `json:"openWorldHint"`
}

type simulateRequest struct {
	Kind        string                  `json:"kind"`
	Name        string                  `json:"name"`
	Method      string                  `json:"method"`
	ClientName  string                  `json:"client_name"`
	Principal   simulatePrincipalReq    `json:"principal"`
	Annotations *simulateAnnotationsReq `json:"annotations"`
	Args        json.RawMessage         `json:"args"`
	PolicyYAML  string                  `json:"policy_yaml"`
}

type simulateStepDTO struct {
	Rule    string `json:"rule"`
	Shadow  bool   `json:"shadow"`
	Outcome string `json:"outcome"`
}

func (a *App) apiSimulate(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminAPI(w, r) {
		return
	}
	var req simulateRequest
	if err := decodeAdminBody(w, r, &req); err != nil {
		a.writeAdminJSON(r.Context(), w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		a.writeAdminJSON(r.Context(), w, http.StatusBadRequest, adminErrorResponse{Error: "name is required"})
		return
	}
	eng := a.gateway.Policy()
	if strings.TrimSpace(req.PolicyYAML) != "" {
		var err error
		_, _, eng, err = compileDraftPolicy(req.PolicyYAML, nil)
		if err != nil {
			a.writeAdminJSON(r.Context(), w, http.StatusBadRequest, adminErrorResponse{Error: err.Error()})
			return
		}
	}
	in, catalogMatched, pinStatus, pinBlocked := a.buildSimInput(req)
	steps, dec := eng.Explain(r.Context(), in)
	vis := eng.VisibleAs(in.Principal, in.Kind, in.Tool.Name)
	outSteps := make([]simulateStepDTO, 0, len(steps))
	for i := range steps {
		outSteps = append(outSteps, simulateStepDTO{
			Rule:    steps[i].Rule,
			Shadow:  steps[i].Shadow,
			Outcome: steps[i].Outcome,
		})
	}
	resp := simulateResponse{
		Decision:       dec.Effect.String(),
		Rule:           dec.Rule,
		Reason:         dec.Reason,
		Visible:        vis,
		CatalogMatched: catalogMatched,
		PinStatus:      pinStatus,
		PinBlocked:     pinBlocked,
		Steps:          outSteps,
	}
	if dec.Shadow != nil {
		resp.Shadow = &simulateShadowDTO{
			Rule:   dec.Shadow.Rule,
			Effect: dec.Shadow.Effect.String(),
		}
	}
	if dec.StepUp != nil {
		maxAge := ""
		if dec.StepUp.MaxAge > 0 {
			maxAge = dec.StepUp.MaxAge.String()
		}
		resp.StepUp = &simulateStepUpDTO{
			Scopes:      dec.StepUp.Scopes,
			ACRValues:   dec.StepUp.ACRValues,
			MaxAge:      maxAge,
			RequireDPoP: dec.StepUp.RequireDPoP,
		}
	}
	a.writeAdminJSON(r.Context(), w, http.StatusOK, resp)
}

func (a *App) buildSimInput(req simulateRequest) (in policy.Input, matched bool, pinStatus string, pinBlocked bool) {
	now := time.Now().UTC()
	kind, method := resolveSimKind(req.Kind, req.Method)
	p := identity.Principal{
		Subject:         req.Principal.Sub,
		ClientID:        req.Principal.ClientID,
		Tenant:          req.Principal.Tenant,
		Scopes:          req.Principal.Scopes,
		Roles:           req.Principal.Roles,
		Groups:          req.Principal.Groups,
		ACR:             req.Principal.ACR,
		AMR:             req.Principal.AMR,
		DPoPVerified:    req.Principal.DPoP,
		TokenThumbprint: req.Principal.JKT,
		Claims:          req.Principal.Claims,
	}
	if req.Principal.Actor != "" {
		p.Actor = &identity.Actor{Subject: req.Principal.Actor}
	}
	if req.Principal.AuthAgeSeconds != nil && *req.Principal.AuthAgeSeconds >= 0 {
		p.AuthTime = now.Add(-time.Duration(*req.Principal.AuthAgeSeconds) * time.Second)
	}
	tool := catalog.Tool{Name: req.Name}
	pinStatus = string(pin.ModeOff)
	if kind == "" {
		if t, ok := a.catalog.Snapshot().Lookup(req.Name); ok {
			tool = t
			matched = true
			if a.pins != nil && a.pins.Mode() != pin.ModeOff {
				pinStatus = string(a.pins.Status(t))
				pinBlocked = a.pins.Blocks(t)
			}
		} else if a.pins != nil && a.pins.Mode() != pin.ModeOff {
			pinStatus = string(pin.StatusNew)
			pinBlocked = a.pins.Mode() == pin.ModeEnforce
		}
	}
	if req.Annotations != nil {
		applySimAnnotations(&tool.Annotations, req.Annotations)
	}
	clientName := req.ClientName
	if clientName == "" {
		clientName = "admin-simulator"
	}
	in = policy.Input{
		Kind:       kind,
		Method:     method,
		ClientName: clientName,
		Principal:  p,
		Tool:       tool,
		Args:       req.Args,
		Now:        now,
	}
	return in, matched, pinStatus, pinBlocked
}

func resolveSimKind(kind, method string) (resolved catalog.Kind, resolvedMethod string) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case kindPrompt:
		if method == "" {
			method = "prompts/get"
		}
		return catalog.KindPrompt, method
	case kindResource:
		if method == "" {
			method = "resources/read"
		}
		return catalog.KindResource, method
	case kindTemplate:
		if method == "" {
			method = "resources/read"
		}
		return catalog.KindTemplate, method
	default:
		if method == "" {
			method = "tools/call"
		}
		return "", method
	}
}

func applySimAnnotations(dst *catalog.Annotations, src *simulateAnnotationsReq) {
	if src.ReadOnly != nil {
		dst.ReadOnly = *src.ReadOnly
	}
	if src.Destructive != nil {
		dst.Destructive = *src.Destructive
	}
	if src.Idempotent != nil {
		dst.Idempotent = *src.Idempotent
	}
	if src.OpenWorld != nil {
		dst.OpenWorld = *src.OpenWorld
	}
}

func decodeAdminBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminAPIBody)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode json: %w", err)
	}
	return nil
}
