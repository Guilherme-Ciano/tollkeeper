package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

func TestTenantPolicyIsolationAndExplain(t *testing.T) {
	t.Parallel()
	eng, err := New(config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:   "global-allow-notes",
				Tools:  []string{"notes__*"},
				Effect: config.EffectAllow,
			},
		},
		Tenants: map[string]config.TenantPolicy{
			"acme": {
				Default: config.EffectDeny,
				Rules: []config.Rule{
					{
						Name:   "acme-crm-only",
						Tools:  []string{"crm__*"},
						Effect: config.EffectAllow,
						Subjects: config.Subjects{
							RolesAny: []string{"crm-agent"},
						},
					},
				},
			},
			"globex": {
				Default: config.EffectDeny,
				Rules: []config.Rule{
					{
						Name:   "globex-billing",
						Tools:  []string{"billing__*"},
						Effect: config.EffectAllow,
						Subjects: config.Subjects{
							GroupsAny: []string{"finance"},
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	notesTool := catalog.Tool{Name: "notes__list", Upstream: "notes", Original: "list"}
	crmTool := catalog.Tool{Name: "crm__get", Upstream: "crm", Original: "get"}
	billingTool := catalog.Tool{Name: "billing__charge", Upstream: "billing", Original: "charge"}

	acmeUser := identity.Principal{Subject: "alice", Tenant: "acme", Roles: []string{"crm-agent"}}
	globexUser := identity.Principal{Subject: "bob", Tenant: "globex", Groups: []string{"finance"}}
	otherTenant := identity.Principal{Subject: "carol", Tenant: "initech"}

	if d := eng.Decide(t.Context(), Input{Principal: acmeUser, Tool: crmTool}); d.Effect != Allow ||
		d.Rule != "acme-crm-only" {
		t.Fatalf("acme crm decision = %+v", d)
	}
	if d := eng.Decide(t.Context(), Input{Principal: acmeUser, Tool: notesTool}); d.Effect != Deny {
		t.Fatalf("global rule leaked into acme tenant: %+v", d)
	}
	if eng.Visible(acmeUser, notesTool) || !eng.Visible(acmeUser, crmTool) || eng.Visible(acmeUser, billingTool) {
		t.Fatal("acme visibility violated tenant isolation")
	}

	if d := eng.Decide(t.Context(), Input{Principal: globexUser, Tool: billingTool}); d.Effect != Allow {
		t.Fatalf("globex billing decision = %+v", d)
	}
	if d := eng.Decide(t.Context(), Input{Principal: globexUser, Tool: crmTool}); d.Effect != Deny {
		t.Fatalf("acme rule leaked into globex: %+v", d)
	}

	if d := eng.Decide(t.Context(), Input{Principal: otherTenant, Tool: notesTool}); d.Effect != Allow ||
		d.Rule != "global-allow-notes" {
		t.Fatalf("unconfigured tenant should fall back to global policy, got %+v", d)
	}

	steps, dec := eng.Explain(t.Context(), Input{Principal: acmeUser, Tool: crmTool})
	if dec.Effect != Allow || len(steps) != 1 || steps[0].Rule != "acme-crm-only" {
		t.Fatalf("explain did not scope to acme tenant: steps=%+v dec=%+v", steps, dec)
	}
}

func TestRFC9470StepUpACRMaxAgeAndDPoP(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)
	eng, err := New(config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:   "wire-transfer-strong-auth",
				Tools:  []string{"payments__wire"},
				Effect: config.EffectAllow,
				OnDeny: config.OnDeny{
					StepUpScopes: []string{"payments:approve"},
					ACRValues:    []string{"phr", "urn:mace:incommon:iap:silver"},
					MaxAge:       5 * time.Minute,
				},
			},
			{
				Name:   "secrets-require-dpop",
				Tools:  []string{"vault__read"},
				Effect: config.EffectAllow,
				OnDeny: config.OnDeny{
					RequireDPoP: true,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	wire := catalog.Tool{Name: "payments__wire", Upstream: "payments", Original: "wire"}
	secret := catalog.Tool{Name: "vault__read", Upstream: "vault", Original: "read"}

	stale := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{
			Subject:  "alice",
			Scopes:   []string{"payments:approve"},
			ACR:      "phr",
			AuthTime: now.Add(-10 * time.Minute),
		},
		Tool: wire,
		Now:  now,
	})
	if stale.Effect != StepUp || stale.StepUp == nil || stale.StepUp.MaxAge != 5*time.Minute {
		t.Fatalf("stale auth should require max_age step-up, got %+v", stale)
	}

	weakACR := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{
			Subject:  "alice",
			Scopes:   []string{"payments:approve"},
			ACR:      "pwd",
			AuthTime: now.Add(-1 * time.Minute),
		},
		Tool: wire,
		Now:  now,
	})
	if weakACR.Effect != StepUp || weakACR.StepUp == nil || len(weakACR.StepUp.ACRValues) != 2 {
		t.Fatalf("weak acr should require acr_values step-up, got %+v", weakACR)
	}

	strong := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{
			Subject:  "alice",
			Scopes:   []string{"payments:approve"},
			ACR:      "phr",
			AuthTime: now.Add(-1 * time.Minute),
		},
		Tool: wire,
		Now:  now,
	})
	if strong.Effect != Allow {
		t.Fatalf("strong fresh auth should be allowed, got %+v", strong)
	}

	noDPoP := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{Subject: "alice", DPoPVerified: false},
		Tool:      secret,
		Now:       now,
	})
	if noDPoP.Effect != StepUp || noDPoP.StepUp == nil || !noDPoP.StepUp.RequireDPoP {
		t.Fatalf("missing dpop should require dpop step-up, got %+v", noDPoP)
	}

	withDPoP := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{Subject: "alice", DPoPVerified: true},
		Tool:      secret,
		Now:       now,
	})
	if withDPoP.Effect != Allow {
		t.Fatalf("dpop verified call should be allowed, got %+v", withDPoP)
	}

	fixturesYAML := `
cases:
  - name: fresh_phr_allowed
    principal:
      sub: alice
      scopes: ["payments:approve"]
      acr: phr
      auth_time: "2026-11-23T14:58:00Z"
    tool: payments__wire
    now: "2026-11-23T15:00:00Z"
    expect: allow
  - name: stale_phr_step_up
    principal:
      sub: alice
      scopes: ["payments:approve"]
      acr: phr
      auth_time: "2026-11-23T14:40:00Z"
    tool: payments__wire
    now: "2026-11-23T15:00:00Z"
    expect: step_up
`
	ff, err := ParseFixtures(strings.NewReader(fixturesYAML))
	if err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	res, err := eng.RunFixtures(t.Context(), ff, catalog.Naming{Separator: "__"})
	if err != nil {
		t.Fatalf("run fixtures: %v", err)
	}
	for _, r := range res {
		if !r.Pass {
			t.Fatalf("fixture %s failed: %s", r.Name, r.Detail)
		}
	}
}
