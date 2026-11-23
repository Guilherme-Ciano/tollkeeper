package policy

import (
	"testing"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

func TestDelegationActorRulesAndCEL(t *testing.T) {
	t.Parallel()
	eng, err := New(config.Policy{
		Default: config.EffectDeny,
		Rules: []config.Rule{
			{
				Name:   "allow-trusted-agent-single-hop",
				Tools:  []string{"crm__*"},
				Effect: config.EffectAllow,
				Subjects: config.Subjects{
					Actors: []string{"agent-*"},
				},
				When: `principal.delegated && principal.actor.depth == 1 && principal.tenant == "acme"`,
			},
			{
				Name:   "allow-direct-users",
				Tools:  []string{"crm__*"},
				Effect: config.EffectAllow,
				When:   `!principal.delegated`,
			},
		},
	})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}

	tool := catalog.Tool{Name: "crm__get_account", Upstream: "crm", Original: "get_account"}

	direct := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{Subject: "alice", Tenant: "acme"},
		Tool:      tool,
	})
	if direct.Effect != Allow || direct.Rule != "allow-direct-users" {
		t.Fatalf("direct user decision = %+v", direct)
	}

	delegated := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{
			Subject: "alice",
			Tenant:  "acme",
			Actor:   &identity.Actor{Subject: "agent-support", ClientID: "orchestrator"},
		},
		Tool: tool,
	})
	if delegated.Effect != Allow || delegated.Rule != "allow-trusted-agent-single-hop" {
		t.Fatalf("delegated agent decision = %+v", delegated)
	}

	deepChain := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{
			Subject: "alice",
			Tenant:  "acme",
			Actor: &identity.Actor{
				Subject: "agent-support",
				Actor:   &identity.Actor{Subject: "agent-sub"},
			},
		},
		Tool: tool,
	})
	if deepChain.Effect != Deny {
		t.Fatalf("deep delegation chain should be denied, got %+v", deepChain)
	}

	wrongTenant := eng.Decide(t.Context(), Input{
		Principal: identity.Principal{
			Subject: "alice",
			Tenant:  "globex",
			Actor:   &identity.Actor{Subject: "agent-support"},
		},
		Tool: tool,
	})
	if wrongTenant.Effect != Deny {
		t.Fatalf("wrong tenant delegated call should be denied, got %+v", wrongTenant)
	}
}
