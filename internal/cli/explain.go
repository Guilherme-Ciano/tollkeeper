package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
)

var (
	ErrExplainTarget = errors.New("give exactly one of --tool, --prompt or --resource")
	ErrExplainArgs   = errors.New("--args is not valid JSON")
)

type explainFlags struct {
	path, sub, clientID, tool, prompt, resource, args, claims string
	scopes                                                    []string
}

func (f *explainFlags) input(naming catalog.Naming) (policy.Input, error) {
	in := policy.Input{Principal: identity.Principal{Subject: f.sub, ClientID: f.clientID, Scopes: f.scopes}}
	targets := 0
	for _, t := range []string{f.tool, f.prompt, f.resource} {
		if t != "" {
			targets++
		}
	}
	if targets != 1 {
		return in, ErrExplainTarget
	}
	name := f.tool
	switch {
	case f.prompt != "":
		in.Kind, in.Method, name = catalog.KindPrompt, "prompts/get", f.prompt
	case f.resource != "":
		in.Kind, in.Method, name = catalog.KindResource, "resources/read", f.resource
	default:
		in.Method = "tools/call"
	}
	in.Tool = catalog.Tool{Name: name, Original: name}
	if in.Kind != catalog.KindResource {
		if up, original, ok := naming.Split(name); ok {
			in.Tool.Upstream, in.Tool.Original = up, original
		}
	}
	if f.args != "" {
		if !json.Valid([]byte(f.args)) {
			return in, ErrExplainArgs
		}
		in.Args = json.RawMessage(f.args)
	}
	if f.claims != "" {
		if err := json.Unmarshal([]byte(f.claims), &in.Principal.Claims); err != nil {
			return in, fmt.Errorf("--claims: %w", err)
		}
	}
	return in, nil
}

func explainCmd() *cobra.Command {
	f := &explainFlags{}
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Show, rule by rule, how the policy decides one call",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(f.path)
			if err != nil {
				return err
			}
			eng, err := policy.New(cfg.Policy)
			if err != nil {
				return err
			}
			in, err := f.input(cfg.Naming())
			if err != nil {
				return err
			}
			steps, d := eng.Explain(cmd.Context(), in)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "RULE\tMODE\tRESULT")
			for _, s := range steps {
				mode := "enforce"
				if s.Shadow {
					mode = "shadow"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Rule, mode, s.Outcome)
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("write: %w", err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "\ndecision: %s via %s (%s)\n", d.Effect, d.Rule, d.Reason)
			if d.Shadow != nil {
				fmt.Fprintf(out, "shadow:   %s would %s\n", d.Shadow.Rule, d.Shadow.Effect)
			}
			fmt.Fprintf(out, "visible:  %t\n", eng.VisibleAs(in.Principal, in.Kind, in.Tool.Name))
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVarP(&f.path, "config", "c", "tollkeeper.yaml", "config file")
	fl.StringVar(&f.sub, "sub", "", "subject")
	fl.StringVar(&f.clientID, "client-id", "", "client id")
	fl.StringSliceVar(&f.scopes, "scope", nil, "granted scope (repeatable)")
	fl.StringVar(&f.claims, "claims", "", "extra token claims as a JSON object")
	fl.StringVar(&f.tool, "tool", "", "gateway tool name, e.g. notes__search")
	fl.StringVar(&f.prompt, "prompt", "", "gateway prompt name")
	fl.StringVar(&f.resource, "resource", "", "resource URI")
	fl.StringVar(&f.args, "args", "", "call arguments as a JSON object")
	return cmd
}
