package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
)

func (u *Upstream) Directory(ctx context.Context) ([]catalog.Entry, error) {
	cs := u.session()
	if cs == nil {
		return nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrUnavailable)
	}
	ctx, cancel := context.WithTimeoutCause(ctx, u.cfg.Timeout, ErrTimeout)
	defer cancel()
	var caps *mcp.ServerCapabilities
	if ir := cs.InitializeResult(); ir != nil {
		caps = ir.Capabilities
	}
	var out []catalog.Entry
	if caps != nil && caps.Prompts != nil {
		prompts, err := collect(cs.Prompts(ctx, nil), u.promptEntry)
		if err != nil {
			return nil, fmt.Errorf("list prompts %s: %w", u.cfg.ID, err)
		}
		out = append(out, prompts...)
	}
	if caps != nil && caps.Resources != nil {
		resources, err := collect(cs.Resources(ctx, nil), resourceEntry)
		if err != nil {
			return nil, fmt.Errorf("list resources %s: %w", u.cfg.ID, err)
		}
		templates, err := collect(cs.ResourceTemplates(ctx, nil), templateEntry)
		if err != nil {
			return nil, fmt.Errorf("list resource templates %s: %w", u.cfg.ID, err)
		}
		out = append(append(out, resources...), templates...)
	}
	return out, nil
}

func collect[T any](seq iter.Seq2[T, error], convert func(T) (catalog.Entry, error)) ([]catalog.Entry, error) {
	var out []catalog.Entry
	for v, err := range seq {
		if err != nil {
			return nil, err
		}
		e, cerr := convert(v)
		if cerr != nil {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (u *Upstream) promptEntry(p *mcp.Prompt) (catalog.Entry, error) {
	name, err := u.naming.Qualify(u.cfg.ID, p.Name)
	if err != nil {
		u.log.Warn("upstream prompt rejected", slog.String("prompt", p.Name), slog.String("error", err.Error()))
		return catalog.Entry{}, err
	}
	cp := *p
	cp.Name = name
	desc, err := json.Marshal(&cp)
	if err != nil {
		return catalog.Entry{}, fmt.Errorf("encode prompt %s: %w", name, err)
	}
	return catalog.Entry{Kind: catalog.KindPrompt, Name: name, Original: p.Name, Descriptor: desc}, nil
}

func resourceEntry(r *mcp.Resource) (catalog.Entry, error) {
	desc, err := json.Marshal(r)
	if err != nil {
		return catalog.Entry{}, fmt.Errorf("encode resource %s: %w", r.URI, err)
	}
	return catalog.Entry{Kind: catalog.KindResource, Name: r.URI, Original: r.URI, Descriptor: desc}, nil
}

func templateEntry(t *mcp.ResourceTemplate) (catalog.Entry, error) {
	desc, err := json.Marshal(t)
	if err != nil {
		return catalog.Entry{}, fmt.Errorf("encode resource template %s: %w", t.URITemplate, err)
	}
	return catalog.Entry{
		Kind: catalog.KindTemplate, Name: t.URITemplate, Original: t.URITemplate, Descriptor: desc,
	}, nil
}

type PromptCall struct {
	Name           string
	Arguments      map[string]string
	Meta           map[string]any
	InputResponses mcp.InputResponseMap
	RequestState   string
}

type ResourceCall struct {
	URI            string
	Meta           map[string]any
	InputResponses mcp.InputResponseMap
	RequestState   string
}

func (u *Upstream) acquire(ctx context.Context) (*mcp.ClientSession, context.Context, func(), error) {
	cs := u.session()
	if cs == nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrUnavailable)
	}
	select {
	case u.sem <- struct{}{}:
	default:
		return nil, nil, nil, fmt.Errorf("%s: %w", u.cfg.ID, ErrSaturated)
	}
	ctx, cancel := context.WithTimeoutCause(ctx, u.cfg.Timeout, ErrTimeout)
	return cs, ctx, func() { cancel(); <-u.sem }, nil
}

func (u *Upstream) wrap(ctx context.Context, op, name string, err error) error {
	if errors.Is(context.Cause(ctx), ErrTimeout) {
		return fmt.Errorf("%s: %w", u.cfg.ID, ErrTimeout)
	}
	return fmt.Errorf("%s %s/%s: %w", op, u.cfg.ID, name, err)
}

func (u *Upstream) GetPrompt(ctx context.Context, c PromptCall) (*mcp.GetPromptResult, error) {
	cs, ctx, release, err := u.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	res, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{
		Meta: c.Meta, Name: c.Name, Arguments: c.Arguments,
		InputResponses: c.InputResponses, RequestState: c.RequestState,
	})
	if err != nil {
		return nil, u.wrap(ctx, "get prompt", c.Name, err)
	}
	return res, nil
}

func (u *Upstream) ReadResource(ctx context.Context, c ResourceCall) (*mcp.ReadResourceResult, error) {
	cs, ctx, release, err := u.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	res, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{
		Meta: c.Meta, URI: c.URI, InputResponses: c.InputResponses, RequestState: c.RequestState,
	})
	if err != nil {
		return nil, u.wrap(ctx, "read resource", c.URI, err)
	}
	return res, nil
}

func (u *Upstream) Complete(ctx context.Context, p *mcp.CompleteParams) (*mcp.CompleteResult, error) {
	cs, ctx, release, err := u.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	res, err := cs.Complete(ctx, p)
	if err != nil {
		return nil, u.wrap(ctx, "complete", "", err)
	}
	return res, nil
}
