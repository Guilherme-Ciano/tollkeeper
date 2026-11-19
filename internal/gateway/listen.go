package gateway

import (
	"context"
	"errors"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const schemaObject = "object"

var errSentinel = errors.New("not a gateway target")

func (g *Gateway) NotifyListChanged(tools, prompts, resources bool) {
	g.notifyMu.Lock()
	defer g.notifyMu.Unlock()
	if tools {
		g.server.AddTool(&mcp.Tool{Name: g.sentinel, InputSchema: map[string]any{"type": schemaObject}},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, errSentinel })
		g.server.RemoveTools(g.sentinel)
	}
	if prompts && g.directory != nil {
		g.server.AddPrompt(&mcp.Prompt{Name: g.sentinel},
			func(context.Context, *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) { return nil, errSentinel })
		g.server.RemovePrompts(g.sentinel)
	}
	if resources && g.directory != nil {
		g.server.AddResource(&mcp.Resource{URI: "tollkeeper://" + g.sentinel, Name: g.sentinel},
			func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
				return nil, errSentinel
			})
		g.server.RemoveResources("tollkeeper://" + g.sentinel)
	}
}
