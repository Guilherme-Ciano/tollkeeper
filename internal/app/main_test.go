package app

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const stdioEnv = "TOLLKEEPER_TEST_STDIO_SERVER"

type envArgs struct{}

func runStdioServer() error {
	s := mcp.NewServer(&mcp.Implementation{Name: "stdio-test", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "env", Description: "list environment variable names"},
		func(context.Context, *mcp.CallToolRequest, envArgs) (*mcp.CallToolResult, any, error) {
			names := make([]string, 0, len(os.Environ()))
			for _, kv := range os.Environ() {
				name, _, _ := strings.Cut(kv, "=")
				names = append(names, name)
			}
			slices.Sort(names)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(names, ",")}},
			}, nil, nil
		})
	return s.Run(context.Background(), &mcp.StdioTransport{})
}

func TestMain(m *testing.M) {
	if os.Getenv(stdioEnv) == "1" {
		code := 0
		if err := runStdioServer(); err != nil {
			code = 1
		}
		os.Exit(code)
	}
	os.Exit(m.Run())
}
