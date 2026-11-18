package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestListenersHearListChanges(t *testing.T) {
	t.Parallel()
	f := newDirFixture(t)
	tools, prompts := make(chan struct{}, 8), make(chan struct{}, 8)
	client := mcp.NewClient(&mcp.Implementation{Name: "listener", Version: "1"}, &mcp.ClientOptions{
		ToolListChangedHandler:   func(context.Context, *mcp.ToolListChangedRequest) { tools <- struct{}{} },
		PromptListChangedHandler: func(context.Context, *mcp.PromptListChangedRequest) { prompts <- struct{}{} },
	})
	cs, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{Endpoint: f.srv.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	caps := cs.InitializeResult().Capabilities
	if caps.Tools == nil || !caps.Tools.ListChanged || caps.Prompts == nil || !caps.Prompts.ListChanged {
		t.Fatalf("listChanged not advertised: %+v", caps)
	}
	wait := func(ch chan struct{}, what string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s list_changed", what)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.gw.NotifyListChanged(false, true, false)
		select {
		case <-prompts:
		case <-time.After(200 * time.Millisecond):
			if time.Now().Before(deadline) {
				continue
			}
			t.Fatal("no prompts list_changed")
		}
		break
	}
	f.gw.NotifyListChanged(true, false, false)
	wait(tools, "tools")
	res, err := cs.ListPrompts(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range res.Prompts {
		if p.Name == f.gw.sentinel {
			t.Fatal("sentinel prompt leaked into prompts/list")
		}
	}
}
