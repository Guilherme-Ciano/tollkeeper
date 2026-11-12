package upstream

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Guilherme-Ciano/tollkeeper/internal/catalog"
)

func nameOnly() catalog.Naming {
	return catalog.Naming{Separator: "__"}
}

func fakeSession() *mcp.ClientSession {
	return &mcp.ClientSession{}
}
