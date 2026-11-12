package gateway

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

const (
	CodeParseError      = -32700
	CodeInvalidRequest  = -32600
	CodeMethodNotFound  = -32601
	CodeInvalidParams   = -32602
	CodeInternal        = -32603
	CodeRateLimited     = -32000
	CodePolicyDenied    = -32001
	CodeAuditUnavailabe = -32003
	CodeUpstreamFailed  = -32004
	CodeHeaderMismatch  = -32020
)

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcError        `json:"error"`
}

func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string, data any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(
		rpcResponse{JSONRPC: "2.0", ID: id, Error: rpcError{Code: code, Message: msg, Data: data}},
	)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		slog.Debug("json-rpc error response not delivered", slog.String("error", err.Error()))
	}
}

type challenge struct {
	resourceMetadata string
	scopes           []string
}

func (c challenge) header(errCode, desc string, extraScopes []string) string {
	var parts []string
	if errCode != "" {
		parts = append(parts, `error="`+errCode+`"`)
	}
	if desc != "" {
		parts = append(parts, `error_description="`+strings.ReplaceAll(desc, `"`, "'")+`"`)
	}
	if c.resourceMetadata != "" {
		parts = append(parts, `resource_metadata="`+c.resourceMetadata+`"`)
	}
	scopes := slices.Clone(c.scopes)
	for _, s := range extraScopes {
		if !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) > 0 {
		parts = append(parts, `scope="`+strings.Join(scopes, " ")+`"`)
	}
	if len(parts) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(parts, ", ")
}
