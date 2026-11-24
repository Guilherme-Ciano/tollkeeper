package gateway

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
)

const (
	CodeParseError       = -32700
	CodeInvalidRequest   = -32600
	CodeMethodNotFound   = -32601
	CodeInvalidParams    = -32602
	CodeInternal         = -32603
	CodeRateLimited      = -32000
	CodePolicyDenied     = -32001
	CodeAuditUnavailabe  = -32003
	CodeUpstreamFailed   = -32004
	CodeDuplicateRequest = -32009
	CodeHeaderMismatch   = -32020
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
		rpcResponse{JSONRPC: jsonrpcVersion, ID: id, Error: rpcError{Code: code, Message: msg, Data: data}},
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

func (c challenge) dpopHeader(errCode, desc string, algs []string) string {
	var parts []string
	if errCode != "" {
		parts = append(parts, `error="`+errCode+`"`)
	}
	if desc != "" {
		parts = append(parts, `error_description="`+strings.ReplaceAll(desc, `"`, "'")+`"`)
	}
	if len(algs) > 0 {
		parts = append(parts, `algs="`+strings.Join(algs, " ")+`"`)
	}
	if c.resourceMetadata != "" {
		parts = append(parts, `resource_metadata="`+c.resourceMetadata+`"`)
	}
	if len(parts) == 0 {
		return "DPoP"
	}
	return "DPoP " + strings.Join(parts, ", ")
}

func (c challenge) stepUpAuthHeader(sc *policy.StepUpChallenge) string {
	parts := []string{
		`error="insufficient_user_authentication"`,
		`error_description="stronger authentication required"`,
	}
	if len(sc.ACRValues) > 0 {
		parts = append(parts, `acr_values="`+strings.Join(sc.ACRValues, " ")+`"`)
	}
	if sc.MaxAge > 0 {
		parts = append(parts, "max_age="+strconv.FormatInt(int64(sc.MaxAge/time.Second), 10))
	}
	if c.resourceMetadata != "" {
		parts = append(parts, `resource_metadata="`+c.resourceMetadata+`"`)
	}
	if len(sc.Scopes) > 0 {
		scopes := slices.Clone(c.scopes)
		for _, s := range sc.Scopes {
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
		parts = append(parts, `scope="`+strings.Join(scopes, " ")+`"`)
	}
	return "Bearer " + strings.Join(parts, ", ")
}
