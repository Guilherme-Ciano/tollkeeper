package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (identity.Principal, error)
}

type anonymousVerifier struct{}

func (anonymousVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return identity.Anonymous(), nil
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != "" && !strings.ContainsAny(tok, " \t")
}

func (g *Gateway) bearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.authDisabled {
			next.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), identity.Anonymous())))
			return
		}
		tok, ok := bearerToken(r)
		if !ok {
			g.metrics.AuthFailures.WithLabelValues("missing").Inc()
			w.Header().Set("WWW-Authenticate", g.challenge.header("", "", nil))
			writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "authorization required", nil)
			return
		}
		p, err := g.verifier.Verify(r.Context(), tok)
		if err != nil {
			if errors.Is(err, authn.ErrKeysUnavailable) {
				g.metrics.AuthFailures.WithLabelValues("keys_unavailable").Inc()
				g.log.ErrorContext(
					r.Context(),
					"token verification keys unavailable",
					slog.String("error", err.Error()),
				)
				w.Header().Set("Retry-After", "5")
				writeRPCError(
					w,
					http.StatusServiceUnavailable,
					nil,
					CodeInternal,
					"authorization temporarily unavailable",
					nil,
				)
				return
			}
			g.metrics.AuthFailures.WithLabelValues("invalid").Inc()
			g.log.InfoContext(r.Context(), "token rejected",
				slog.String("token_fp", authn.Fingerprint(tok)), slog.String("error", err.Error()))
			w.Header().Set("WWW-Authenticate", g.challenge.header("invalid_token", "token validation failed", nil))
			writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "invalid token", nil)
			return
		}
		if missing := missingScopes(p, g.requiredScopes); len(missing) > 0 {
			g.metrics.AuthFailures.WithLabelValues("insufficient_scope").Inc()
			w.Header().Set("WWW-Authenticate", g.challenge.header("insufficient_scope", "", g.requiredScopes))
			writeRPCError(
				w,
				http.StatusForbidden,
				nil,
				CodePolicyDenied,
				"insufficient scope",
				map[string]any{"required_scopes": g.requiredScopes},
			)
			return
		}
		next.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), p)))
	})
}

func missingScopes(p identity.Principal, required []string) []string {
	var out []string
	for _, s := range required {
		if !p.HasScope(s) {
			out = append(out, s)
		}
	}
	return out
}
