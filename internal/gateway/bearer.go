package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Guilherme-Ciano/tollkeeper/internal/authn"
	"github.com/Guilherme-Ciano/tollkeeper/internal/config"
	"github.com/Guilherme-Ciano/tollkeeper/internal/identity"
)

const (
	schemeBearer = "Bearer"
	schemeDPoP   = "DPoP"
)

type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (identity.Principal, error)
}

type anonymousVerifier struct{}

func (anonymousVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return identity.Anonymous(), nil
}

func authToken(r *http.Request) (scheme, token string, ok bool) {
	h := r.Header.Get("Authorization")
	rawScheme, tok, found := strings.Cut(h, " ")
	if !found {
		return "", "", false
	}
	switch {
	case strings.EqualFold(rawScheme, schemeBearer):
		scheme = schemeBearer
	case strings.EqualFold(rawScheme, schemeDPoP):
		scheme = schemeDPoP
	default:
		return "", "", false
	}
	tok = strings.TrimSpace(tok)
	if tok == "" || strings.ContainsAny(tok, " \t") {
		return "", "", false
	}
	return scheme, tok, true
}

func (g *Gateway) bearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.authDisabled {
			next.ServeHTTP(w, r.WithContext(identity.WithPrincipal(r.Context(), identity.Anonymous())))
			return
		}
		scheme, tok, ok := authToken(r)
		if !ok {
			g.rejectMissingAuth(w)
			return
		}
		if !g.schemeAllowed(w, scheme) {
			return
		}
		p, ok := g.verifyToken(w, r, scheme, tok)
		if !ok {
			return
		}
		p, ok = g.verifyDPoP(w, r, scheme, tok, p)
		if !ok {
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
		ctx := identity.WithPrincipal(r.Context(), p)
		ctx = identity.WithSubjectToken(ctx, tok)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (g *Gateway) rejectMissingAuth(w http.ResponseWriter) {
	g.metrics.AuthFailures.WithLabelValues("missing").Inc()
	if g.dpop != nil && g.dpopMode == config.DPoPModeRequired {
		w.Header().Set("WWW-Authenticate", g.challenge.dpopHeader("", "", g.dpop.Algorithms()))
	} else {
		w.Header().Set("WWW-Authenticate", g.challenge.header("", "", nil))
	}
	writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "authorization required", nil)
}

func (g *Gateway) schemeAllowed(w http.ResponseWriter, scheme string) bool {
	if scheme == schemeDPoP && (g.dpop == nil || g.dpopMode == "" || g.dpopMode == config.DPoPModeOff) {
		g.metrics.AuthFailures.WithLabelValues("invalid").Inc()
		w.Header().Set("WWW-Authenticate", g.challenge.header("invalid_request", "dpop not enabled", nil))
		writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "invalid authorization scheme", nil)
		return false
	}
	if scheme == schemeBearer && g.dpop != nil && g.dpopMode == config.DPoPModeRequired {
		g.metrics.AuthFailures.WithLabelValues("dpop_required").Inc()
		w.Header().Set(
			"WWW-Authenticate",
			g.challenge.dpopHeader("invalid_token", "dpop-bound access token required", g.dpop.Algorithms()),
		)
		writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "dpop authorization required", nil)
		return false
	}
	return true
}

func (g *Gateway) verifyToken(
	w http.ResponseWriter,
	r *http.Request,
	scheme, tok string,
) (identity.Principal, bool) {
	p, err := g.verifier.Verify(r.Context(), tok)
	if err == nil {
		return p, true
	}
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
		return identity.Principal{}, false
	}
	g.metrics.AuthFailures.WithLabelValues("invalid").Inc()
	g.log.InfoContext(r.Context(), "token rejected",
		slog.String("token_fp", authn.Fingerprint(tok)), slog.String("error", err.Error()))
	if scheme == schemeDPoP && g.dpop != nil {
		w.Header().
			Set("WWW-Authenticate", g.challenge.dpopHeader("invalid_token", "token validation failed", g.dpop.Algorithms()))
	} else {
		w.Header().Set("WWW-Authenticate", g.challenge.header("invalid_token", "token validation failed", nil))
	}
	writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "invalid token", nil)
	return identity.Principal{}, false
}

func (g *Gateway) verifyDPoP(
	w http.ResponseWriter,
	r *http.Request,
	scheme, tok string,
	p identity.Principal,
) (identity.Principal, bool) {
	if g.dpop == nil || g.dpopMode == "" || g.dpopMode == config.DPoPModeOff {
		return p, true
	}
	if scheme == schemeBearer {
		if p.TokenThumbprint != "" {
			g.metrics.AuthFailures.WithLabelValues("dpop_required").Inc()
			w.Header().Set(
				"WWW-Authenticate",
				g.challenge.dpopHeader("invalid_token", "dpop-bound token requires DPoP scheme", g.dpop.Algorithms()),
			)
			writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "dpop proof required", nil)
			return identity.Principal{}, false
		}
		return p, true
	}
	if g.dpopMode == config.DPoPModeRequired && p.TokenThumbprint == "" {
		g.metrics.AuthFailures.WithLabelValues("dpop_invalid").Inc()
		w.Header().Set(
			"WWW-Authenticate",
			g.challenge.dpopHeader("invalid_token", "access token missing cnf.jkt binding", g.dpop.Algorithms()),
		)
		writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "dpop-bound token required", nil)
		return identity.Principal{}, false
	}
	jkt, err := g.dpop.Verify(r, tok, p.TokenThumbprint)
	if err != nil {
		g.rejectDPoP(w, r, tok, err)
		return identity.Principal{}, false
	}
	p.DPoPVerified = true
	if p.TokenThumbprint == "" {
		p.TokenThumbprint = jkt
	}
	return p, true
}

func (g *Gateway) rejectDPoP(w http.ResponseWriter, r *http.Request, tok string, err error) {
	if errors.Is(err, authn.ErrUseDPoPNonce) {
		g.metrics.AuthFailures.WithLabelValues("dpop_nonce").Inc()
		w.Header().Set("DPoP-Nonce", g.dpop.IssueNonce())
		w.Header().Set(
			"WWW-Authenticate",
			g.challenge.dpopHeader("use_dpop_nonce", "dpop nonce required", g.dpop.Algorithms()),
		)
		writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "dpop nonce required", nil)
		return
	}
	g.metrics.AuthFailures.WithLabelValues("dpop_invalid").Inc()
	g.log.InfoContext(r.Context(), "dpop proof rejected",
		slog.String("token_fp", authn.Fingerprint(tok)), slog.String("error", err.Error()))
	w.Header().Set(
		"WWW-Authenticate",
		g.challenge.dpopHeader("invalid_dpop_proof", "dpop proof validation failed", g.dpop.Algorithms()),
	)
	writeRPCError(w, http.StatusUnauthorized, nil, CodeInvalidRequest, "invalid dpop proof", nil)
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
