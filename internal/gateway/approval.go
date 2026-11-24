package gateway

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Guilherme-Ciano/tollkeeper/internal/approval"
	"github.com/Guilherme-Ciano/tollkeeper/internal/audit"
	"github.com/Guilherme-Ciano/tollkeeper/internal/policy"
)

const defaultApprovalChallengeTTL = 5 * time.Minute

func (g *Gateway) verifyApproval(
	ctx context.Context,
	r *http.Request,
	a *Admission,
) (*approval.Verified, policy.Approval) {
	if g.approvals == nil || a.Kind != "" {
		return nil, policy.Approval{}
	}
	header := g.cfg.Approvals.Header
	if header == "" {
		header = approval.DefaultHeader
	}
	tok := strings.TrimSpace(r.Header.Get(header))
	if tok == "" {
		return nil, policy.Approval{}
	}
	v, err := g.approvals.Verify(approval.VerifyRequest{
		Token:   tok,
		Subject: a.Principal.Subject,
		Tenant:  a.Principal.Tenant,
		Tool:    a.Tool.Name,
		Args:    a.Envelope.Arguments,
	})
	if err != nil {
		label := approvalErrorLabel(err)
		g.metrics.ApprovalVerifications.WithLabelValues(label).Inc()
		g.log.WarnContext(ctx, "approval token rejected",
			slog.String("tool", a.Tool.Name),
			slog.String("reason", label),
			slog.String("error", err.Error()))
		return nil, policy.Approval{}
	}
	g.metrics.ApprovalVerifications.WithLabelValues("ok").Inc()
	return &v, policy.Approval{
		Verified: true,
		ID:       v.ID,
		Approver: v.Approver,
		Reason:   v.Reason,
	}
}

func approvalErrorLabel(err error) string {
	switch {
	case errors.Is(err, approval.ErrExpired), errors.Is(err, approval.ErrTTLTooLong):
		return "expired"
	case errors.Is(err, approval.ErrOperationMismatch),
		errors.Is(err, approval.ErrSubjectMismatch),
		errors.Is(err, approval.ErrTenantMismatch),
		errors.Is(err, approval.ErrAudienceMismatch),
		errors.Is(err, approval.ErrIssuerMismatch):
		return "mismatch"
	default:
		return "invalid"
	}
}

func (g *Gateway) consumeApproval(ctx context.Context, w http.ResponseWriter, a *Admission) bool {
	if a.ApprovalVerified == nil || !g.cfg.Approvals.SingleUse || g.approvalReplay == nil {
		return true
	}
	v := a.ApprovalVerified
	ttl := max(v.ExpiresAt.Sub(g.now())+g.cfg.Approvals.ClockSkew, time.Second)
	key := approval.ReplayKey(v.ID, a.Tool.Name, v.ArgsHash)
	ok, err := g.approvalReplay.Consume(ctx, key, ttl)
	if err != nil {
		g.metrics.ApprovalVerifications.WithLabelValues("error").Inc()
		g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "approval_error").Inc()
		g.log.ErrorContext(ctx, "approval replay store failed", slog.String("error", err.Error()))
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "approval replay store unavailable")
		writeRPCError(
			w,
			http.StatusServiceUnavailable,
			a.Envelope.ID,
			CodeInternal,
			"approval replay store unavailable",
			nil,
		)
		return false
	}
	if !ok {
		g.metrics.ApprovalVerifications.WithLabelValues("replayed").Inc()
		g.metrics.Requests.WithLabelValues(a.Envelope.Method, a.Tool.Name, a.Tool.Upstream, "approval_replayed").Inc()
		g.recordDecision(ctx, a, audit.DecisionRejected, "", "approval token already used")
		writeRPCError(
			w,
			http.StatusConflict,
			a.Envelope.ID,
			CodeApprovalReplayed,
			"approval token already used",
			map[string]any{"approval_id": v.ID},
		)
		return false
	}
	return true
}

func (g *Gateway) writeApprovalChallenge(w http.ResponseWriter, a *Admission, sc *policy.StepUpChallenge) {
	header := g.cfg.Approvals.Header
	if header == "" {
		header = approval.DefaultHeader
	}
	ttl := sc.ApprovalTTL
	if ttl <= 0 {
		ttl = defaultApprovalChallengeTTL
		if g.cfg.Approvals.MaxTTL > 0 && g.cfg.Approvals.MaxTTL < ttl {
			ttl = g.cfg.Approvals.MaxTTL
		}
	}
	data := map[string]any{
		"approval_required": true,
		"tool":              a.Tool.Name,
		"args_hash":         approval.CanonicalArgsHash(a.Envelope.Arguments),
		"subject":           a.Principal.Subject,
		"header":            header,
		"ttl_s":             int64(ttl / time.Second),
	}
	if a.Principal.Tenant != "" {
		data["tenant"] = a.Principal.Tenant
	}
	if sc.ApprovalReason != "" {
		data["reason"] = sc.ApprovalReason
	}
	writeRPCError(w, http.StatusForbidden, a.Envelope.ID, CodeApprovalRequired, "human approval required", data)
}
