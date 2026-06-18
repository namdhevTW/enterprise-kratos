package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type recoveryEngine interface {
	InitFlow(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error)
	GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	RequestRecovery(ctx context.Context, tenantID, flowID uuid.UUID, email string) (string, error)
	UseToken(ctx context.Context, tenantID, flowID uuid.UUID, token string) (*session.Session, uuid.UUID, error)
}

// Handler exposes the recovery Engine over HTTP.
type Handler struct {
	engine recoveryEngine
}

// NewHandler creates a Handler backed by engine.
func NewHandler(engine recoveryEngine) *Handler {
	return &Handler{engine: engine}
}

// Mount registers recovery routes. Must be inside a tenant-scoped chi router.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/self-service/recovery/flows", h.initFlow)
	r.Get("/self-service/recovery/flows/{flowId}", h.getFlow)
	r.Post("/self-service/recovery/flows/{flowId}", h.submitFlow)
}

// initFlow handles POST /t/{slug}/self-service/recovery/flows
func (h *Handler) initFlow(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	f, err := h.engine.InitFlow(r.Context(), t.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	f.UI.Action = actionURL(t.Slug, f.ID)
	writeJSON(w, http.StatusOK, toResponse(f))
}

// getFlow handles GET /t/{slug}/self-service/recovery/flows/{flowId}
// If ?token= is present the recovery link is processed immediately.
func (h *Handler) getFlow(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	flowID, err := uuid.Parse(chi.URLParam(r, "flowId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid flow id"))
		return
	}

	token := r.URL.Query().Get("token")
	if token != "" {
		// Recovery link click: verify token, issue session.
		sess, identityID, err := h.engine.UseToken(r.Context(), t.ID, flowID, token)
		if err != nil {
			if errors.Is(err, flow.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, errBody("flow not found"))
				return
			}
			if errors.Is(err, flow.ErrExpired) {
				writeJSON(w, http.StatusGone, errBody("recovery link expired"))
				return
			}
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		// Recovery session issued — client should immediately show the
		// "set new password" settings UI.
		writeJSON(w, http.StatusOK, map[string]any{
			"session_token": sess.Token,
			"session_id":    sess.ID,
			"identity_id":   identityID,
			"expires_at":    sess.ExpiresAt,
			"next":          "set_password",
		})
		return
	}

	f, err := h.engine.GetFlow(r.Context(), t.ID, flowID)
	if err != nil {
		if errors.Is(err, flow.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody("flow not found"))
			return
		}
		if errors.Is(err, flow.ErrExpired) {
			writeJSON(w, http.StatusGone, errBody("flow expired"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}

	f.UI.Action = actionURL(t.Slug, f.ID)
	writeJSON(w, http.StatusOK, toResponse(f))
}

// submitFlow handles POST /t/{slug}/self-service/recovery/flows/{flowId}
// Body: {"email": "user@example.com", "method": "link"}
func (h *Handler) submitFlow(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	flowID, err := uuid.Parse(chi.URLParam(r, "flowId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid flow id"))
		return
	}

	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request body"))
		return
	}

	email := body["email"]
	if email == "" {
		writeJSON(w, http.StatusBadRequest, errBody("email is required"))
		return
	}

	token, err := h.engine.RequestRecovery(r.Context(), t.ID, flowID, email)
	if err != nil {
		if errors.Is(err, flow.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody("flow not found"))
			return
		}
		if errors.Is(err, flow.ErrExpired) {
			writeJSON(w, http.StatusGone, errBody("flow expired"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"state": "pending_link",
		// In production, the token is delivered by email only.
		// Exposed here for testing without email infrastructure.
		"recovery_token": token,
	})
}

// ---- helpers ----------------------------------------------------------------

func actionURL(tenantSlug string, flowID uuid.UUID) string {
	return fmt.Sprintf("/t/%s/self-service/recovery/flows/%s", tenantSlug, flowID)
}

type flowResponse struct {
	ID    string          `json:"id"`
	Type  string          `json:"type"`
	State string          `json:"state"`
	UI    clientUIResponse `json:"ui"`
}

type clientUIResponse struct {
	Action   string                    `json:"action"`
	Method   string                    `json:"method"`
	Nodes    []authenticator.UINode    `json:"nodes"`
	Messages []authenticator.UIMessage `json:"messages,omitempty"`
}

func toResponse(f *flow.Flow) flowResponse {
	nodes := f.UI.Nodes
	if nodes == nil {
		nodes = []authenticator.UINode{}
	}
	return flowResponse{
		ID:    f.ID.String(),
		Type:  string(f.Type),
		State: string(f.State),
		UI: clientUIResponse{
			Action:   f.UI.Action,
			Method:   f.UI.Method,
			Nodes:    nodes,
			Messages: f.UI.Messages,
		},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
