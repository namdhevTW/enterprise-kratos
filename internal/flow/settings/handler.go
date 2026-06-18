package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Handler exposes the settings Engine over HTTP.
type Handler struct {
	engine   *Engine
	sessions *session.Store
}

// NewHandler creates a Handler backed by engine.
func NewHandler(engine *Engine, sessions *session.Store) *Handler {
	return &Handler{engine: engine, sessions: sessions}
}

// Mount registers settings routes. Must be inside a tenant-scoped chi router.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/self-service/settings/flows", h.initFlow)
	r.Get("/self-service/settings/flows/{flowId}", h.getFlow)
	r.Post("/self-service/settings/flows/{flowId}", h.submitFlow)
}

// initFlow handles POST /t/{slug}/self-service/settings/flows
// Requires a valid session token.
func (h *Handler) initFlow(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	sess, err := h.requireSession(r, t.ID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody(err.Error()))
		return
	}

	f, err := h.engine.InitFlow(r.Context(), t.ID, sess.IdentityID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	f.UI.Action = actionURL(t.Slug, f.ID)
	writeJSON(w, http.StatusOK, toResponse(f))
}

// getFlow handles GET /t/{slug}/self-service/settings/flows/{flowId}
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

// submitFlow handles POST /t/{slug}/self-service/settings/flows/{flowId}
// Requires a valid session token and the flow must belong to that identity.
func (h *Handler) submitFlow(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	sess, err := h.requireSession(r, t.ID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errBody(err.Error()))
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

	method := body["method"]
	if method == "" {
		writeJSON(w, http.StatusBadRequest, errBody("method is required"))
		return
	}

	if err := h.engine.SubmitFlow(r.Context(), t.ID, flowID, sess.IdentityID, method, body); err != nil {
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

	writeJSON(w, http.StatusOK, map[string]string{"state": "success"})
}

// ---- helpers ----------------------------------------------------------------

func (h *Handler) requireSession(r *http.Request, tenantID uuid.UUID) (*session.Session, error) {
	token := extractToken(r)
	if token == "" {
		return nil, errors.New("authentication required: provide X-Session-Token or Authorization: Bearer")
	}
	sess, err := h.sessions.GetByToken(r.Context(), tenantID, token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired session: %w", err)
	}
	return sess, nil
}

func extractToken(r *http.Request) string {
	if v := r.Header.Get("X-Session-Token"); v != "" {
		return v
	}
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return strings.TrimPrefix(v, "Bearer ")
	}
	return ""
}

func actionURL(tenantSlug string, flowID uuid.UUID) string {
	return fmt.Sprintf("/t/%s/self-service/settings/flows/%s", tenantSlug, flowID)
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
