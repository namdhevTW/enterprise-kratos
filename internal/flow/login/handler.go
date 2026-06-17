package login

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/flow"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Handler exposes the login Engine over HTTP.
type Handler struct {
	engine *Engine
}

// NewHandler creates a Handler backed by engine.
func NewHandler(engine *Engine) *Handler {
	return &Handler{engine: engine}
}

// Mount registers login flow routes onto r.
// All routes must be mounted inside a chi router that already has the tenant
// middleware applied (i.e. under /t/{tenant-slug}).
func (h *Handler) Mount(r chi.Router) {
	r.Post("/self-service/login/flows", h.initFlow)
	r.Get("/self-service/login/flows/{flowId}", h.getFlow)
	r.Post("/self-service/login/flows/{flowId}", h.submitFlow)
}

// initFlow handles POST /t/{tenant-slug}/self-service/login/flows
func (h *Handler) initFlow(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	f, err := h.engine.InitFlow(r.Context(), t.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("failed to create login flow"))
		return
	}

	f.UI.Action = actionURL(t.Slug, f.ID)
	writeJSON(w, http.StatusOK, toResponse(f))
}

// getFlow handles GET /t/{tenant-slug}/self-service/login/flows/{flowId}
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

// submitFlow handles POST /t/{tenant-slug}/self-service/login/flows/{flowId}
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

	method := body["method"]
	if method == "" {
		writeJSON(w, http.StatusBadRequest, errBody("method is required"))
		return
	}

	result, err := h.engine.SubmitFlow(r.Context(), t.ID, flowID, method, body)
	if err != nil {
		if errors.Is(err, flow.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody("flow not found"))
			return
		}
		if errors.Is(err, flow.ErrExpired) {
			writeJSON(w, http.StatusGone, errBody("flow expired"))
			return
		}
		// Credential rejection or validation errors go back as 400.
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}

	result.Flow.UI.Action = actionURL(t.Slug, result.Flow.ID)

	if result.Completed {
		// Session issuance (step 4) will replace this response.
		writeJSON(w, http.StatusOK, map[string]any{
			"flow":        toResponse(result.Flow),
			"identity_id": result.IdentityID,
			"aal":         result.AAL,
			"amr":         result.AMR,
		})
		return
	}

	// Flow advanced (e.g., to second factor) — return the updated UI.
	writeJSON(w, http.StatusOK, toResponse(result.Flow))
}

// ---- helpers ----------------------------------------------------------------

func actionURL(tenantSlug string, flowID uuid.UUID) string {
	return fmt.Sprintf("/t/%s/self-service/login/flows/%s", tenantSlug, flowID)
}

// flowResponse is the client-facing representation of a flow.
// The Internal field of the UI is intentionally omitted.
type flowResponse struct {
	ID    string     `json:"id"`
	Type  string     `json:"type"`
	State string     `json:"state"`
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
