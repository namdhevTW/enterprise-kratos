package verification

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/enterprise-idp/idpd/internal/flow"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Handler exposes the verification Engine over HTTP.
type Handler struct {
	engine *Engine
}

// NewHandler creates a Handler backed by engine.
func NewHandler(engine *Engine) *Handler {
	return &Handler{engine: engine}
}

// Mount registers verification routes. Must be mounted inside a tenant-scoped router.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/self-service/verification/flows/{flowId}", h.getFlow)
	r.Post("/self-service/verification/flows/{flowId}", h.submitFlow)
}

// getFlow handles GET /t/{slug}/self-service/verification/flows/{flowId}
// If a ?token= query param is present the flow is verified immediately (email link).
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
		// Email link click: verify inline.
		if err := h.engine.SubmitFlow(r.Context(), t.ID, flowID, token); err != nil {
			if errors.Is(err, flow.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, errBody("flow not found"))
				return
			}
			if errors.Is(err, flow.ErrExpired) {
				writeJSON(w, http.StatusGone, errBody("verification link expired"))
				return
			}
			writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"state": "success"})
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

	writeJSON(w, http.StatusOK, toResponse(f, t.Slug))
}

// submitFlow handles POST /t/{slug}/self-service/verification/flows/{flowId}
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

	token := body["token"]
	if token == "" {
		writeJSON(w, http.StatusBadRequest, errBody("token is required"))
		return
	}

	if err := h.engine.SubmitFlow(r.Context(), t.ID, flowID, token); err != nil {
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

type flowResponse struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	State string `json:"state"`
	UI    struct {
		Action string `json:"action"`
		Method string `json:"method"`
	} `json:"ui"`
}

func toResponse(f *flow.Flow, tenantSlug string) flowResponse {
	resp := flowResponse{
		ID:    f.ID.String(),
		Type:  string(f.Type),
		State: string(f.State),
	}
	resp.UI.Action = fmt.Sprintf("/t/%s/self-service/verification/flows/%s", tenantSlug, f.ID)
	resp.UI.Method = "POST"
	return resp
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
