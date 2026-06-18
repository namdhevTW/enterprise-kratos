package oidc

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/enterprise-idp/idpd/internal/flow"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Handler exposes the OIDC initiate and callback endpoints over HTTP.
type Handler struct {
	engine *Engine
}

// NewHandler creates a Handler backed by engine.
func NewHandler(engine *Engine) *Handler {
	return &Handler{engine: engine}
}

// Mount registers OIDC routes. Must be inside a tenant-scoped chi router.
func (h *Handler) Mount(r chi.Router) {
	// Initiate OIDC for an existing login flow.
	r.Post("/self-service/login/flows/{flowId}/methods/oidc", h.initiate)
	// Authorization code callback from the OIDC provider.
	r.Get("/self-service/login/flows/oidc/callback", h.callback)
}

// initiate handles POST /t/{slug}/self-service/login/flows/{flowId}/methods/oidc
// Body: {"provider_id": "<uuid>"}
// Response: {"redirect_to": "https://accounts.google.com/o/oauth2/auth?..."}
func (h *Handler) initiate(w http.ResponseWriter, r *http.Request) {
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

	var body struct {
		ProviderID string `json:"provider_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request body"))
		return
	}

	providerID, err := uuid.Parse(body.ProviderID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid provider_id"))
		return
	}

	redirectTo, err := h.engine.InitiateLogin(r.Context(), t.ID, flowID, providerID)
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

	writeJSON(w, http.StatusOK, map[string]string{"redirect_to": redirectTo})
}

// callback handles GET /t/{slug}/self-service/login/flows/oidc/callback
// Query params: state (= flowID), code
// The redirect_uri registered with the OIDC provider must point to this endpoint.
func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	// OIDC providers may return an error in the callback.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             errParam,
			"error_description": desc,
		})
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		writeJSON(w, http.StatusBadRequest, errBody("state and code are required"))
		return
	}

	result, err := h.engine.HandleCallback(r.Context(), t.ID, state, code)
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
		"session_token": result.Session.Token,
		"session_id":    result.Session.ID,
		"identity_id":   result.IdentityID,
		"aal":           result.Session.AAL,
		"is_new":        result.IsNew,
		"expires_at":    result.Session.ExpiresAt,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
