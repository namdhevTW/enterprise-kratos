package sso

import (
	"encoding/json"
	"errors"
	"net/http"

	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Handler exposes admin CRUD endpoints for SSO providers.
// NOTE: In production these routes must be protected by an admin auth layer.
type Handler struct {
	store *Store
}

// NewHandler creates a Handler backed by store.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// Mount registers SSO admin routes. Must be inside a tenant-scoped chi router.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/admin/sso/providers", h.create)
	r.Get("/admin/sso/providers", h.list)
	r.Get("/admin/sso/providers/{providerId}", h.get)
	r.Delete("/admin/sso/providers/{providerId}", h.delete)
	r.Patch("/admin/sso/providers/{providerId}/enabled", h.setEnabled)
}

type createRequest struct {
	Type     string          `json:"type"`     // "oidc" | "saml"
	Provider string          `json:"provider"` // "google" | "azure" | "okta" | "custom"
	Config   json.RawMessage `json:"config"`
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request body"))
		return
	}
	if req.Type != "oidc" && req.Type != "saml" {
		writeJSON(w, http.StatusBadRequest, errBody("type must be oidc or saml"))
		return
	}
	if req.Provider == "" {
		writeJSON(w, http.StatusBadRequest, errBody("provider is required"))
		return
	}
	if len(req.Config) == 0 {
		writeJSON(w, http.StatusBadRequest, errBody("config is required"))
		return
	}

	p, err := h.store.Create(r.Context(), t.ID, req.Type, req.Provider, req.Config)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("failed to create SSO provider"))
		return
	}
	writeJSON(w, http.StatusCreated, toResponse(p))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	providers, err := h.store.List(r.Context(), t.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	resp := make([]providerResponse, 0, len(providers))
	for _, p := range providers {
		resp = append(resp, toResponse(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": resp})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	providerID, err := uuid.Parse(chi.URLParam(r, "providerId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid provider id"))
		return
	}

	p, err := h.store.Get(r.Context(), t.ID, providerID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody("provider not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	writeJSON(w, http.StatusOK, toResponse(p))
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	providerID, err := uuid.Parse(chi.URLParam(r, "providerId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid provider id"))
		return
	}

	if err := h.store.Delete(r.Context(), t.ID, providerID); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody("provider not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) setEnabled(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	providerID, err := uuid.Parse(chi.URLParam(r, "providerId"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid provider id"))
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request body"))
		return
	}

	if err := h.store.SetEnabled(r.Context(), t.ID, providerID, body.Enabled); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody("provider not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers ----------------------------------------------------------------

type providerResponse struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Provider string `json:"provider"`
	Enabled  bool   `json:"enabled"`
	// Config is intentionally omitted from list/get responses to avoid
	// leaking client secrets. Use a dedicated secrets management API in production.
}

func toResponse(p *Provider) providerResponse {
	return providerResponse{
		ID:       p.ID.String(),
		Type:     p.Type,
		Provider: p.Provider,
		Enabled:  p.Enabled,
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
