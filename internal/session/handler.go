package session

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
	"github.com/go-chi/chi/v5"
)

// Handler exposes session endpoints over HTTP.
type Handler struct {
	store *Store
}

// NewHandler creates a Handler backed by store.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// Mount registers session routes. Must be mounted inside a chi router that
// already has the tenant middleware applied.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/sessions/whoami", h.whoami)
	r.Delete("/sessions/whoami", h.logout)
}

// whoami handles GET /t/{slug}/sessions/whoami
func (h *Handler) whoami(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	token := extractToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, errBody("no session token provided"))
		return
	}

	sess, err := h.store.GetByToken(r.Context(), t.ID, token)
	if err != nil {
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrRevoked) {
			writeJSON(w, http.StatusUnauthorized, errBody("invalid or revoked session"))
			return
		}
		if errors.Is(err, ErrExpired) {
			writeJSON(w, http.StatusUnauthorized, errBody("session expired"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          sess.ID,
		"identity_id": sess.IdentityID,
		"tenant_id":   sess.TenantID,
		"aal":         sess.AAL,
		"amr":         sess.AMR,
		"expires_at":  sess.ExpiresAt,
		"active":      sess.Active,
	})
}

// logout handles DELETE /t/{slug}/sessions/whoami — revokes the current session.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	t := internaltenant.TenantFromContext(r.Context())
	if t == nil {
		writeJSON(w, http.StatusUnauthorized, errBody("tenant not resolved"))
		return
	}

	token := extractToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, errBody("no session token provided"))
		return
	}

	if err := h.store.RevokeByToken(r.Context(), t.ID, token); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errBody("session not found"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errBody("internal error"))
		return
	}

	w.WriteHeader(http.StatusNoContent)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string {
	return map[string]string{"error": msg}
}
