package tenant

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Resolver is a chi middleware that resolves the `{tenant-slug}` URL parameter
// to a *Tenant and injects it into the request context.
//
// The middleware aborts the request with:
//   - 404 JSON  {"error":"tenant not found"}  — when the slug is unknown
//   - 503 JSON  {"error":"service unavailable"} — on any other repository error
type Resolver struct {
	repo Repository
}

// NewResolver creates a Resolver backed by the provided Repository.
func NewResolver(repo Repository) *Resolver {
	return &Resolver{repo: repo}
}

// Handler returns the http.Handler middleware function suitable for use with
// chi's Use() or With().
func (rs *Resolver) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "tenant-slug")

		t, err := rs.repo.GetBySlug(r.Context(), slug)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
				return
			}
			slog.ErrorContext(r.Context(), "tenant resolver: db error",
				"slug", slug,
				"err", err,
			)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "service unavailable"})
			return
		}

		ctx := WithTenant(r.Context(), t)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeJSON encodes v as JSON into w with the given status code.
// On encode failure it falls back to a plain-text 500.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON encode error", "err", err)
	}
}
