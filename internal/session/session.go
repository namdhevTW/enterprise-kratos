package session

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound = errors.New("session not found")
	ErrExpired  = errors.New("session expired")
	ErrRevoked  = errors.New("session revoked")
)

// Session represents a row in the sessions table.
type Session struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	IdentityID uuid.UUID
	Token      string
	ExpiresAt  time.Time
	AAL        string
	AMR        []string
	Active     bool
}
