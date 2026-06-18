package flow

import (
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/google/uuid"
)

// Type identifies which self-service flow this is.
type Type string

const (
	TypeLogin        Type = "login"
	TypeRegistration Type = "registration"
	TypeRecovery     Type = "recovery"
	TypeSettings     Type = "settings"
	TypeVerification Type = "verification"
)

// State tracks the lifecycle of a self-service flow.
type State string

const (
	StatePending State = "pending"
	StateSuccess State = "success"
	StateFailed  State = "failed"
	StateExpired State = "expired"
)

// UI is the Kratos-compatible blob stored in self_service_flows.ui (JSONB).
// Internal is stripped before the struct is sent to clients.
type UI struct {
	Action   string                    `json:"action"`
	Method   string                    `json:"method"`
	Nodes    []authenticator.UINode    `json:"nodes"`
	Messages []authenticator.UIMessage `json:"messages,omitempty"`
	// Internal carries server-side state needed to advance the flow.
	// It is persisted to JSONB but must never be sent verbatim to clients.
	Internal *UIInternal `json:"_internal,omitempty"`
}

// UIInternal is the server-side state stored inside the UI JSONB blob.
type UIInternal struct {
	// Phase is "first_factor", "second_factor", "register", "complete", or "verify".
	Phase string `json:"phase"`
	// AuthnStates maps authenticator ID → opaque state from StartFlow.
	// Used to pass context back to the authenticator on CompleteFlow.
	AuthnStates  map[string]string `json:"authn_states,omitempty"`
	CompletedAAL string            `json:"completed_aal,omitempty"` // "" | "aal1"
	CompletedAMR []string          `json:"completed_amr,omitempty"`
	// VerificationToken is the plaintext single-use token for verification flows.
	// It is never sent to clients — the handler strips UIInternal before responding.
	VerificationToken string `json:"verification_token,omitempty"`
	// OIDC-specific fields — populated during OIDC initiation, cleared after callback.
	OIDCProviderID   string `json:"oidc_provider_id,omitempty"`
	OIDCNonce        string `json:"oidc_nonce,omitempty"`
	OIDCCodeVerifier string `json:"oidc_code_verifier,omitempty"` // PKCE S256 verifier
	// Recovery-specific fields — set after the identifier is submitted.
	RecoveryToken      string `json:"recovery_token,omitempty"`
	RecoveryIdentityID string `json:"recovery_identity_id,omitempty"`
}

// Flow represents a row in self_service_flows.
type Flow struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	Type       Type
	State      State
	IdentityID *uuid.UUID
	UI         UI
	ExpiresAt  time.Time
}
