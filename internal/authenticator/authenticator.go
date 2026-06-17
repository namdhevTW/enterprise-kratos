package authenticator

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// Type classifies whether an authenticator satisfies first-factor, second-factor,
// or either requirement.
type Type int

const (
	FirstFactor  Type = iota // e.g. password, oidc, saml
	SecondFactor             // e.g. totp, otp, passkey
	Either                   // can satisfy either factor
)

// UINode is a Kratos-compatible node rendered in the self-service UI.
type UINode struct {
	Type       string      `json:"type"`               // input|button|img|text|anchor
	Group      string      `json:"group"`              // default|password|totp|oidc|passkey|otp
	Attributes UINodeAttrs `json:"attributes"`
	Messages   []UIMessage `json:"messages,omitempty"`
	Meta       UINodeMeta  `json:"meta"`
}

// UINodeAttrs holds the renderable attributes of a UINode.
type UINodeAttrs struct {
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"` // text|password|hidden|submit
	Value    any    `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
}

// UINodeMeta carries the label for a node.
type UINodeMeta struct {
	Label *UIMessage `json:"label,omitempty"`
}

// UIMessage is a localizable message attached to a node or a flow.
type UIMessage struct {
	ID   int64  `json:"id"`
	Type string `json:"type"` // info|error|success
	Text string `json:"text"`
}

// StartFlowRequest is passed to Authenticator.StartFlow to initialise an
// authentication step. IdentityID may be zero for registration flows.
type StartFlowRequest struct {
	TenantID   uuid.UUID
	IdentityID uuid.UUID
	FlowID     uuid.UUID
	Params     map[string]string // optional hints (e.g. preferred channel)
}

// FlowState is returned by StartFlow. Nodes are rendered to the client;
// State is opaque data the authenticator needs back when CompleteFlow is called.
type FlowState struct {
	Nodes []UINode
	State string // opaque; stored in self_service_flows.ui
}

// CompleteFlowRequest carries the client submission for an authentication step.
// CredentialConfig is the stored credential data loaded by the flow engine so
// the authenticator can verify without touching the DB itself.
type CompleteFlowRequest struct {
	TenantID         uuid.UUID
	IdentityID       uuid.UUID
	FlowID           uuid.UUID
	FlowState        string          // value from FlowState.State
	Values           map[string]string
	CredentialConfig json.RawMessage // loaded by flow engine before calling authenticator
}

// AuthResult is returned by CompleteFlow on success.
type AuthResult struct {
	IdentityID       uuid.UUID
	AAL              string            // "aal1" or "aal2"
	AMR              []string          // authentication method references
	CredentialConfig json.RawMessage   // updated credential to persist (nil = no change)
}

// EnrollRequest is passed to Authenticator.Enroll to create a new credential.
type EnrollRequest struct {
	TenantID   uuid.UUID
	IdentityID uuid.UUID
	Values     map[string]string // e.g. {"password": "...", "totp_code": "..."}
}

// EnrollResult carries the credential data to persist after successful enrollment.
type EnrollResult struct {
	CredentialType   string
	Identifiers      []string        // lookup keys (email, phone, subject)
	CredentialConfig json.RawMessage // to store in identity_credentials.config
}

// UnenrollRequest is passed to Authenticator.Unenroll to revoke a credential.
type UnenrollRequest struct {
	TenantID     uuid.UUID
	IdentityID   uuid.UUID
	CredentialID uuid.UUID
}

// Authenticator is the plugin interface that every authentication method must
// implement. Implementations must be safe for concurrent use.
type Authenticator interface {
	// ID returns the stable identifier for this authenticator (e.g. "password",
	// "totp", "passkey"). Must match the type column in identity_credentials.
	ID() string

	// Type reports whether this authenticator satisfies first-factor,
	// second-factor, or either requirement.
	Type() Type

	// StartFlow initialises an authentication step and returns UI nodes + opaque
	// state. Called when a flow first reaches this authenticator.
	StartFlow(ctx context.Context, r *StartFlowRequest) (*FlowState, error)

	// CompleteFlow verifies the client submission and returns an AuthResult on
	// success. The flow engine is responsible for loading CredentialConfig before
	// calling this method.
	CompleteFlow(ctx context.Context, r *CompleteFlowRequest) (*AuthResult, error)

	// Enroll creates a new credential for the identity and returns data to persist.
	Enroll(ctx context.Context, r *EnrollRequest) (*EnrollResult, error)

	// Unenroll signals that a credential should be revoked. The flow engine
	// performs the actual DB deletion; the authenticator may call external
	// services here (e.g. to invalidate device registrations).
	Unenroll(ctx context.Context, r *UnenrollRequest) error
}
