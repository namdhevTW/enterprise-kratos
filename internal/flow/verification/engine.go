package verification

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/google/uuid"
)

const flowTTL = 1 * time.Hour

// Engine drives the email-verification self-service flow.
type Engine struct {
	flows      *flow.Store
	identities *identity.Store
}

// New constructs a verification Engine.
func New(flows *flow.Store, identities *identity.Store) *Engine {
	return &Engine{flows: flows, identities: identities}
}

// InitFlow creates a pending verification flow for identityID and returns the
// flow together with the plaintext token. The caller is responsible for
// delivering the token to the user (e.g. via email).
func (e *Engine) InitFlow(ctx context.Context, tenantID, identityID uuid.UUID) (*flow.Flow, string, error) {
	token, err := generateToken()
	if err != nil {
		return nil, "", fmt.Errorf("verification.InitFlow generate token: %w", err)
	}

	ui := flow.UI{
		Method: "POST",
		Internal: &flow.UIInternal{
			Phase:             "verify",
			VerificationToken: token,
		},
	}

	f, err := e.flows.Create(ctx, tenantID, flow.TypeVerification, ui, time.Now().Add(flowTTL))
	if err != nil {
		return nil, "", fmt.Errorf("verification.InitFlow: %w", err)
	}

	if err := e.flows.Update(ctx, tenantID, f.ID, flow.StatePending, &identityID, f.UI); err != nil {
		return nil, "", fmt.Errorf("verification.InitFlow set identity: %w", err)
	}
	f.IdentityID = &identityID

	return f, token, nil
}

// GetFlow retrieves a verification flow by tenant + id.
func (e *Engine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	return e.flows.Get(ctx, tenantID, flowID)
}

// SubmitFlow verifies the submitted token. On success it activates the identity
// and marks the flow as successful.
func (e *Engine) SubmitFlow(ctx context.Context, tenantID, flowID uuid.UUID, token string) error {
	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return fmt.Errorf("verification.SubmitFlow: %w", err)
	}
	if f.State != flow.StatePending {
		return fmt.Errorf("verification.SubmitFlow: flow is %s", f.State)
	}
	if f.Type != flow.TypeVerification {
		return fmt.Errorf("verification.SubmitFlow: wrong flow type %s", f.Type)
	}
	if f.IdentityID == nil {
		return fmt.Errorf("verification.SubmitFlow: flow has no identity_id")
	}

	stored := ""
	if f.UI.Internal != nil {
		stored = f.UI.Internal.VerificationToken
	}
	if stored == "" {
		return fmt.Errorf("verification.SubmitFlow: no token stored in flow")
	}

	// Constant-time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(token), []byte(stored)) != 1 {
		_ = e.flows.UpdateState(ctx, tenantID, flowID, flow.StateFailed)
		return errors.New("verification.SubmitFlow: invalid token")
	}

	// Activate identity.
	if err := e.identities.UpdateIdentityState(ctx, tenantID, *f.IdentityID, identity.StateActive); err != nil {
		return fmt.Errorf("verification.SubmitFlow activate identity: %w", err)
	}

	// Clear token from flow state and mark success.
	f.UI.Internal = &flow.UIInternal{Phase: "complete"}
	if err := e.flows.Update(ctx, tenantID, flowID, flow.StateSuccess, f.IdentityID, f.UI); err != nil {
		return fmt.Errorf("verification.SubmitFlow update flow: %w", err)
	}
	return nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
