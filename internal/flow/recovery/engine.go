package recovery

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/enterprise-idp/idpd/internal/session"
	"github.com/google/uuid"
)

const (
	flowTTL        = 30 * time.Minute
	recoverySessionTTL = 15 * time.Minute // short-lived; forces password change
)

type flowStorer interface {
	Create(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error)
	Get(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	Update(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error
	UpdateState(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State) error
}
type policyGetter interface {
	Get(ctx context.Context, tenantID uuid.UUID) (*policy.FlowPolicy, error)
}
type identityFinder interface {
	GetIdentityIDByIdentifier(ctx context.Context, tenantID uuid.UUID, identifier string) (uuid.UUID, error)
	UpdateIdentityState(ctx context.Context, tenantID, identityID uuid.UUID, state string) error
}
type sessionCreator interface {
	Create(ctx context.Context, tenantID, identityID uuid.UUID, aal string, amr []string, ttl time.Duration) (*session.Session, error)
}

// Engine drives the account recovery self-service flow.
type Engine struct {
	flows      flowStorer
	policies   policyGetter
	identities identityFinder
	sessions   sessionCreator
}

// New constructs a recovery Engine.
func New(flows flowStorer, policies policyGetter, identities identityFinder, sessions sessionCreator) *Engine {
	return &Engine{flows: flows, policies: policies, identities: identities, sessions: sessions}
}

// InitFlow creates a new pending recovery flow with a single email input node.
func (e *Engine) InitFlow(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error) {
	pol, err := e.policies.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("recovery.InitFlow: %w", err)
	}
	if !pol.Recovery.Enabled {
		return nil, fmt.Errorf("recovery.InitFlow: account recovery is disabled for this tenant")
	}

	nodes := []authenticator.UINode{
		{
			Type:  "input",
			Group: "default",
			Attributes: authenticator.UINodeAttrs{
				Name:     "email",
				Type:     "email",
				Required: true,
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1070007, Type: "info", Text: "Email"},
			},
		},
		{
			Type:  "input",
			Group: "default",
			Attributes: authenticator.UINodeAttrs{
				Name:  "method",
				Type:  "submit",
				Value: "link",
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1060001, Type: "info", Text: "Submit"},
			},
		},
	}

	ui := flow.UI{
		Method:   "POST",
		Nodes:    nodes,
		Internal: &flow.UIInternal{Phase: "request"},
	}

	f, err := e.flows.Create(ctx, tenantID, flow.TypeRecovery, ui, time.Now().Add(flowTTL))
	if err != nil {
		return nil, fmt.Errorf("recovery.InitFlow: %w", err)
	}
	return f, nil
}

// GetFlow retrieves a recovery flow by tenant + id.
func (e *Engine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	return e.flows.Get(ctx, tenantID, flowID)
}

// RequestRecovery processes the email identifier submission. It looks up the
// identity, generates a recovery token, stores it in the flow, and returns
// the plaintext token (deliver via email in production).
func (e *Engine) RequestRecovery(ctx context.Context, tenantID, flowID uuid.UUID, email string) (string, error) {
	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return "", fmt.Errorf("recovery.RequestRecovery: %w", err)
	}
	if f.State != flow.StatePending {
		return "", fmt.Errorf("recovery.RequestRecovery: flow is %s", f.State)
	}
	if f.Type != flow.TypeRecovery {
		return "", fmt.Errorf("recovery.RequestRecovery: wrong flow type %s", f.Type)
	}

	pol, err := e.policies.Get(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("recovery.RequestRecovery: %w", err)
	}
	if !pol.Recovery.Enabled {
		return "", fmt.Errorf("recovery: account recovery is disabled for this tenant")
	}

	// Look up identity by email — fail silently to avoid user enumeration.
	// We still generate a token (or a fake one) so timing is indistinguishable.
	identityID, lookupErr := e.identities.GetIdentityIDByIdentifier(ctx, tenantID, email)

	token, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("recovery.RequestRecovery: generate token: %w", err)
	}

	if lookupErr != nil {
		// Identity not found — advance flow anyway (anti-enumeration).
		// The token is generated but points to no identity.
		f.UI.Nodes = nil
		f.UI.Messages = []authenticator.UIMessage{
			{ID: 1060003, Type: "info", Text: "If an account with that email exists, a recovery link has been sent."},
		}
		f.UI.Internal = &flow.UIInternal{Phase: "pending_link", RecoveryToken: token}
		_ = e.flows.Update(ctx, tenantID, f.ID, flow.StatePending, nil, f.UI)
		return token, nil
	}

	f.UI.Nodes = nil
	f.UI.Messages = []authenticator.UIMessage{
		{ID: 1060003, Type: "info", Text: "If an account with that email exists, a recovery link has been sent."},
	}
	f.UI.Internal = &flow.UIInternal{
		Phase:              "pending_link",
		RecoveryToken:      token,
		RecoveryIdentityID: identityID.String(),
	}
	if err := e.flows.Update(ctx, tenantID, f.ID, flow.StatePending, &identityID, f.UI); err != nil {
		return "", fmt.Errorf("recovery.RequestRecovery: update flow: %w", err)
	}
	return token, nil
}

// UseToken verifies a recovery link token. On success it activates the
// identity (if pending), issues a short-lived recovery session, and marks
// the flow as successful.
func (e *Engine) UseToken(ctx context.Context, tenantID, flowID uuid.UUID, token string) (*session.Session, uuid.UUID, error) {
	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: %w", err)
	}
	if f.State != flow.StatePending {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: flow is %s", f.State)
	}
	if f.Type != flow.TypeRecovery {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: wrong flow type %s", f.Type)
	}
	if f.UI.Internal == nil || f.UI.Internal.Phase != "pending_link" {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: flow is not in pending_link phase")
	}

	stored := f.UI.Internal.RecoveryToken
	if stored == "" {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: no token in flow")
	}

	if subtle.ConstantTimeCompare([]byte(token), []byte(stored)) != 1 {
		_ = e.flows.UpdateState(ctx, tenantID, flowID, flow.StateFailed)
		return nil, uuid.Nil, errors.New("recovery.UseToken: invalid token")
	}

	rawIdentityID := f.UI.Internal.RecoveryIdentityID
	if rawIdentityID == "" {
		// Token was generated but no identity was found (anti-enumeration path).
		_ = e.flows.UpdateState(ctx, tenantID, flowID, flow.StateFailed)
		return nil, uuid.Nil, errors.New("recovery.UseToken: invalid token")
	}

	identityID, err := uuid.Parse(rawIdentityID)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: invalid identity_id in flow: %w", err)
	}

	// Ensure identity is active (activate if it was pending verification).
	if err := e.identities.UpdateIdentityState(ctx, tenantID, identityID, identity.StateActive); err != nil {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: activate identity: %w", err)
	}

	// Issue a short-lived recovery session. AMR="recovery" signals the client
	// to prompt the user to set a new password before proceeding.
	sess, err := e.sessions.Create(ctx, tenantID, identityID, "aal1", []string{"recovery"}, recoverySessionTTL)
	if err != nil {
		return nil, uuid.Nil, fmt.Errorf("recovery.UseToken: create session: %w", err)
	}

	f.UI.Internal = &flow.UIInternal{Phase: "complete"}
	_ = e.flows.Update(ctx, tenantID, flowID, flow.StateSuccess, &identityID, f.UI)

	return sess, identityID, nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
