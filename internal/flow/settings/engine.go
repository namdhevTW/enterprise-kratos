package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	authnregistry "github.com/enterprise-idp/idpd/internal/authenticator/registry"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/google/uuid"
)

const flowTTL = 15 * time.Minute

type flowStorer interface {
	Create(ctx context.Context, tenantID uuid.UUID, flowType flow.Type, ui flow.UI, expiresAt time.Time) (*flow.Flow, error)
	Get(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error)
	Update(ctx context.Context, tenantID, flowID uuid.UUID, state flow.State, identityID *uuid.UUID, ui flow.UI) error
}
type identityManager interface {
	GetIdentity(ctx context.Context, tenantID, identityID uuid.UUID) (*identity.Identity, error)
	UpdateTraits(ctx context.Context, tenantID, identityID uuid.UUID, traits json.RawMessage) error
	GetByIdentityAndType(ctx context.Context, tenantID, identityID uuid.UUID, credType string) (*identity.Credential, error)
	UpsertCredential(ctx context.Context, tenantID, identityID uuid.UUID, credType string, identifiers []string, config json.RawMessage) error
}
type authnReg interface {
	Get(id string) (authenticator.Authenticator, error)
}

// Engine drives the settings self-service flow for authenticated users.
type Engine struct {
	flows      flowStorer
	identities identityManager
	authn      authnReg
}

// New constructs a settings Engine.
func New(flows flowStorer, identities identityManager, authn authnReg) *Engine {
	return &Engine{flows: flows, identities: identities, authn: authn}
}

// InitFlow creates a new pending settings flow for the authenticated identity.
func (e *Engine) InitFlow(ctx context.Context, tenantID, identityID uuid.UUID) (*flow.Flow, error) {
	ident, err := e.identities.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return nil, fmt.Errorf("settings.InitFlow: %w", err)
	}

	// Build profile nodes from current traits.
	var traits map[string]any
	_ = json.Unmarshal(ident.Traits, &traits)

	emailVal := ""
	if v, ok := traits["email"].(string); ok {
		emailVal = v
	}

	nodes := []authenticator.UINode{
		{
			Type:  "input",
			Group: "profile",
			Attributes: authenticator.UINodeAttrs{
				Name:     "traits.email",
				Type:     "email",
				Value:    emailVal,
				Required: true,
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1070002, Type: "info", Text: "Email"},
			},
		},
		{
			Type:  "input",
			Group: "profile",
			Attributes: authenticator.UINodeAttrs{
				Name:  "method",
				Type:  "submit",
				Value: "profile",
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1070003, Type: "info", Text: "Save"},
			},
		},
		// Password section
		{
			Type:  "input",
			Group: "password",
			Attributes: authenticator.UINodeAttrs{
				Name:     "password",
				Type:     "password",
				Required: true,
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1070001, Type: "info", Text: "New Password"},
			},
		},
		{
			Type:  "input",
			Group: "password",
			Attributes: authenticator.UINodeAttrs{
				Name:  "method",
				Type:  "submit",
				Value: "password",
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1070004, Type: "info", Text: "Save password"},
			},
		},
	}

	ui := flow.UI{
		Method:   "POST",
		Nodes:    nodes,
		Internal: &flow.UIInternal{Phase: "settings"},
	}

	f, err := e.flows.Create(ctx, tenantID, flow.TypeSettings, ui, time.Now().Add(flowTTL))
	if err != nil {
		return nil, fmt.Errorf("settings.InitFlow: %w", err)
	}
	// Associate the authenticated identity with the flow from the start.
	if err := e.flows.Update(ctx, tenantID, f.ID, flow.StatePending, &identityID, f.UI); err != nil {
		return nil, fmt.Errorf("settings.InitFlow: set identity: %w", err)
	}
	f.IdentityID = &identityID
	return f, nil
}

// GetFlow retrieves a settings flow by tenant + id.
func (e *Engine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	return e.flows.Get(ctx, tenantID, flowID)
}

// SubmitFlow applies a settings change. method must be "profile" or "password".
// identityID is the caller's authenticated identity (from session).
func (e *Engine) SubmitFlow(ctx context.Context, tenantID, flowID, identityID uuid.UUID, method string, values map[string]string) error {
	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return fmt.Errorf("settings.SubmitFlow: %w", err)
	}
	if f.State != flow.StatePending {
		return fmt.Errorf("settings.SubmitFlow: flow is %s", f.State)
	}
	if f.Type != flow.TypeSettings {
		return fmt.Errorf("settings.SubmitFlow: wrong flow type %s", f.Type)
	}
	// Prevent one user from submitting another user's settings flow.
	if f.IdentityID == nil || *f.IdentityID != identityID {
		return fmt.Errorf("settings.SubmitFlow: flow does not belong to this identity")
	}

	switch method {
	case "profile":
		return e.submitProfile(ctx, tenantID, flowID, identityID, f, values)
	case "password":
		return e.submitPassword(ctx, tenantID, flowID, identityID, f, values)
	default:
		return fmt.Errorf("settings.SubmitFlow: unknown method %q", method)
	}
}

// submitProfile updates the identity's traits from the submitted form fields.
func (e *Engine) submitProfile(ctx context.Context, tenantID, flowID, identityID uuid.UUID, f *flow.Flow, values map[string]string) error {
	ident, err := e.identities.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return fmt.Errorf("settings.profile: load identity: %w", err)
	}

	// Start from current traits, then apply submitted traits.* fields.
	var traits map[string]any
	if err := json.Unmarshal(ident.Traits, &traits); err != nil {
		traits = map[string]any{}
	}
	for k, v := range values {
		if len(k) > 7 && k[:7] == "traits." {
			traits[k[7:]] = v
		}
	}

	raw, err := json.Marshal(traits)
	if err != nil {
		return fmt.Errorf("settings.profile: marshal traits: %w", err)
	}
	if err := e.identities.UpdateTraits(ctx, tenantID, identityID, json.RawMessage(raw)); err != nil {
		return fmt.Errorf("settings.profile: update traits: %w", err)
	}

	f.UI.Internal = &flow.UIInternal{Phase: "complete"}
	f.UI.Messages = []authenticator.UIMessage{{ID: 1050001, Type: "success", Text: "Your profile has been updated."}}
	_ = e.flows.Update(ctx, tenantID, flowID, flow.StateSuccess, &identityID, f.UI)
	return nil
}

// submitPassword re-enrolls the identity's password credential.
// Does NOT require the current password (session is the trust anchor).
// Password re-verification is recommended in production; omitted here for brevity.
func (e *Engine) submitPassword(ctx context.Context, tenantID, flowID, identityID uuid.UUID, f *flow.Flow, values map[string]string) error {
	a, err := e.authn.Get("password")
	if errors.Is(err, authnregistry.ErrNotFound) {
		return fmt.Errorf("settings.password: password authenticator not registered")
	}
	if err != nil {
		return fmt.Errorf("settings.password: get authenticator: %w", err)
	}

	enrollResult, err := a.Enroll(ctx, &authenticator.EnrollRequest{
		TenantID:   tenantID,
		IdentityID: identityID,
		Values:     values,
	})
	if err != nil {
		return fmt.Errorf("settings.password: enroll: %w", err)
	}

	// Look up the existing password credential to preserve its identifiers,
	// then upsert with the new hash.
	existing, lookupErr := e.identities.GetByIdentityAndType(ctx, tenantID, identityID, "password")
	identifiers := enrollResult.Identifiers

	if lookupErr == nil {
		identifiers = existing.Identifiers
	} else if len(identifiers) == 0 {
		// No existing credential and authenticator provided no identifiers —
		// load email from traits as fallback.
		ident, idErr := e.identities.GetIdentity(ctx, tenantID, identityID)
		if idErr == nil {
			var traits map[string]any
			if json.Unmarshal(ident.Traits, &traits) == nil {
				if email, ok := traits["email"].(string); ok {
					identifiers = []string{email}
				}
			}
		}
	}

	if err := e.identities.UpsertCredential(ctx, tenantID, identityID, "password", identifiers, enrollResult.CredentialConfig); err != nil {
		return fmt.Errorf("settings.password: upsert credential: %w", err)
	}

	f.UI.Internal = &flow.UIInternal{Phase: "complete"}
	f.UI.Messages = []authenticator.UIMessage{{ID: 1050002, Type: "success", Text: "Your password has been updated."}}
	_ = e.flows.Update(ctx, tenantID, flowID, flow.StateSuccess, &identityID, f.UI)
	return nil
}
