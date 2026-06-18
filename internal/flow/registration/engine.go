package registration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	authnregistry "github.com/enterprise-idp/idpd/internal/authenticator/registry"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/flow/verification"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/enterprise-idp/idpd/internal/schema"
	"github.com/google/uuid"
)

const flowTTL = 30 * time.Minute

// Engine drives the registration self-service flow.
type Engine struct {
	flows      *flow.Store
	policies   *policy.Store
	identities *identity.Store
	schemas    *schema.Store
	authn      *authnregistry.Registry
	verif      *verification.Engine
}

// New constructs a registration Engine.
func New(
	flows *flow.Store,
	policies *policy.Store,
	identities *identity.Store,
	schemas *schema.Store,
	authn *authnregistry.Registry,
	verif *verification.Engine,
) *Engine {
	return &Engine{
		flows:      flows,
		policies:   policies,
		identities: identities,
		schemas:    schemas,
		authn:      authn,
		verif:      verif,
	}
}

// SubmitResult is returned by SubmitFlow on success.
type SubmitResult struct {
	Flow               *flow.Flow
	Completed          bool          // true when identity is active and session can be issued
	NeedsVerification  bool          // true when identity is pending email verification
	IdentityID         uuid.UUID
	SessionTTL         time.Duration // valid only when Completed = true
	VerificationFlowID uuid.UUID     // valid only when NeedsVerification = true
	VerificationToken  string        // plaintext token; in production deliver via email only
}

// InitFlow creates a new pending registration flow and returns it with UI nodes
// for all allowed first-factor methods.
func (e *Engine) InitFlow(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error) {
	pol, err := e.policies.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("registration.InitFlow: %w", err)
	}
	if !pol.Registration.Enabled {
		return nil, fmt.Errorf("registration.InitFlow: registration is disabled for this tenant")
	}

	nodes := []authenticator.UINode{
		{
			Type:  "input",
			Group: "default",
			Attributes: authenticator.UINodeAttrs{
				Name:     "traits.email",
				Type:     "email",
				Required: true,
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1070002, Type: "info", Text: "Email"},
			},
		},
	}

	for _, methodID := range pol.Login.AllowedFirstFactors {
		a, aErr := e.authn.Get(methodID)
		if errors.Is(aErr, authnregistry.ErrNotFound) {
			continue
		}
		if aErr != nil {
			return nil, fmt.Errorf("registration.InitFlow get authenticator %q: %w", methodID, aErr)
		}
		state, sErr := a.StartFlow(ctx, &authenticator.StartFlowRequest{TenantID: tenantID})
		if sErr != nil {
			return nil, fmt.Errorf("registration.InitFlow start %q: %w", methodID, sErr)
		}
		nodes = append(nodes, state.Nodes...)
	}

	firstMethod := ""
	if len(pol.Login.AllowedFirstFactors) > 0 {
		firstMethod = pol.Login.AllowedFirstFactors[0]
	}
	nodes = append(nodes, authenticator.UINode{
		Type:  "input",
		Group: "default",
		Attributes: authenticator.UINodeAttrs{
			Name:  "method",
			Type:  "submit",
			Value: firstMethod,
		},
		Meta: authenticator.UINodeMeta{
			Label: &authenticator.UIMessage{ID: 1040001, Type: "info", Text: "Sign up"},
		},
	})

	ui := flow.UI{
		Method:   "POST",
		Nodes:    nodes,
		Internal: &flow.UIInternal{Phase: "register"},
	}

	f, err := e.flows.Create(ctx, tenantID, flow.TypeRegistration, ui, time.Now().Add(flowTTL))
	if err != nil {
		return nil, fmt.Errorf("registration.InitFlow: %w", err)
	}
	return f, nil
}

// GetFlow retrieves a registration flow by tenant + id.
func (e *Engine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	return e.flows.Get(ctx, tenantID, flowID)
}

// SubmitFlow processes a registration submission. On success it creates the
// identity and credential, and either completes the flow or initiates email
// verification depending on the tenant policy.
func (e *Engine) SubmitFlow(ctx context.Context, tenantID, flowID uuid.UUID, method string, values map[string]string) (*SubmitResult, error) {
	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return nil, fmt.Errorf("registration.SubmitFlow: %w", err)
	}
	if f.State != flow.StatePending {
		return nil, fmt.Errorf("registration.SubmitFlow: flow is %s", f.State)
	}
	if f.Type != flow.TypeRegistration {
		return nil, fmt.Errorf("registration.SubmitFlow: wrong flow type %s", f.Type)
	}

	pol, err := e.policies.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("registration.SubmitFlow: %w", err)
	}
	if !pol.Registration.Enabled {
		return nil, fmt.Errorf("registration: registration is disabled for this tenant")
	}
	if !containsStr(pol.Login.AllowedFirstFactors, method) {
		return nil, fmt.Errorf("registration: method %q is not allowed", method)
	}

	identifier := extractIdentifier(values)
	if identifier == "" {
		return nil, fmt.Errorf("registration: identifier (traits.email) is required")
	}

	// Reject if identifier is already taken for this credential type in this tenant.
	_, dupErr := e.identities.GetByIdentifier(ctx, tenantID, method, identifier)
	if dupErr == nil {
		return nil, fmt.Errorf("registration: an account with this identifier already exists")
	}
	if !errors.Is(dupErr, identity.ErrNotFound) {
		return nil, fmt.Errorf("registration: duplicate check: %w", dupErr)
	}

	a, err := e.authn.Get(method)
	if err != nil {
		return nil, fmt.Errorf("registration: get authenticator %q: %w", method, err)
	}

	enrollResult, err := a.Enroll(ctx, &authenticator.EnrollRequest{
		TenantID: tenantID,
		Values:   values,
	})
	if err != nil {
		return nil, fmt.Errorf("registration: enroll %q: %w", method, err)
	}

	sch, err := e.schemas.EnsureDefault(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("registration: ensure schema: %w", err)
	}

	identityState := identity.StateActive
	if pol.Registration.RequireVerification {
		identityState = identity.StatePendingVerification
	}

	traits := buildTraits(values, identifier)
	ident, err := e.identities.CreateIdentity(ctx, tenantID, sch.ID, traits, identityState)
	if err != nil {
		return nil, fmt.Errorf("registration: create identity: %w", err)
	}

	// Use the authenticator's identifiers if provided; otherwise fall back to the
	// submitted identifier (password creds are keyed by email, not by an inherent ID).
	credIdentifiers := enrollResult.Identifiers
	if len(credIdentifiers) == 0 {
		credIdentifiers = []string{identifier}
	}

	if _, err := e.identities.CreateCredential(ctx, tenantID, ident.ID, enrollResult.CredentialType, credIdentifiers, enrollResult.CredentialConfig); err != nil {
		return nil, fmt.Errorf("registration: create credential: %w", err)
	}

	f.UI.Nodes = nil
	f.UI.Messages = nil
	f.UI.Internal = &flow.UIInternal{Phase: "complete"}
	if err := e.flows.Update(ctx, tenantID, f.ID, flow.StateSuccess, &ident.ID, f.UI); err != nil {
		return nil, fmt.Errorf("registration: update flow: %w", err)
	}
	f.State = flow.StateSuccess
	f.IdentityID = &ident.ID

	if pol.Registration.RequireVerification {
		vf, token, vErr := e.verif.InitFlow(ctx, tenantID, ident.ID)
		if vErr != nil {
			return nil, fmt.Errorf("registration: init verification flow: %w", vErr)
		}
		return &SubmitResult{
			Flow:               f,
			NeedsVerification:  true,
			IdentityID:         ident.ID,
			VerificationFlowID: vf.ID,
			VerificationToken:  token,
		}, nil
	}

	return &SubmitResult{
		Flow:       f,
		Completed:  true,
		IdentityID: ident.ID,
		SessionTTL: parseSessionTTL(pol),
	}, nil
}

// ---- helpers ----------------------------------------------------------------

// extractIdentifier pulls the user's identifier from submitted form values.
// Accepts traits.email (flat form field), identifier (explicit), or traits (JSON blob).
func extractIdentifier(values map[string]string) string {
	if v := values["traits.email"]; v != "" {
		return v
	}
	if v := values["identifier"]; v != "" {
		return v
	}
	if raw := values["traits"]; raw != "" {
		var traits map[string]any
		if json.Unmarshal([]byte(raw), &traits) == nil {
			if email, ok := traits["email"].(string); ok {
				return email
			}
		}
	}
	return ""
}

// buildTraits assembles the traits JSONB from flat form fields.
func buildTraits(values map[string]string, identifier string) json.RawMessage {
	traits := map[string]any{"email": identifier}
	for k, v := range values {
		if len(k) > 7 && k[:7] == "traits." {
			traits[k[7:]] = v
		}
	}
	raw, _ := json.Marshal(traits)
	return raw
}

func parseSessionTTL(pol *policy.FlowPolicy) time.Duration {
	d, err := time.ParseDuration(pol.Session.TTL)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
