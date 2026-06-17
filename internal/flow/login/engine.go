package login

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	authnregistry "github.com/enterprise-idp/idpd/internal/authenticator/registry"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/google/uuid"
)

const flowTTL = 30 * time.Minute

// Engine drives the login self-service flow.
type Engine struct {
	flows      *flow.Store
	policies   *policy.Store
	identities *identity.Store
	authn      *authnregistry.Registry
}

// New constructs a login Engine.
func New(flows *flow.Store, policies *policy.Store, identities *identity.Store, authn *authnregistry.Registry) *Engine {
	return &Engine{
		flows:      flows,
		policies:   policies,
		identities: identities,
		authn:      authn,
	}
}

// SubmitResult is returned by SubmitFlow when credentials are accepted.
type SubmitResult struct {
	Flow       *flow.Flow
	Completed  bool          // true when all AAL requirements are satisfied
	IdentityID uuid.UUID     // set when Completed = true
	AAL        string        // "aal1" or "aal2"
	AMR        []string      // authentication method references
	SessionTTL time.Duration // parsed from tenant session policy; valid only when Completed = true
}

// InitFlow creates a new pending login flow for the tenant. It assembles UI
// nodes from all allowed first-factor authenticators that are currently
// registered, plus a shared identifier input node.
func (e *Engine) InitFlow(ctx context.Context, tenantID uuid.UUID) (*flow.Flow, error) {
	pol, err := e.policies.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("login.InitFlow: %w", err)
	}

	nodes := []authenticator.UINode{
		{
			Type:  "input",
			Group: "default",
			Attributes: authenticator.UINodeAttrs{
				Name:     "identifier",
				Type:     "text",
				Required: true,
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{ID: 1070022, Type: "info", Text: "ID"},
			},
		},
	}

	authnStates := make(map[string]string)

	for _, methodID := range pol.Login.AllowedFirstFactors {
		a, aErr := e.authn.Get(methodID)
		if errors.Is(aErr, authnregistry.ErrNotFound) {
			continue // not yet registered (e.g. oidc, saml)
		}
		if aErr != nil {
			return nil, fmt.Errorf("login.InitFlow get authenticator %q: %w", methodID, aErr)
		}

		state, sErr := a.StartFlow(ctx, &authenticator.StartFlowRequest{
			TenantID: tenantID,
		})
		if sErr != nil {
			return nil, fmt.Errorf("login.InitFlow start %q: %w", methodID, sErr)
		}
		nodes = append(nodes, state.Nodes...)
		if state.State != "" {
			authnStates[methodID] = state.State
		}
	}

	nodes = append(nodes, authenticator.UINode{
		Type:  "input",
		Group: "default",
		Attributes: authenticator.UINodeAttrs{
			Name:  "method",
			Type:  "submit",
			Value: pol.Login.AllowedFirstFactors[0],
		},
		Meta: authenticator.UINodeMeta{
			Label: &authenticator.UIMessage{ID: 1010001, Type: "info", Text: "Sign in"},
		},
	})

	ui := flow.UI{
		Method: "POST",
		Nodes:  nodes,
		Internal: &flow.UIInternal{
			Phase:       "first_factor",
			AuthnStates: authnStates,
		},
	}

	f, err := e.flows.Create(ctx, tenantID, flow.TypeLogin, ui, time.Now().Add(flowTTL))
	if err != nil {
		return nil, fmt.Errorf("login.InitFlow: %w", err)
	}
	return f, nil
}

// GetFlow retrieves a login flow by tenant+id.
func (e *Engine) GetFlow(ctx context.Context, tenantID, flowID uuid.UUID) (*flow.Flow, error) {
	return e.flows.Get(ctx, tenantID, flowID)
}

// SubmitFlow processes a credential submission. method selects the authenticator;
// values contains all submitted form fields (identifier, password, totp_code, …).
func (e *Engine) SubmitFlow(ctx context.Context, tenantID, flowID uuid.UUID, method string, values map[string]string) (*SubmitResult, error) {
	f, err := e.flows.Get(ctx, tenantID, flowID)
	if err != nil {
		return nil, fmt.Errorf("login.SubmitFlow: %w", err)
	}
	if f.State != flow.StatePending {
		return nil, fmt.Errorf("login.SubmitFlow: flow is %s", f.State)
	}

	pol, err := e.policies.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("login.SubmitFlow: %w", err)
	}

	phase := "first_factor"
	if f.UI.Internal != nil && f.UI.Internal.Phase != "" {
		phase = f.UI.Internal.Phase
	}

	switch phase {
	case "first_factor":
		return e.submitFirstFactor(ctx, f, pol, method, values)
	case "second_factor":
		return e.submitSecondFactor(ctx, f, pol, method, values)
	default:
		return nil, fmt.Errorf("login.SubmitFlow: unknown phase %q", phase)
	}
}

func (e *Engine) submitFirstFactor(ctx context.Context, f *flow.Flow, pol *policy.FlowPolicy, method string, values map[string]string) (*SubmitResult, error) {
	if !containsStr(pol.Login.AllowedFirstFactors, method) {
		return nil, fmt.Errorf("login: method %q not allowed as first factor", method)
	}

	a, err := e.authn.Get(method)
	if err != nil {
		return nil, fmt.Errorf("login: get authenticator %q: %w", method, err)
	}

	identifier := values["identifier"]
	if identifier == "" {
		return nil, fmt.Errorf("login: missing identifier")
	}

	cred, err := e.identities.GetByIdentifier(ctx, f.TenantID, method, identifier)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			// Return a generic error so we don't reveal whether the account exists.
			return nil, fmt.Errorf("login: invalid credentials")
		}
		return nil, fmt.Errorf("login: credential lookup: %w", err)
	}

	var authnState string
	if f.UI.Internal != nil {
		authnState = f.UI.Internal.AuthnStates[method]
	}

	result, err := a.CompleteFlow(ctx, &authenticator.CompleteFlowRequest{
		TenantID:         f.TenantID,
		IdentityID:       cred.IdentityID,
		FlowID:           f.ID,
		FlowState:        authnState,
		Values:           values,
		CredentialConfig: cred.Config,
	})
	if err != nil {
		e.appendFlowError(ctx, f, "The provided credentials are invalid. Check for spelling mistakes in your password or username, email address, or phone number.")
		return nil, fmt.Errorf("login: authentication failed: %w", err)
	}

	// First factor accepted — decide whether we need a second factor.
	if pol.Login.MFARequired && len(pol.Login.AllowedSecondFactors) > 0 {
		return e.advanceToSecondFactor(ctx, f, pol, cred.IdentityID, result.AMR)
	}

	// No MFA required: mark flow complete.
	internal := &flow.UIInternal{
		Phase:        "complete",
		CompletedAAL: "aal1",
		CompletedAMR: result.AMR,
	}
	f.UI.Nodes = nil
	f.UI.Messages = nil
	f.UI.Internal = internal

	if err := e.flows.Update(ctx, f.TenantID, f.ID, flow.StateSuccess, &cred.IdentityID, f.UI); err != nil {
		return nil, fmt.Errorf("login: update flow: %w", err)
	}
	f.IdentityID = &cred.IdentityID
	f.State = flow.StateSuccess

	return &SubmitResult{
		Flow:       f,
		Completed:  true,
		IdentityID: cred.IdentityID,
		AAL:        "aal1",
		AMR:        result.AMR,
		SessionTTL: parseSessionTTL(pol),
	}, nil
}

// advanceToSecondFactor transitions a flow from first-factor-complete to
// pending second factor and persists the updated state.
func (e *Engine) advanceToSecondFactor(ctx context.Context, f *flow.Flow, pol *policy.FlowPolicy, identityID uuid.UUID, priorAMR []string) (*SubmitResult, error) {
	nodes := []authenticator.UINode{}
	authnStates := make(map[string]string)

	for _, methodID := range pol.Login.AllowedSecondFactors {
		a, aErr := e.authn.Get(methodID)
		if errors.Is(aErr, authnregistry.ErrNotFound) {
			continue
		}
		if aErr != nil {
			return nil, fmt.Errorf("login: get second-factor authenticator %q: %w", methodID, aErr)
		}
		state, sErr := a.StartFlow(ctx, &authenticator.StartFlowRequest{
			TenantID:   f.TenantID,
			IdentityID: identityID,
			FlowID:     f.ID,
		})
		if sErr != nil {
			return nil, fmt.Errorf("login: start second factor %q: %w", methodID, sErr)
		}
		nodes = append(nodes, state.Nodes...)
		if state.State != "" {
			authnStates[methodID] = state.State
		}
	}

	f.UI.Nodes = nodes
	f.UI.Messages = nil
	f.UI.Internal = &flow.UIInternal{
		Phase:        "second_factor",
		AuthnStates:  authnStates,
		CompletedAAL: "aal1",
		CompletedAMR: priorAMR,
	}

	if err := e.flows.Update(ctx, f.TenantID, f.ID, flow.StatePending, &identityID, f.UI); err != nil {
		return nil, fmt.Errorf("login: update flow to second factor: %w", err)
	}
	f.IdentityID = &identityID

	return &SubmitResult{Flow: f, Completed: false}, nil
}

func (e *Engine) submitSecondFactor(ctx context.Context, f *flow.Flow, pol *policy.FlowPolicy, method string, values map[string]string) (*SubmitResult, error) {
	if !containsStr(pol.Login.AllowedSecondFactors, method) {
		return nil, fmt.Errorf("login: method %q not allowed as second factor", method)
	}

	if f.IdentityID == nil {
		return nil, fmt.Errorf("login: second factor submitted but identity_id is not set on flow")
	}

	a, err := e.authn.Get(method)
	if err != nil {
		return nil, fmt.Errorf("login: get authenticator %q: %w", method, err)
	}

	cred, err := e.identities.GetByIdentityAndType(ctx, f.TenantID, *f.IdentityID, method)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return nil, fmt.Errorf("login: no %s credential enrolled for this identity", method)
		}
		return nil, fmt.Errorf("login: credential lookup: %w", err)
	}

	var authnState string
	if f.UI.Internal != nil {
		authnState = f.UI.Internal.AuthnStates[method]
	}

	result, err := a.CompleteFlow(ctx, &authenticator.CompleteFlowRequest{
		TenantID:         f.TenantID,
		IdentityID:       *f.IdentityID,
		FlowID:           f.ID,
		FlowState:        authnState,
		Values:           values,
		CredentialConfig: cred.Config,
	})
	if err != nil {
		e.appendFlowError(ctx, f, "The provided credentials are invalid.")
		return nil, fmt.Errorf("login: second factor failed: %w", err)
	}

	var priorAMR []string
	if f.UI.Internal != nil {
		priorAMR = f.UI.Internal.CompletedAMR
	}
	amr := make([]string, len(priorAMR)+len(result.AMR))
	copy(amr, priorAMR)
	copy(amr[len(priorAMR):], result.AMR)

	f.UI.Nodes = nil
	f.UI.Messages = nil
	f.UI.Internal = &flow.UIInternal{
		Phase:        "complete",
		CompletedAAL: "aal2",
		CompletedAMR: amr,
	}

	if err := e.flows.Update(ctx, f.TenantID, f.ID, flow.StateSuccess, f.IdentityID, f.UI); err != nil {
		return nil, fmt.Errorf("login: update flow: %w", err)
	}
	f.State = flow.StateSuccess

	return &SubmitResult{
		Flow:       f,
		Completed:  true,
		IdentityID: *f.IdentityID,
		AAL:        "aal2",
		AMR:        amr,
		SessionTTL: parseSessionTTL(pol),
	}, nil
}

func parseSessionTTL(pol *policy.FlowPolicy) time.Duration {
	d, err := time.ParseDuration(pol.Session.TTL)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
}

// appendFlowError persists an error message to the flow's UI and keeps it pending.
// Write errors are silently ignored since the client-facing error is returned separately.
func (e *Engine) appendFlowError(ctx context.Context, f *flow.Flow, text string) {
	f.UI.Messages = []authenticator.UIMessage{
		{ID: 4000006, Type: "error", Text: text},
	}
	_ = e.flows.Update(ctx, f.TenantID, f.ID, flow.StatePending, f.IdentityID, f.UI)
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
