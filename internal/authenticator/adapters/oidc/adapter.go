package oidcadapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/enterprise-idp/idpd/internal/authenticator"
	"github.com/enterprise-idp/idpd/internal/sso"
	"github.com/google/uuid"
)

const ID = "oidc"

type providerLister interface {
	ListByType(ctx context.Context, tenantID uuid.UUID, typ string) ([]*sso.Provider, error)
}

// Adapter implements authenticator.Authenticator for per-tenant OIDC providers.
// Its StartFlow renders one button node per enabled OIDC provider for the tenant.
// CompleteFlow is intentionally not supported — OIDC completion goes through the
// dedicated callback handler in internal/oidc, not through the standard flow engine.
type Adapter struct {
	providers providerLister
}

// New returns a new OIDC Adapter backed by the given SSO store.
func New(providers providerLister) *Adapter {
	return &Adapter{providers: providers}
}

func (a *Adapter) ID() string               { return ID }
func (a *Adapter) Type() authenticator.Type { return authenticator.FirstFactor }

// StartFlow loads the tenant's enabled OIDC providers and returns one submit
// button node per provider. The node value is the provider UUID so the OIDC
// initiate handler knows which provider the user selected.
func (a *Adapter) StartFlow(ctx context.Context, r *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
	providers, err := a.providers.ListByType(ctx, r.TenantID, "oidc")
	if err != nil {
		return nil, fmt.Errorf("oidc.StartFlow list providers: %w", err)
	}

	nodes := make([]authenticator.UINode, 0, len(providers))
	for _, p := range providers {
		label := p.Provider
		nodes = append(nodes, authenticator.UINode{
			Type:  "input",
			Group: "oidc",
			Attributes: authenticator.UINodeAttrs{
				Name:  "provider_id",
				Type:  "submit",
				Value: p.ID.String(),
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{
					ID:   1070010,
					Type: "info",
					Text: "Sign in with " + label,
				},
			},
		})
	}

	return &authenticator.FlowState{Nodes: nodes}, nil
}

// CompleteFlow is not used for OIDC — the callback handler drives completion.
func (a *Adapter) CompleteFlow(_ context.Context, _ *authenticator.CompleteFlowRequest) (*authenticator.AuthResult, error) {
	return nil, errors.New("oidc: use the OIDC callback endpoint to complete authentication")
}

// Enroll is not supported via this interface; OIDC credentials are created
// implicitly during the first successful callback (JIT provisioning).
func (a *Adapter) Enroll(_ context.Context, _ *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
	return nil, errors.New("oidc: enrollment is handled implicitly via the callback flow")
}

// Unenroll removes the OIDC credential; the flow engine deletes the DB row.
func (a *Adapter) Unenroll(_ context.Context, _ *authenticator.UnenrollRequest) error {
	return nil
}
