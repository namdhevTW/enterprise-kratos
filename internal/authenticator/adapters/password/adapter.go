package password

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/enterprise-idp/idpd/internal/authenticator"
)

const (
	// ID is the stable credential type identifier for this authenticator.
	ID = "password"

	bcryptCost = 12
)

// credentialConfig is the JSON structure stored in identity_credentials.config.
type credentialConfig struct {
	HashedPassword string `json:"hashed_password"`
}

// Adapter implements authenticator.Authenticator for bcrypt passwords.
// It is stateless; all credential data is passed in via request fields.
type Adapter struct{}

// New returns a new password Adapter.
func New() *Adapter { return &Adapter{} }

func (a *Adapter) ID() string               { return ID }
func (a *Adapter) Type() authenticator.Type { return authenticator.FirstFactor }

// StartFlow returns a single password input node. No external calls needed.
func (a *Adapter) StartFlow(_ context.Context, _ *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
	nodes := []authenticator.UINode{
		{
			Type:  "input",
			Group: "password",
			Attributes: authenticator.UINodeAttrs{
				Name:     "password",
				Type:     "password",
				Required: true,
			},
			Meta: authenticator.UINodeMeta{
				Label: &authenticator.UIMessage{
					ID:   1070001,
					Type: "info",
					Text: "Password",
				},
			},
		},
	}
	return &authenticator.FlowState{Nodes: nodes}, nil
}

// CompleteFlow verifies the submitted password against the stored bcrypt hash.
// r.CredentialConfig must contain the JSON-encoded credentialConfig.
func (a *Adapter) CompleteFlow(_ context.Context, r *authenticator.CompleteFlowRequest) (*authenticator.AuthResult, error) {
	submitted := r.Values["password"]
	if submitted == "" {
		return nil, errors.New("password: missing password value")
	}

	var cfg credentialConfig
	if err := json.Unmarshal(r.CredentialConfig, &cfg); err != nil {
		return nil, fmt.Errorf("password: decode credential config: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cfg.HashedPassword), []byte(submitted)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return nil, errors.New("password: invalid credentials")
		}
		return nil, fmt.Errorf("password: compare hash: %w", err)
	}

	return &authenticator.AuthResult{
		IdentityID: r.IdentityID,
		AAL:        "aal1",
		AMR:        []string{"pwd"},
	}, nil
}

// Enroll hashes the submitted plaintext password and returns the credential
// config to persist.
func (a *Adapter) Enroll(_ context.Context, r *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
	plain := r.Values["password"]
	if plain == "" {
		return nil, errors.New("password: missing password value for enrollment")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("password: hash password: %w", err)
	}

	cfg := credentialConfig{HashedPassword: string(hash)}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("password: marshal credential config: %w", err)
	}

	return &authenticator.EnrollResult{
		CredentialType:   ID,
		Identifiers:      nil, // password credentials are looked up by identity_id, not identifier
		CredentialConfig: raw,
	}, nil
}

// Unenroll is a no-op for passwords; the flow engine deletes the DB row.
func (a *Adapter) Unenroll(_ context.Context, _ *authenticator.UnenrollRequest) error {
	return nil
}
