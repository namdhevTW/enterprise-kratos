package sso

import (
	"encoding/json"

	"github.com/google/uuid"
)

// Provider represents a row in tenant_sso_providers.
type Provider struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Type     string          // "oidc" | "saml"
	Provider string          // "google" | "azure" | "okta" | "custom"
	Config   json.RawMessage // type-specific JSON; see OIDCConfig / SAMLConfig
	Enabled  bool
}

// OIDCConfig is the config blob for Type="oidc" providers.
// NOTE: ClientSecret should be encrypted at rest in production.
type OIDCConfig struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	IssuerURL    string   `json:"issuer_url"`             // OIDC discovery base: {issuer}/.well-known/openid-configuration
	RedirectURI  string   `json:"redirect_uri"`           // must be registered with the OIDC provider
	Scopes       []string `json:"scopes,omitempty"`       // defaults to [openid email profile]
}

// SAMLConfig is the config blob for Type="saml" providers.
// Full SAML SP flow implementation is tracked as a follow-up task.
type SAMLConfig struct {
	MetadataURL  string `json:"metadata_url"`
	SPID         string `json:"sp_id"`                     // our entity ID
	NameIDFormat string `json:"name_id_format,omitempty"` // e.g. urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
}
