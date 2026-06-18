package migration

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// KratosConfig holds the subset of a Kratos YAML config that the migration
// tool needs to read. Unknown fields are silently ignored.
type KratosConfig struct {
	DSN      string   `yaml:"dsn"`
	Identity Identity `yaml:"identity"`
	SelfService SelfService `yaml:"selfservice"`
	Session KratosSessionConfig `yaml:"session"`
}

type Identity struct {
	DefaultSchemaID string         `yaml:"default_schema_id"`
	Schemas         []SchemaEntry  `yaml:"schemas"`
}

type SchemaEntry struct {
	ID  string `yaml:"id"`
	URL string `yaml:"url"` // file:///..., base64://..., or https://...
}

type SelfService struct {
	Methods Methods `yaml:"methods"`
	Flows   Flows   `yaml:"flows"`
}

type Methods struct {
	Password MethodEnabled `yaml:"password"`
	OIDC     OIDCMethod    `yaml:"oidc"`
	TOTP     MethodEnabled `yaml:"totp"`
	Lookup   MethodEnabled `yaml:"lookup_secret"`
	WebAuthn MethodEnabled `yaml:"webauthn"`
}

type MethodEnabled struct {
	Enabled bool `yaml:"enabled"`
}

type OIDCMethod struct {
	Enabled bool       `yaml:"enabled"`
	Config  OIDCConfig `yaml:"config"`
}

type OIDCConfig struct {
	Providers []OIDCProvider `yaml:"providers"`
}

type OIDCProvider struct {
	ID           string   `yaml:"id"`
	Provider     string   `yaml:"provider"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	IssuerURL    string   `yaml:"issuer_url"`
	Scope        []string `yaml:"scope"`
	// For Microsoft/Azure
	Tenant       string   `yaml:"microsoft_tenant,omitempty"`
	// Mapper URL for claims
	MapperURL    string   `yaml:"mapper_url,omitempty"`
}

type Flows struct {
	Login        LoginFlow        `yaml:"login"`
	Registration RegistrationFlow `yaml:"registration"`
	Recovery     RecoveryFlow     `yaml:"recovery"`
	Verification VerificationFlow `yaml:"verification"`
	Settings     SettingsFlow     `yaml:"settings"`
}

type LoginFlow struct {
	// No fields we need currently
}

type RegistrationFlow struct {
	After *AfterFlow `yaml:"after"`
}

// AfterFlow holds post-registration hooks; we inspect it to detect
// whether email verification is required.
type AfterFlow struct {
	Password *struct {
		Hooks []Hook `yaml:"hooks"`
	} `yaml:"password"`
	OIDC *struct {
		Hooks []Hook `yaml:"hooks"`
	} `yaml:"oidc"`
}

type Hook struct {
	Hook string `yaml:"hook"`
}

type RecoveryFlow struct {
	Enabled bool   `yaml:"enabled"`
	Use     string `yaml:"use"` // "link" | "code"
}

type VerificationFlow struct {
	Enabled bool   `yaml:"enabled"`
	Use     string `yaml:"use"`
}

type SettingsFlow struct {
	// No fields we need currently
}

type KratosSessionConfig struct {
	Lifespan string `yaml:"lifespan"` // e.g. "24h"
}

// ParseConfig reads and parses a Kratos YAML config file.
func ParseConfig(path string) (*KratosConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("migration.ParseConfig read %q: %w", path, err)
	}
	var cfg KratosConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("migration.ParseConfig parse %q: %w", path, err)
	}
	return &cfg, nil
}

// RequireVerification returns true when Kratos is configured to send a
// verification email after registration (via the verification hook).
func (cfg *KratosConfig) RequireVerification() bool {
	after := cfg.SelfService.Flows.Registration.After
	if after == nil {
		return false
	}
	check := func(hooks []Hook) bool {
		for _, h := range hooks {
			if h.Hook == "verification" {
				return true
			}
		}
		return false
	}
	if after.Password != nil && check(after.Password.Hooks) {
		return true
	}
	if after.OIDC != nil && check(after.OIDC.Hooks) {
		return true
	}
	return false
}

// AllowedFirstFactors returns the first-factor methods enabled in the config.
func (cfg *KratosConfig) AllowedFirstFactors() []string {
	var methods []string
	if cfg.SelfService.Methods.Password.Enabled {
		methods = append(methods, "password")
	}
	if cfg.SelfService.Methods.OIDC.Enabled {
		methods = append(methods, "oidc")
	}
	return methods
}
