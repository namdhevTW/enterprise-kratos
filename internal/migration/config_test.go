package migration

import (
	"os"
	"testing"
)

// writeTempYAML writes content to a temp file and returns its path.
// The caller is responsible for calling os.Remove on the returned path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "kratos-config-*.yaml")
	if err != nil {
		t.Fatalf("writeTempYAML: create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatalf("writeTempYAML: write: %v", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		t.Fatalf("writeTempYAML: close: %v", err)
	}
	return f.Name()
}

// ---------------------------------------------------------------------------
// ParseConfig — structural tests
// ---------------------------------------------------------------------------

func TestParseConfig_MinimalYAML(t *testing.T) {
	yaml := `
dsn: postgres://localhost/kratos
identity:
  default_schema_id: person
  schemas:
    - id: person
      url: file:///schema.json
selfservice:
  methods:
    password:
      enabled: true
    oidc:
      enabled: false
  flows:
    recovery:
      enabled: true
      use: link
    verification:
      enabled: true
    registration:
      after:
        password:
          hooks:
            - hook: session
            - hook: verification
session:
  lifespan: 48h
`
	path := writeTempYAML(t, yaml)
	defer os.Remove(path)

	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("ParseConfig: returned nil config")
	}
}

func TestParseConfig_FileNotFound(t *testing.T) {
	_, err := ParseConfig("/nonexistent/path/does-not-exist.yaml")
	if err == nil {
		t.Fatal("ParseConfig: expected error for missing file, got nil")
	}
}

func TestParseConfig_InvalidYAML(t *testing.T) {
	path := writeTempYAML(t, ":\tinvalid: yaml: {{{")
	defer os.Remove(path)

	_, err := ParseConfig(path)
	if err == nil {
		t.Fatal("ParseConfig: expected error for invalid YAML, got nil")
	}
}

func TestParseConfig_AllFieldsPopulated(t *testing.T) {
	yaml := `
dsn: postgres://localhost/kratos
identity:
  default_schema_id: person
  schemas:
    - id: person
      url: file:///schema.json
    - id: admin
      url: https://example.com/admin-schema.json
selfservice:
  methods:
    password:
      enabled: true
    oidc:
      enabled: true
      config:
        providers:
          - id: google
            provider: google
            client_id: abc123
            client_secret: secret
            issuer_url: https://accounts.google.com
            scope:
              - email
              - profile
            mapper_url: file:///mapper.jsonnet
  flows:
    recovery:
      enabled: true
      use: link
    verification:
      enabled: true
      use: code
    registration:
      after:
        password:
          hooks:
            - hook: session
            - hook: verification
        oidc:
          hooks:
            - hook: verification
session:
  lifespan: 24h
`
	path := writeTempYAML(t, yaml)
	defer os.Remove(path)

	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: unexpected error: %v", err)
	}

	// DSN
	if cfg.DSN != "postgres://localhost/kratos" {
		t.Errorf("DSN: got %q, want %q", cfg.DSN, "postgres://localhost/kratos")
	}

	// Identity
	if cfg.Identity.DefaultSchemaID != "person" {
		t.Errorf("Identity.DefaultSchemaID: got %q, want %q", cfg.Identity.DefaultSchemaID, "person")
	}
	if len(cfg.Identity.Schemas) != 2 {
		t.Fatalf("Identity.Schemas: got %d entries, want 2", len(cfg.Identity.Schemas))
	}
	if cfg.Identity.Schemas[0].ID != "person" {
		t.Errorf("Identity.Schemas[0].ID: got %q, want %q", cfg.Identity.Schemas[0].ID, "person")
	}
	if cfg.Identity.Schemas[0].URL != "file:///schema.json" {
		t.Errorf("Identity.Schemas[0].URL: got %q, want %q", cfg.Identity.Schemas[0].URL, "file:///schema.json")
	}
	if cfg.Identity.Schemas[1].ID != "admin" {
		t.Errorf("Identity.Schemas[1].ID: got %q, want %q", cfg.Identity.Schemas[1].ID, "admin")
	}

	// SelfService.Methods
	if !cfg.SelfService.Methods.Password.Enabled {
		t.Error("SelfService.Methods.Password.Enabled: got false, want true")
	}
	if !cfg.SelfService.Methods.OIDC.Enabled {
		t.Error("SelfService.Methods.OIDC.Enabled: got false, want true")
	}

	// OIDC providers
	providers := cfg.SelfService.Methods.OIDC.Config.Providers
	if len(providers) != 1 {
		t.Fatalf("OIDC providers: got %d, want 1", len(providers))
	}
	p := providers[0]
	if p.ID != "google" {
		t.Errorf("OIDC provider ID: got %q, want %q", p.ID, "google")
	}
	if p.Provider != "google" {
		t.Errorf("OIDC provider Provider: got %q, want %q", p.Provider, "google")
	}
	if p.ClientID != "abc123" {
		t.Errorf("OIDC provider ClientID: got %q, want %q", p.ClientID, "abc123")
	}
	if p.ClientSecret != "secret" {
		t.Errorf("OIDC provider ClientSecret: got %q, want %q", p.ClientSecret, "secret")
	}
	if p.IssuerURL != "https://accounts.google.com" {
		t.Errorf("OIDC provider IssuerURL: got %q, want %q", p.IssuerURL, "https://accounts.google.com")
	}
	if len(p.Scope) != 2 || p.Scope[0] != "email" || p.Scope[1] != "profile" {
		t.Errorf("OIDC provider Scope: got %v, want [email profile]", p.Scope)
	}
	if p.MapperURL != "file:///mapper.jsonnet" {
		t.Errorf("OIDC provider MapperURL: got %q, want %q", p.MapperURL, "file:///mapper.jsonnet")
	}

	// Flows.Recovery
	if !cfg.SelfService.Flows.Recovery.Enabled {
		t.Error("Flows.Recovery.Enabled: got false, want true")
	}
	if cfg.SelfService.Flows.Recovery.Use != "link" {
		t.Errorf("Flows.Recovery.Use: got %q, want %q", cfg.SelfService.Flows.Recovery.Use, "link")
	}

	// Flows.Verification
	if !cfg.SelfService.Flows.Verification.Enabled {
		t.Error("Flows.Verification.Enabled: got false, want true")
	}
	if cfg.SelfService.Flows.Verification.Use != "code" {
		t.Errorf("Flows.Verification.Use: got %q, want %q", cfg.SelfService.Flows.Verification.Use, "code")
	}

	// Registration after hooks
	after := cfg.SelfService.Flows.Registration.After
	if after == nil {
		t.Fatal("Flows.Registration.After: got nil, want non-nil")
	}
	if after.Password == nil {
		t.Fatal("Flows.Registration.After.Password: got nil, want non-nil")
	}
	if len(after.Password.Hooks) != 2 {
		t.Fatalf("Flows.Registration.After.Password.Hooks: got %d, want 2", len(after.Password.Hooks))
	}
	if after.Password.Hooks[0].Hook != "session" {
		t.Errorf("After.Password.Hooks[0]: got %q, want %q", after.Password.Hooks[0].Hook, "session")
	}
	if after.Password.Hooks[1].Hook != "verification" {
		t.Errorf("After.Password.Hooks[1]: got %q, want %q", after.Password.Hooks[1].Hook, "verification")
	}
	if after.OIDC == nil {
		t.Fatal("Flows.Registration.After.OIDC: got nil, want non-nil")
	}
	if len(after.OIDC.Hooks) != 1 || after.OIDC.Hooks[0].Hook != "verification" {
		t.Errorf("After.OIDC.Hooks: got %v, want [{verification}]", after.OIDC.Hooks)
	}

	// Session
	if cfg.Session.Lifespan != "24h" {
		t.Errorf("Session.Lifespan: got %q, want %q", cfg.Session.Lifespan, "24h")
	}
}

// ---------------------------------------------------------------------------
// RequireVerification
// ---------------------------------------------------------------------------

func TestRequireVerification_NoAfterConfig(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Flows: Flows{
				Registration: RegistrationFlow{
					After: nil,
				},
			},
		},
	}
	if cfg.RequireVerification() {
		t.Error("RequireVerification: got true with nil After, want false")
	}
}

func TestRequireVerification_PasswordHooksWithoutVerification(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Flows: Flows{
				Registration: RegistrationFlow{
					After: &AfterFlow{
						Password: &struct {
							Hooks []Hook `yaml:"hooks"`
						}{
							Hooks: []Hook{
								{Hook: "session"},
								{Hook: "redirect"},
							},
						},
					},
				},
			},
		},
	}
	if cfg.RequireVerification() {
		t.Error("RequireVerification: got true without verification hook, want false")
	}
}

func TestRequireVerification_PasswordHooksWithVerification(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Flows: Flows{
				Registration: RegistrationFlow{
					After: &AfterFlow{
						Password: &struct {
							Hooks []Hook `yaml:"hooks"`
						}{
							Hooks: []Hook{
								{Hook: "session"},
								{Hook: "verification"},
							},
						},
					},
				},
			},
		},
	}
	if !cfg.RequireVerification() {
		t.Error("RequireVerification: got false with password verification hook, want true")
	}
}

func TestRequireVerification_OIDCHooksWithVerification(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Flows: Flows{
				Registration: RegistrationFlow{
					After: &AfterFlow{
						// Password block has no verification hook
						Password: &struct {
							Hooks []Hook `yaml:"hooks"`
						}{
							Hooks: []Hook{
								{Hook: "session"},
							},
						},
						// OIDC block has the verification hook
						OIDC: &struct {
							Hooks []Hook `yaml:"hooks"`
						}{
							Hooks: []Hook{
								{Hook: "verification"},
							},
						},
					},
				},
			},
		},
	}
	if !cfg.RequireVerification() {
		t.Error("RequireVerification: got false with oidc verification hook, want true")
	}
}

func TestRequireVerification_AfterPresentButBothSectionsNil(t *testing.T) {
	// After is non-nil but neither Password nor OIDC subsections are set.
	cfg := &KratosConfig{
		SelfService: SelfService{
			Flows: Flows{
				Registration: RegistrationFlow{
					After: &AfterFlow{
						Password: nil,
						OIDC:     nil,
					},
				},
			},
		},
	}
	if cfg.RequireVerification() {
		t.Error("RequireVerification: got true with empty AfterFlow, want false")
	}
}

func TestRequireVerification_ViaYAMLParse(t *testing.T) {
	yaml := `
selfservice:
  flows:
    registration:
      after:
        password:
          hooks:
            - hook: session
            - hook: verification
`
	path := writeTempYAML(t, yaml)
	defer os.Remove(path)

	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !cfg.RequireVerification() {
		t.Error("RequireVerification: got false after parsing YAML with verification hook, want true")
	}
}

// ---------------------------------------------------------------------------
// AllowedFirstFactors
// ---------------------------------------------------------------------------

func TestAllowedFirstFactors_PasswordEnabledOIDCDisabled(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Methods: Methods{
				Password: MethodEnabled{Enabled: true},
				OIDC:     OIDCMethod{Enabled: false},
			},
		},
	}
	factors := cfg.AllowedFirstFactors()
	if len(factors) != 1 || factors[0] != "password" {
		t.Errorf("AllowedFirstFactors: got %v, want [password]", factors)
	}
}

func TestAllowedFirstFactors_BothEnabled(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Methods: Methods{
				Password: MethodEnabled{Enabled: true},
				OIDC:     OIDCMethod{Enabled: true},
			},
		},
	}
	factors := cfg.AllowedFirstFactors()
	if len(factors) != 2 {
		t.Fatalf("AllowedFirstFactors: got %d factors, want 2: %v", len(factors), factors)
	}
	if factors[0] != "password" {
		t.Errorf("AllowedFirstFactors[0]: got %q, want %q", factors[0], "password")
	}
	if factors[1] != "oidc" {
		t.Errorf("AllowedFirstFactors[1]: got %q, want %q", factors[1], "oidc")
	}
}

func TestAllowedFirstFactors_NoneEnabled(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Methods: Methods{
				Password: MethodEnabled{Enabled: false},
				OIDC:     OIDCMethod{Enabled: false},
			},
		},
	}
	factors := cfg.AllowedFirstFactors()
	if len(factors) != 0 {
		t.Errorf("AllowedFirstFactors: got %v, want empty slice", factors)
	}
}

func TestAllowedFirstFactors_OIDCEnabledPasswordDisabled(t *testing.T) {
	cfg := &KratosConfig{
		SelfService: SelfService{
			Methods: Methods{
				Password: MethodEnabled{Enabled: false},
				OIDC:     OIDCMethod{Enabled: true},
			},
		},
	}
	factors := cfg.AllowedFirstFactors()
	if len(factors) != 1 || factors[0] != "oidc" {
		t.Errorf("AllowedFirstFactors: got %v, want [oidc]", factors)
	}
}

func TestAllowedFirstFactors_ViaYAMLParse(t *testing.T) {
	yaml := `
selfservice:
  methods:
    password:
      enabled: true
    oidc:
      enabled: false
`
	path := writeTempYAML(t, yaml)
	defer os.Remove(path)

	cfg, err := ParseConfig(path)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	factors := cfg.AllowedFirstFactors()
	if len(factors) != 1 || factors[0] != "password" {
		t.Errorf("AllowedFirstFactors: got %v, want [password]", factors)
	}
}
