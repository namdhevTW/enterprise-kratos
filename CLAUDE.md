# Enterprise IDP — Project Reference

## What We're Building

A new, from-scratch Identity Provider (IDP) in Go with:
- Full Ory Kratos feature parity (self-service flows, identity schemas, sessions, credentials)
- Multi-tenancy as a first-class primitive (not bolted on)
- Ory Hydra as the OAuth2/OIDC authorization server (shared instance, per-tenant client-ids)
- CockroachDB 25.2.18 (self-hosted) as the storage layer
- Pluggable authenticator interface that delegates to external enterprise REST services
- API-first, no UI initially
- Migration tooling to import existing Ory Kratos instances into a single multi-tenant deployment

**Goal**: Consolidate N individual Kratos instances (one per platform team) into one IDP where each team is a tenant.

---

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Multi-tenancy model | Row-level isolation | All tables include `tenant_id` in PK |
| Tenant routing | Path-based `/t/{tenant-slug}/...` | Clean, no DNS per tenant |
| Identity isolation | Email can exist in multiple tenants independently | Tenants are fully independent |
| Session isolation | Sessions scoped strictly per tenant | Token valid for Tenant A has zero validity for Tenant B |
| Identity schemas | Per-tenant (not shared) | Teams have different trait requirements |
| SSO config | Stored in CockroachDB, cached in-memory | Runtime updates without restarts |
| Cache invalidation | CockroachDB changefeeds | Push-based, no polling |
| SAML/OIDC | Per-tenant provider config | Each tenant brings their own IdP |
| External auth services | REST adapter pattern | TOTP, PassKey, OTP owned by enterprise services |
| Hydra | Shared instance, per-tenant client-ids | Already running in prod |

---

## Module Structure

```
/cmd/idpd                    - server binary
/internal
  /tenant                    - resolver, middleware, context propagation
  /flow                      - self-service flow engine
    /login
    /registration
    /recovery
    /settings
    /verification
  /identity                  - CRUD, schema validation
  /session                   - tenant-scoped session management
  /authenticator             - plugin registry + adapters
    /registry                - maps authenticator ID → implementation
    /adapters
      /rest                  - generic REST adapter (TOTP, PassKey, OTP)
      /password              - built-in bcrypt
      /oidc                  - per-tenant OIDC (dynamic client config)
      /saml                  - per-tenant SAML SP
  /schema                    - per-tenant identity schema registry + validator
  /policy                    - flow policy engine (what's allowed per tenant)
  /config                    - tenant config cache + CockroachDB changefeed sync
  /hydra                     - Hydra login/consent bridge
  /migration                 - Kratos YAML + data import tooling
/api/v1                      - HTTP handlers (chi or stdlib)
/db
  /migrations                - CRDB migrations (goose)
  /queries                   - sqlc generated
```

---

## Database Schema

```sql
CREATE TABLE tenants (
  id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug    TEXT NOT NULL UNIQUE,
  name    TEXT NOT NULL,
  state   TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE identity_schemas (
  id        UUID    NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID    NOT NULL REFERENCES tenants(id),
  version   INT     NOT NULL DEFAULT 1,
  schema    JSONB   NOT NULL,
  is_active BOOL    NOT NULL DEFAULT true,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE identities (
  id        UUID  NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID  NOT NULL,
  schema_id UUID  NOT NULL,
  traits    JSONB NOT NULL,
  state     TEXT  NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE identity_credentials (
  id          UUID     NOT NULL DEFAULT gen_random_uuid(),
  tenant_id   UUID     NOT NULL,
  identity_id UUID     NOT NULL,
  type        TEXT     NOT NULL,     -- password|oidc|saml|totp|passkey|otp
  identifiers TEXT[]   NOT NULL,     -- for lookup (emails, subjects)
  config      JSONB    NOT NULL,     -- hashed pw, oidc subject, etc.
  PRIMARY KEY (tenant_id, id),
  UNIQUE INDEX (tenant_id, type, identifiers)
);

CREATE TABLE sessions (
  id                            UUID        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id                     UUID        NOT NULL,
  identity_id                   UUID        NOT NULL,
  token                         TEXT        NOT NULL,
  expires_at                    TIMESTAMPTZ NOT NULL,
  authenticator_assurance_level TEXT        NOT NULL DEFAULT 'aal1',
  amr                           JSONB,
  active                        BOOL        NOT NULL DEFAULT true,
  PRIMARY KEY (tenant_id, id),
  UNIQUE INDEX (tenant_id, token)
);

CREATE TABLE self_service_flows (
  id          UUID        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
  type        TEXT        NOT NULL,   -- login|registration|recovery|settings|verification
  state       TEXT        NOT NULL,   -- pending|success|failed|expired
  identity_id UUID,
  ui          JSONB       NOT NULL,   -- nodes + messages (Kratos-compatible)
  expires_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE tenant_sso_providers (
  id        UUID  NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID  NOT NULL,
  type      TEXT  NOT NULL,   -- oidc|saml
  provider  TEXT  NOT NULL,   -- google|azure|okta|custom
  config    JSONB NOT NULL,   -- encrypted: client_id, secret, metadata_url
  enabled   BOOL  NOT NULL DEFAULT true,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE tenant_flow_policies (
  tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
  policy    JSONB NOT NULL
);
```

---

## Authenticator Plugin Interface

```go
type AuthenticatorType int
const (
    FirstFactor  AuthenticatorType = iota
    SecondFactor
    Either
)

type Authenticator interface {
    ID()   string
    Type() AuthenticatorType

    StartFlow(ctx context.Context, r *StartFlowRequest) (*FlowState, error)
    CompleteFlow(ctx context.Context, r *CompleteFlowRequest) (*AuthResult, error)
    Enroll(ctx context.Context, r *EnrollRequest) (*EnrollResult, error)
    Unenroll(ctx context.Context, r *UnenrollRequest) error
}

// RESTAdapter wraps external TOTP/PassKey/OTP enterprise services
type RESTAdapter struct {
    authenticatorID string
    baseURL         string
    client          *http.Client
}
```

---

## Flow Policy Schema (per-tenant JSONB)

```json
{
  "login": {
    "allowed_first_factors":  ["password", "oidc", "saml"],
    "allowed_second_factors": ["totp", "otp", "passkey"],
    "mfa_required":           true,
    "sso_only":               false
  },
  "registration": {
    "enabled":              true,
    "require_verification": true
  },
  "session": {
    "ttl":                "24h",
    "required_aal":       "aal2",
    "inactivity_timeout": "1h"
  },
  "recovery": {
    "enabled":         true,
    "allowed_methods": ["link", "otp"]
  }
}
```

---

## Login Request Flow

```
POST /t/{tenant-slug}/self-service/login/flows

1. Tenant middleware resolves slug → tenant_id, loads policy from cache
2. Flow engine checks policy: which first factors are allowed?
3. Creates self_service_flow row (tenant_id scoped)
4. Returns UI nodes for allowed methods
5. Client submits credentials
6. Authenticator registry dispatches to correct plugin:
   - password → built-in
   - totp     → RESTAdapter → enterprise TOTP service
   - passkey  → RESTAdapter → enterprise PassKey service
   - otp      → RESTAdapter → enterprise OTP service
   - oidc     → dynamic OIDC client (per-tenant config from cache)
   - saml     → per-tenant SAML SP
7. On success: check if AAL policy requires second factor
8. Issue session (tenant_id scoped) + call Hydra accept_login_request
```

---

## Migration Tooling

```
idpctl migrate \
  --kratos-config ./kratos.yml \
  --kratos-db postgres://... \
  --target-tenant my-team \
  --target-idp https://idp.internal

Migrates:
  ✓ kratos.yml         → tenant_flow_policies + tenant_sso_providers
  ✓ identity schema    → identity_schemas
  ✓ identities+traits  → identities
  ✓ credentials        → identity_credentials (password hashes, oidc subjects)
  ✓ active sessions    → sessions (optional: --include-sessions)
  ✗ TOTP secrets       → owned by enterprise service, out of scope
```

---

## External Enterprise Services

| Service  | Protocol | Notes |
|---|---|---|
| TOTP     | REST | Production, battle-tested, still evolving |
| PassKey  | REST | Production, battle-tested, still evolving |
| OTP      | REST | Production, battle-tested, still evolving |

All wrapped via `RESTAdapter` implementing the `Authenticator` interface. Per-tenant config injected at request time, not at construction time.

---

## Build Order

- [ ] 1. DB schema + tenant CRUD
- [ ] 2. Authenticator registry + REST adapter
- [ ] 3. Login flow engine
- [ ] 4. Session management + Hydra bridge
- [ ] 5. Registration + verification flows
- [ ] 6. OIDC/SAML per-tenant SSO
- [ ] 7. Migration CLI (`idpctl`)
- [ ] 8. Recovery + settings flows

---

## Infrastructure

- **Kubernetes**: self-hosted
- **CockroachDB**: 25.2.18, self-hosted
- **Ory Hydra**: shared instance, per-tenant OAuth2 client-ids
- **Language**: Go
- **DB migrations**: goose
- **Query layer**: sqlc
- **HTTP router**: TBD (chi or stdlib)
