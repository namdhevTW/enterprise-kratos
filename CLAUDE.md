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

## Build Status

All 8 steps complete. All tests passing. 81.2% overall coverage.

- [x] 1. DB schema + tenant CRUD
- [x] 2. Authenticator registry + REST adapter
- [x] 3. Login flow engine
- [x] 4. Session management + Hydra bridge
- [x] 5. Registration + verification flows
- [x] 6. OIDC/SAML per-tenant SSO (OIDC: full; SAML: DB model + stub, flow TBD)
- [x] 7. Migration CLI (`idpctl`)
- [x] 8. Recovery + settings flows
- [x] OpenAPI 3.1.0 spec (`api/openapi.yaml`)
- [x] Test suite: 100% engine coverage, 81.2% overall (1555/1916 stmts)

---

## Key Design Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Multi-tenancy model | Row-level isolation | All tables include `tenant_id` in PK |
| Tenant routing | Path-based `/t/{tenant-slug}/...` | Clean, no DNS per tenant |
| Identity isolation | Email can exist in multiple tenants independently | Tenants are fully independent |
| Session isolation | Sessions scoped strictly per tenant | Token valid for Tenant A has zero validity for Tenant B |
| Identity schemas | Per-tenant (not shared) | Teams have different trait requirements |
| SSO config | Stored in CockroachDB, loaded per-request; in-memory cache in OIDC engine | Runtime updates; changefeed invalidation is a future step |
| SAML/OIDC | Per-tenant provider config | Each tenant brings their own IdP |
| External auth services | REST adapter pattern | TOTP, PassKey, OTP owned by enterprise services |
| Hydra | Shared instance, per-tenant client-ids | Already running in prod |
| HTTP router | chi v5 | URL params, middleware composition |
| Query layer | Raw pgx/v5 | No ORM or sqlc — full control over CockroachDB-specific SQL |
| DB migrations | goose | SQL-first, up/down migrations |

---

## Module Structure

```
/cmd
  /idpd                      - server binary (main entry point)
  /idpctl                    - migration CLI

/internal
  /dbutil                    - dbutil.Querier interface + pgxpool adapter (enables pgxmock in tests)
  /tenant                    - model, store, resolver middleware, context helpers
  /flow                      - shared flow model + store (self_service_flows table)
    /login                   - login engine + HTTP handler
    /registration            - registration engine + HTTP handler
    /recovery                - recovery engine + HTTP handler (anti-enumeration, 15-min recovery session)
    /settings                - settings engine + HTTP handler (profile update, password change)
    /verification            - email verification engine + HTTP handler
  /identity                  - Identity + Credential models, CRUD store
  /session                   - Session model, store (Create/GetByToken/Revoke), HTTP handler (whoami/logout)
  /schema                    - Per-tenant identity schema store (GetActive, EnsureDefault)
  /policy                    - Per-tenant flow policy store + Default()
  /authenticator             - Authenticator interface + type constants + UI node types
    /registry                - maps authenticator ID → implementation
    /adapters
      /password              - bcrypt adapter (FirstFactor)
      /rest                  - generic REST adapter for TOTP, PassKey, OTP (SecondFactor)
      /oidc                  - OIDC adapter (StartFlow returns per-tenant buttons; callback in /oidc)
  /oidc                      - OIDC redirect + callback engine, HTTP handler, PKCE, provider cache
  /sso                       - SSO provider model, store, admin CRUD HTTP handler
  /hydra                     - Hydra admin API client (AcceptLoginRequest)
  /migration                 - Kratos YAML config parser, Kratos DB reader, Migrator

/api
  /openapi.yaml              - OpenAPI 3.1.0 spec (16 paths, 24 operations, 13 schemas)

/db
  /migrations                - CockroachDB migrations (goose)
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
  state     TEXT  NOT NULL DEFAULT 'active',   -- active | pending_verification
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE identity_credentials (
  id          UUID     NOT NULL DEFAULT gen_random_uuid(),
  tenant_id   UUID     NOT NULL,
  identity_id UUID     NOT NULL,
  type        TEXT     NOT NULL,     -- password|oidc|saml|totp|passkey|otp
  identifiers TEXT[]   NOT NULL,     -- for lookup (emails, subjects, {providerID}:{sub})
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
  ui          JSONB       NOT NULL,   -- nodes + messages (Kratos-compatible) + _internal server state
  expires_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE tenant_sso_providers (
  id        UUID  NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID  NOT NULL,
  type      TEXT  NOT NULL,   -- oidc|saml
  provider  TEXT  NOT NULL,   -- google|azure|okta|custom
  config    JSONB NOT NULL,   -- NOTE: client secrets stored plaintext in PoC; encrypt at rest in production
  enabled   BOOL  NOT NULL DEFAULT true,
  PRIMARY KEY (tenant_id, id)
);

CREATE TABLE tenant_flow_policies (
  tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
  policy    JSONB NOT NULL
);
```

---

## HTTP Routes

All routes under `/t/{tenant-slug}/`. The tenant middleware resolves slug → tenant_id and sets it in context.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | — | Health check |
| POST | `/t/{slug}/self-service/login/flows` | — | Init login flow |
| GET | `/t/{slug}/self-service/login/flows/{id}` | — | Get login flow |
| POST | `/t/{slug}/self-service/login/flows/{id}` | — | Submit credentials (+ `?login_challenge=` for Hydra) |
| POST | `/t/{slug}/self-service/login/flows/{id}/methods/oidc` | — | Initiate OIDC redirect |
| GET | `/t/{slug}/self-service/login/flows/oidc/callback` | — | OIDC authorization code callback |
| POST | `/t/{slug}/self-service/registration/flows` | — | Init registration flow |
| GET | `/t/{slug}/self-service/registration/flows/{id}` | — | Get registration flow |
| POST | `/t/{slug}/self-service/registration/flows/{id}` | — | Submit registration |
| GET | `/t/{slug}/self-service/verification/flows/{id}` | — | Get flow or verify via `?token=` |
| POST | `/t/{slug}/self-service/verification/flows/{id}` | — | Submit token |
| POST | `/t/{slug}/self-service/recovery/flows` | — | Init recovery flow |
| GET | `/t/{slug}/self-service/recovery/flows/{id}` | — | Get flow or use token via `?token=` |
| POST | `/t/{slug}/self-service/recovery/flows/{id}` | — | Submit email (anti-enumeration) |
| POST | `/t/{slug}/self-service/settings/flows` | Session | Init settings flow |
| GET | `/t/{slug}/self-service/settings/flows/{id}` | — | Get settings flow |
| POST | `/t/{slug}/self-service/settings/flows/{id}` | Session | Submit profile/password change |
| GET | `/t/{slug}/sessions/whoami` | Session | Introspect current session |
| DELETE | `/t/{slug}/sessions/whoami` | Session | Logout |
| POST | `/t/{slug}/admin/sso/providers` | (admin layer) | Create SSO provider |
| GET | `/t/{slug}/admin/sso/providers` | (admin layer) | List SSO providers |
| GET | `/t/{slug}/admin/sso/providers/{id}` | (admin layer) | Get SSO provider |
| DELETE | `/t/{slug}/admin/sso/providers/{id}` | (admin layer) | Delete SSO provider |
| PATCH | `/t/{slug}/admin/sso/providers/{id}/enabled` | (admin layer) | Enable/disable provider |

Session auth: `X-Session-Token: <token>` or `Authorization: Bearer <token>`

---

## Authenticator Plugin Interface

```go
type Authenticator interface {
    ID()   string
    Type() AuthenticatorType  // FirstFactor | SecondFactor | Either

    StartFlow(ctx context.Context, r *StartFlowRequest) (*FlowState, error)
    CompleteFlow(ctx context.Context, r *CompleteFlowRequest) (*AuthResult, error)
    Enroll(ctx context.Context, r *EnrollRequest) (*EnrollResult, error)
    Unenroll(ctx context.Context, r *UnenrollRequest) error
}
```

Registered adapters: `password` (bcrypt, FirstFactor), `oidc` (per-tenant buttons, FirstFactor), `rest/*` (TOTP/PassKey/OTP, SecondFactor).

---

## Flow Policy Schema (per-tenant JSONB)

```json
{
  "login": {
    "allowed_first_factors":  ["password", "oidc"],
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
    "required_aal":       "aal1",
    "inactivity_timeout": "1h"
  },
  "recovery": {
    "enabled":         true,
    "allowed_methods": ["link"]
  }
}
```

---

## Login Request Flow

```
POST /t/{tenant-slug}/self-service/login/flows

1. Tenant middleware resolves slug → tenant_id
2. Login engine reads policy: which first factors are allowed?
3. Creates self_service_flow row (tenant_id scoped, 30-min TTL)
4. Returns UI nodes for allowed methods (identifier input + method-specific inputs)
5. Client submits: {method, identifier, password/totp_code/...}
6. Authenticator registry dispatches:
   - password  → bcrypt adapter
   - totp/otp  → REST adapter → enterprise service
   - oidc      → initiate redirect (separate endpoint)
7. If MFARequired + second factors configured → advance to second_factor phase
8. On complete: Create session (tenant-scoped) → issue token
   - If login_challenge present + HYDRA_ADMIN_URL set → AcceptLoginRequest → 302 redirect
   - Otherwise → 200 JSON with session_token
```

---

## OIDC Flow

```
POST /t/{slug}/self-service/login/flows/{flowId}/methods/oidc
Body: {"provider_id": "<uuid>"}
→ Returns {"redirect_to": "https://provider.example.com/auth?..."}
  (PKCE S256 + nonce stored in flow UIInternal; state = flowID)

Browser redirects, user authenticates at provider.

GET /t/{slug}/self-service/login/flows/oidc/callback?state={flowID}&code={code}
→ Exchanges code, verifies id_token (nonce + sig), looks up or JIT-provisions identity
→ Returns session_token
```

---

## Migration CLI

```
idpctl migrate \
  --kratos-config ./kratos.yml \
  --kratos-db     postgres://root@kratos-db:5432/kratos \
  --target-tenant my-team \
  --target-db     "postgresql://root@crdb:26257/idpd?sslmode=disable" \
  [--target-name  "My Team"]
  [--include-sessions]
  [--dry-run]

Migrates:
  ✓ kratos.yml         → tenant_flow_policies + tenant_sso_providers
  ✓ identity schema    → identity_schemas (file://, base64://, https:// URL support)
  ✓ identities+traits  → identities
  ✓ credentials        → identity_credentials
                          password: hash format is compatible (bcrypt/argon2 pass through)
                          oidc:     rebuilt as {providerID}:{subject} identifiers
  ✓ active sessions    → sessions (--include-sessions flag)
  ✗ TOTP secrets       → owned by enterprise service, out of scope

--dry-run prints identity/credential/provider counts without writing.
Kratos network ID is auto-detected from the networks table (Kratos v1.x).
```

---

## Engineering Patterns

### Interface injection for testability

Every engine and handler accepts narrow interfaces rather than concrete store types. This pattern appears consistently across the codebase:

```go
// In the engine file (unexported, local to the package)
type flowStorer interface {
    Create(ctx, tenantID, flowType, ui, expiresAt) (*flow.Flow, error)
    Get(ctx, tenantID, flowID)                      (*flow.Flow, error)
    Update(ctx, tenantID, flowID, state, id, ui)    error
}

type Engine struct {
    flows flowStorer   // *flow.Store satisfies this
    // ...
}

func New(flows flowStorer, ...) *Engine { ... }
```

Concrete `*Store` types satisfy the interfaces via Go's structural typing. Tests inject fakes.

### DB querier abstraction (`internal/dbutil`)

`dbutil.Querier` wraps `*pgxpool.Pool` so stores can be tested with `pgxmock.NewPool()` without a real database:

```go
type Querier interface {
    QueryRow(ctx, sql, args...) pgx.Row
    Query(ctx, sql, args...)    (pgx.Rows, error)
    Exec(ctx, sql, args...)     (pgconn.CommandTag, error)
}

// NewStore keeps its public API unchanged:
func NewStore(pool *pgxpool.Pool) *Store {
    return &Store{pool: dbutil.Wrap(pool)}  // internally uses Querier
}
```

### UI Internal state

`flow.UI._internal` (type `flow.UIInternal`) stores server-side flow state that is persisted to CockroachDB JSONB but is **never sent to clients** — all handlers strip it before responding. Fields include: phase, authn_states, completed_aal, completed_amr, verification_token, recovery_token, OIDC nonce/code_verifier/provider_id.

---

## External Enterprise Services

| Service  | Protocol | Notes |
|---|---|---|
| TOTP     | REST | Production, wrapped by `rest.Adapter` |
| PassKey  | REST | Production, wrapped by `rest.Adapter` |
| OTP      | REST | Production, wrapped by `rest.Adapter` |

All wrapped via `internal/authenticator/adapters/rest`. Per-tenant config injected at request time, not at construction time.

---

## Testing

```bash
go test ./internal/... -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out | grep total
# → total: 81.2%
```

Coverage highlights:
- Flow engines: 93–100% each
- HTTP handlers: 87–98% each
- Stores: 86–100% each (pgxmock, no real DB required)
- Authenticator adapters: 93–100%
- OIDC engine: 67% (InitiateLogin fully tested with mock OIDC server; HandleCallback limited by JWT signing complexity)

Not covered without a running CockroachDB:
- `internal/migration/run.go` — bulk INSERT/UPDATE migration logic
- `internal/dbutil` — the pool adapter methods themselves (4 stmts)

---

## Infrastructure

- **Kubernetes**: self-hosted
- **CockroachDB**: 25.2.18, self-hosted
- **Ory Hydra**: shared instance, per-tenant OAuth2 client-ids; bridge in `internal/hydra`
- **Language**: Go 1.25
- **DB migrations**: goose (`db/migrations/`)
- **Query layer**: raw pgx/v5 (no sqlc)
- **HTTP router**: chi v5
- **Key dependencies**: `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2`, `gopkg.in/yaml.v3`, `github.com/pashagolub/pgxmock/v4` (test)

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | — | CockroachDB connection string |
| `PORT` | No | `8080` | HTTP listen port |
| `HYDRA_ADMIN_URL` | No | — | Hydra admin URL; enables login_challenge redirect flow when set |
