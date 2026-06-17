-- +goose Up
-- +goose StatementBegin
CREATE TABLE tenants (
  id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug    TEXT NOT NULL UNIQUE,
  name    TEXT NOT NULL,
  state   TEXT NOT NULL DEFAULT 'active'
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE identity_schemas (
  id        UUID    NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID    NOT NULL REFERENCES tenants(id),
  version   INT     NOT NULL DEFAULT 1,
  schema    JSONB   NOT NULL,
  is_active BOOL    NOT NULL DEFAULT true,
  PRIMARY KEY (tenant_id, id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE identities (
  id        UUID  NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID  NOT NULL,
  schema_id UUID  NOT NULL,
  traits    JSONB NOT NULL,
  state     TEXT  NOT NULL DEFAULT 'active',
  PRIMARY KEY (tenant_id, id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE identity_credentials (
  id          UUID     NOT NULL DEFAULT gen_random_uuid(),
  tenant_id   UUID     NOT NULL,
  identity_id UUID     NOT NULL,
  type        TEXT     NOT NULL,
  identifiers TEXT[]   NOT NULL,
  config      JSONB    NOT NULL,
  PRIMARY KEY (tenant_id, id),
  UNIQUE INDEX idx_identity_credentials_lookup (tenant_id, type, identifiers)
);
-- +goose StatementEnd

-- +goose StatementBegin
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
  UNIQUE INDEX idx_sessions_token (tenant_id, token)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE self_service_flows (
  id          UUID        NOT NULL DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
  type        TEXT        NOT NULL,
  state       TEXT        NOT NULL,
  identity_id UUID,
  ui          JSONB       NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE tenant_sso_providers (
  id        UUID  NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID  NOT NULL,
  type      TEXT  NOT NULL,
  provider  TEXT  NOT NULL,
  config    JSONB NOT NULL,
  enabled   BOOL  NOT NULL DEFAULT true,
  PRIMARY KEY (tenant_id, id)
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE tenant_flow_policies (
  tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
  policy    JSONB NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS tenant_flow_policies;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS tenant_sso_providers;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS self_service_flows;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS sessions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS identity_credentials;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS identities;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS identity_schemas;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS tenants;
-- +goose StatementEnd
