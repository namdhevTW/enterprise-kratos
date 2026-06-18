package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KratosIdentity is a row from Kratos's identities table.
type KratosIdentity struct {
	ID       uuid.UUID
	SchemaID string
	Traits   json.RawMessage
	State    string // "active" | "inactive"
}

// KratosCredential is a joined row from identity_credentials +
// identity_credential_types + identity_credential_identifiers.
type KratosCredential struct {
	ID         uuid.UUID
	IdentityID uuid.UUID
	Type       string   // "password" | "oidc" | "totp" | ...
	Config     json.RawMessage
	Identifiers []string
}

// KratosSession is a row from Kratos's sessions table.
type KratosSession struct {
	ID          uuid.UUID
	IdentityID  uuid.UUID
	Token       string
	ExpiresAt   time.Time
	Active      bool
	AAL         string
}

// KratosReader reads data from a Kratos PostgreSQL database.
type KratosReader struct {
	pool *pgxpool.Pool
	nid  uuid.UUID
}

// NewKratosReader connects to the Kratos DB and discovers the network ID.
// Pass a non-nil nid to override automatic discovery.
func NewKratosReader(ctx context.Context, dsn string, nid *uuid.UUID) (*KratosReader, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("kratos: parse DSN: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("kratos: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("kratos: ping: %w", err)
	}

	r := &KratosReader{pool: pool}
	if nid != nil {
		r.nid = *nid
	} else {
		if err := r.discoverNID(ctx); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Close releases the database connection.
func (r *KratosReader) Close() { r.pool.Close() }

// NID returns the resolved Kratos network ID.
func (r *KratosReader) NID() uuid.UUID { return r.nid }

func (r *KratosReader) discoverNID(ctx context.Context) error {
	err := r.pool.QueryRow(ctx, `SELECT id FROM networks LIMIT 1`).Scan(&r.nid)
	if err != nil {
		return fmt.Errorf("kratos: discover network ID: %w (is this a Kratos v1.x database?)", err)
	}
	return nil
}

// Identities reads all identities for the network.
func (r *KratosReader) Identities(ctx context.Context) ([]*KratosIdentity, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, schema_id, traits, state
		FROM identities
		WHERE nid = $1
	`, r.nid)
	if err != nil {
		return nil, fmt.Errorf("kratos: query identities: %w", err)
	}
	defer rows.Close()

	var out []*KratosIdentity
	for rows.Next() {
		var ident KratosIdentity
		var traitsRaw []byte
		if err := rows.Scan(&ident.ID, &ident.SchemaID, &traitsRaw, &ident.State); err != nil {
			return nil, fmt.Errorf("kratos: scan identity: %w", err)
		}
		ident.Traits = json.RawMessage(traitsRaw)
		out = append(out, &ident)
	}
	return out, rows.Err()
}

// Credentials reads all credentials for the network, joined with type names
// and identifiers, grouped by credential ID.
func (r *KratosReader) Credentials(ctx context.Context) ([]*KratosCredential, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT
			ic.id,
			ic.identity_id,
			ict.name AS type,
			ic.config,
			COALESCE(
				array_agg(ici.identifier) FILTER (WHERE ici.identifier IS NOT NULL),
				'{}'
			) AS identifiers
		FROM identity_credentials ic
		JOIN identity_credential_types ict
			ON ic.identity_credential_type_id = ict.id
		LEFT JOIN identity_credential_identifiers ici
			ON ici.identity_credential_id = ic.id AND ici.nid = $1
		WHERE ic.nid = $1
		GROUP BY ic.id, ic.identity_id, ict.name, ic.config
	`, r.nid)
	if err != nil {
		return nil, fmt.Errorf("kratos: query credentials: %w", err)
	}
	defer rows.Close()

	var out []*KratosCredential
	for rows.Next() {
		var cred KratosCredential
		var cfgRaw []byte
		if err := rows.Scan(&cred.ID, &cred.IdentityID, &cred.Type, &cfgRaw, &cred.Identifiers); err != nil {
			return nil, fmt.Errorf("kratos: scan credential: %w", err)
		}
		cred.Config = json.RawMessage(cfgRaw)
		out = append(out, &cred)
	}
	return out, rows.Err()
}

// ActiveSessions reads non-expired, active sessions for the network.
func (r *KratosReader) ActiveSessions(ctx context.Context) ([]*KratosSession, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, identity_id, token, expires_at, active, aal
		FROM sessions
		WHERE nid = $1 AND active = true AND expires_at > NOW()
	`, r.nid)
	if err != nil {
		return nil, fmt.Errorf("kratos: query sessions: %w", err)
	}
	defer rows.Close()

	var out []*KratosSession
	for rows.Next() {
		var s KratosSession
		if err := rows.Scan(&s.ID, &s.IdentityID, &s.Token, &s.ExpiresAt, &s.Active, &s.AAL); err != nil {
			return nil, fmt.Errorf("kratos: scan session: %w", err)
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// ---- Schema URL resolution --------------------------------------------------

// FetchSchema resolves a Kratos schema URL to raw JSON bytes.
// Supports file://, base64://, and http(s):// URLs.
func FetchSchema(schemaURL string) (json.RawMessage, error) {
	switch {
	case strings.HasPrefix(schemaURL, "file://"):
		path := strings.TrimPrefix(schemaURL, "file://")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("schema: read file %q: %w", path, err)
		}
		return json.RawMessage(data), nil

	case strings.HasPrefix(schemaURL, "base64://"):
		encoded := strings.TrimPrefix(schemaURL, "base64://")
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("schema: decode base64: %w", err)
		}
		return json.RawMessage(data), nil

	case strings.HasPrefix(schemaURL, "http://") || strings.HasPrefix(schemaURL, "https://"):
		resp, err := http.Get(schemaURL) //nolint:noctx
		if err != nil {
			return nil, fmt.Errorf("schema: fetch %q: %w", schemaURL, err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("schema: read response from %q: %w", schemaURL, err)
		}
		return json.RawMessage(data), nil

	default:
		return nil, fmt.Errorf("schema: unsupported URL scheme %q", schemaURL)
	}
}
