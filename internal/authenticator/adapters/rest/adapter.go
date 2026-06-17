package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/enterprise-idp/idpd/internal/authenticator"
)

// Adapter wraps an external enterprise REST service (TOTP, PassKey, OTP) and
// implements the authenticator.Authenticator interface. A single Adapter is
// instantiated per authenticator type; tenant_id is forwarded in every request
// so the upstream service can scope its operations correctly.
type Adapter struct {
	id      string
	authType authenticator.Type
	baseURL string
	client  *http.Client
}

// New constructs an Adapter. baseURL should not have a trailing slash.
func New(id string, authType authenticator.Type, baseURL string, client *http.Client) *Adapter {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Adapter{
		id:       id,
		authType: authType,
		baseURL:  strings.TrimRight(baseURL, "/"),
		client:   client,
	}
}

func (a *Adapter) ID() string                { return a.id }
func (a *Adapter) Type() authenticator.Type  { return a.authType }

// StartFlow calls POST {baseURL}/flows/start.
func (a *Adapter) StartFlow(ctx context.Context, r *authenticator.StartFlowRequest) (*authenticator.FlowState, error) {
	req := startFlowReq{
		TenantID:   r.TenantID.String(),
		IdentityID: r.IdentityID.String(),
		FlowID:     r.FlowID.String(),
		Params:     r.Params,
	}

	var resp startFlowResp
	if err := a.post(ctx, "/flows/start", req, &resp); err != nil {
		return nil, fmt.Errorf("rest[%s] StartFlow: %w", a.id, err)
	}

	return &authenticator.FlowState{
		Nodes: resp.Nodes,
		State: resp.State,
	}, nil
}

// CompleteFlow calls POST {baseURL}/flows/complete.
func (a *Adapter) CompleteFlow(ctx context.Context, r *authenticator.CompleteFlowRequest) (*authenticator.AuthResult, error) {
	req := completeFlowReq{
		TenantID:   r.TenantID.String(),
		IdentityID: r.IdentityID.String(),
		FlowID:     r.FlowID.String(),
		FlowState:  r.FlowState,
		Values:     r.Values,
	}

	var resp completeFlowResp
	if err := a.post(ctx, "/flows/complete", req, &resp); err != nil {
		return nil, fmt.Errorf("rest[%s] CompleteFlow: %w", a.id, err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("rest[%s] CompleteFlow: upstream rejected credentials", a.id)
	}

	return &authenticator.AuthResult{
		IdentityID: r.IdentityID,
		AAL:        resp.AAL,
		AMR:        resp.AMR,
	}, nil
}

// Enroll calls POST {baseURL}/credentials/enroll.
func (a *Adapter) Enroll(ctx context.Context, r *authenticator.EnrollRequest) (*authenticator.EnrollResult, error) {
	req := enrollReq{
		TenantID:   r.TenantID.String(),
		IdentityID: r.IdentityID.String(),
		Values:     r.Values,
	}

	var resp enrollResp
	if err := a.post(ctx, "/credentials/enroll", req, &resp); err != nil {
		return nil, fmt.Errorf("rest[%s] Enroll: %w", a.id, err)
	}

	return &authenticator.EnrollResult{
		CredentialType:   resp.CredentialType,
		Identifiers:      resp.Identifiers,
		CredentialConfig: resp.CredentialConfig,
	}, nil
}

// Unenroll calls POST {baseURL}/credentials/unenroll.
func (a *Adapter) Unenroll(ctx context.Context, r *authenticator.UnenrollRequest) error {
	req := unenrollReq{
		TenantID:     r.TenantID.String(),
		IdentityID:   r.IdentityID.String(),
		CredentialID: r.CredentialID.String(),
	}

	if err := a.post(ctx, "/credentials/unenroll", req, nil); err != nil {
		return fmt.Errorf("rest[%s] Unenroll: %w", a.id, err)
	}
	return nil
}

// post marshals body as JSON, POSTs to baseURL+path, and decodes the JSON
// response into out (nil out = discard body). Non-2xx responses are errors.
func (a *Adapter) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody errResp
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		if errBody.Error != "" {
			return fmt.Errorf("upstream %d: %s", resp.StatusCode, errBody.Error)
		}
		return fmt.Errorf("upstream responded with status %d", resp.StatusCode)
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// ---- request/response shapes ------------------------------------------------

type startFlowReq struct {
	TenantID   string            `json:"tenant_id"`
	IdentityID string            `json:"identity_id"`
	FlowID     string            `json:"flow_id"`
	Params     map[string]string `json:"params,omitempty"`
}

type startFlowResp struct {
	Nodes []authenticator.UINode `json:"nodes"`
	State string                 `json:"state"`
}

type completeFlowReq struct {
	TenantID   string            `json:"tenant_id"`
	IdentityID string            `json:"identity_id"`
	FlowID     string            `json:"flow_id"`
	FlowState  string            `json:"flow_state"`
	Values     map[string]string `json:"values"`
}

type completeFlowResp struct {
	Success bool     `json:"success"`
	AAL     string   `json:"aal"`
	AMR     []string `json:"amr"`
}

type enrollReq struct {
	TenantID   string            `json:"tenant_id"`
	IdentityID string            `json:"identity_id"`
	Values     map[string]string `json:"values,omitempty"`
}

type enrollResp struct {
	CredentialType   string          `json:"credential_type"`
	Identifiers      []string        `json:"identifiers"`
	CredentialConfig json.RawMessage `json:"credential_config"`
}

type unenrollReq struct {
	TenantID     string `json:"tenant_id"`
	IdentityID   string `json:"identity_id"`
	CredentialID string `json:"credential_id"`
}

type errResp struct {
	Error string `json:"error"`
}
