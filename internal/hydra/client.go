package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// Client wraps the Ory Hydra Admin API.
type Client struct {
	adminURL   string
	httpClient *http.Client
}

// NewClient constructs a Client. If httpClient is nil, http.DefaultClient is used.
func NewClient(adminURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{adminURL: adminURL, httpClient: httpClient}
}

type acceptLoginBody struct {
	Subject     string         `json:"subject"`
	Remember    bool           `json:"remember"`
	RememberFor int            `json:"remember_for"`
	Context     map[string]any `json:"context,omitempty"`
}

type acceptLoginResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// AcceptLoginRequest calls the Hydra admin API to accept an OAuth2 login
// request. Returns the redirect URL that the browser should be sent to.
func (c *Client) AcceptLoginRequest(ctx context.Context, challenge string, identityID, tenantID uuid.UUID, aal string, remember bool) (string, error) {
	body := acceptLoginBody{
		Subject:     identityID.String(),
		Remember:    remember,
		RememberFor: 3600,
		Context: map[string]any{
			"tenant_id": tenantID.String(),
			"aal":       aal,
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("hydra.AcceptLoginRequest marshal: %w", err)
	}

	url := fmt.Sprintf("%s/admin/oauth2/auth/requests/login/accept?login_challenge=%s",
		c.adminURL, challenge)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("hydra.AcceptLoginRequest build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hydra.AcceptLoginRequest http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hydra.AcceptLoginRequest: unexpected status %d", resp.StatusCode)
	}

	var result acceptLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("hydra.AcceptLoginRequest decode response: %w", err)
	}
	return result.RedirectTo, nil
}
