// Package admin contains the admin-plane helpers used by the demo.
//
// Uses Keycloak's OIDC password grant to get an admin token, then calls the
// extension's admin API to register a capability and approve pending grants.
//
// These operations are NOT part of the Agent Auth Protocol flow itself —
// they're the deployment-time setup a service operator does once (or when
// capabilities change). Included here so the demo can be run from scratch.
package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// GetAdminToken exchanges an admin username+password for an access_token
// via the admin-cli OIDC public client.
func GetAdminToken(kcBaseURL, realm, username, password string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "admin-cli")
	form.Set("username", username)
	form.Set("password", password)

	u := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", kcBaseURL, realm)
	req, err := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("admin token failed: %d %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode admin token: %w", err)
	}
	return out.AccessToken, nil
}

// CapabilityDefinition is the body POSTed to the admin capability API.
type CapabilityDefinition struct {
	Name             string `json:"name"`
	Description      string `json:"description"`
	Visibility       string `json:"visibility"`
	RequiresApproval bool   `json:"requires_approval"`
	Location         string `json:"location"`
	Input            any    `json:"input,omitempty"`
	Output           any    `json:"output,omitempty"`
}

// RegisterCapability POSTs a capability definition to the extension admin
// API. Returns "created" on success, "already_exists" on 409.
func RegisterCapability(kcBaseURL, realm, adminToken string, cap CapabilityDefinition) (string, error) {
	u := fmt.Sprintf("%s/admin/realms/%s/agent-auth/capabilities", kcBaseURL, realm)
	body, err := json.Marshal(cap)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest("POST", u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("authorization", "Bearer "+adminToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusConflict {
		return "already_exists", nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("register capability failed: %d %s", resp.StatusCode, string(respBody))
	}
	return "created", nil
}

// ApproveCapability approves a pending capability grant on an agent via the
// admin shortcut (AAP §2.9 / §5.3 admin-mediated approval).
func ApproveCapability(kcBaseURL, realm, adminToken, agentID, capability string) error {
	u := fmt.Sprintf(
		"%s/admin/realms/%s/agent-auth/agents/%s/capabilities/%s/approve",
		kcBaseURL, realm, agentID, capability,
	)
	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+adminToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("approve failed: %d %s", resp.StatusCode, string(respBody))
	}
	return nil
}
