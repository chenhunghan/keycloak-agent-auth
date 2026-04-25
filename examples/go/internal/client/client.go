// Package client implements the AAP Client — a broker process that holds
// the host identity and mints host+jwt / agent+jwt on behalf of AI agents.
//
// Per AAP §1.5/§1.6, the Client is "the process that holds a host identity
// and exposes protocol tools to AI systems (MCP server, CLI, SDK). It
// manages host and agent keys, talks to servers, and signs JWTs."
//
// In this demo the Client:
//   - generates an in-memory Ed25519 keypair (the Host identity)
//   - generates a second Ed25519 keypair per Agent registered under it
//   - mints host+jwt (§4.2) for host-scoped ops (register, revoke, introspect)
//   - mints agent+jwt (§4.3) for /capability/execute (gateway mode)
//
// A production Client would persist the host key (OS keychain, secrets
// manager, disk with correct permissions) so the Host identity survives
// restarts.
package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Ed25519KeyPair bundles a matched Ed25519 key pair.
type Ed25519KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func generateEd25519() (Ed25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ed25519KeyPair{}, err
	}
	return Ed25519KeyPair{Public: pub, Private: priv}, nil
}

// AgentRegistration is the request body for POST /agent/register.
type AgentRegistration struct {
	Name         string `json:"name"`
	HostName     string `json:"host_name,omitempty"`
	Mode         string `json:"mode"`
	Capabilities []any  `json:"capabilities"`
	Reason       string `json:"reason,omitempty"`
}

// AgentRegistrationResponse is the response body for POST /agent/register.
type AgentRegistrationResponse struct {
	AgentID               string           `json:"agent_id"`
	Status                string           `json:"status"`
	Approval              map[string]any   `json:"approval,omitempty"`
	AgentCapabilityGrants []map[string]any `json:"agent_capability_grants,omitempty"`
}

// IntrospectResponse is the response body for POST /agent/introspect.
type IntrospectResponse struct {
	Active                bool             `json:"active"`
	AgentID               string           `json:"agent_id,omitempty"`
	HostID                string           `json:"host_id,omitempty"`
	Mode                  string           `json:"mode,omitempty"`
	ExpiresAt             string           `json:"expires_at,omitempty"`
	AgentCapabilityGrants []map[string]any `json:"agent_capability_grants,omitempty"`
}

// ExecuteAttempt captures the status + body of an execute call without
// raising on non-2xx. Use it for post-revocation probes.
type ExecuteAttempt struct {
	Status int
	Body   any
}

// Client is a Host-scoped broker. Construct with New, call RegisterAgent,
// then ExecuteViaGateway / IntrospectAgent / RevokeAgent.
type Client struct {
	issuerURL string
	hostKey   Ed25519KeyPair
	agentKey  *Ed25519KeyPair
	agentID   string
	http      *http.Client
}

// New creates a Client with a fresh in-memory host Ed25519 keypair.
func New(issuerURL string) (*Client, error) {
	hostKey, err := generateEd25519()
	if err != nil {
		return nil, err
	}
	return &Client{
		issuerURL: issuerURL,
		hostKey:   hostKey,
		http:      &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// CurrentAgentID returns the agent ID assigned at registration, or "" if
// RegisterAgent has not been called yet.
func (c *Client) CurrentAgentID() string {
	return c.agentID
}

// RegisterAgent mints a host+jwt for registration (including the agent
// public JWK), POSTs to /agent/register, and stores the returned agent_id.
func (c *Client) RegisterAgent(req AgentRegistration) (*AgentRegistrationResponse, error) {
	agentKey, err := generateEd25519()
	if err != nil {
		return nil, err
	}
	c.agentKey = &agentKey

	hostJwt, err := c.mintHostJwtForRegistration()
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", c.issuerURL+"/agent/register", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("authorization", "Bearer "+hostJwt)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST /agent/register failed: %d %s", resp.StatusCode, string(respBody))
	}
	var out AgentRegistrationResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode /agent/register: %w", err)
	}
	c.agentID = out.AgentID
	return &out, nil
}

// GetAgentStatus calls GET /agent/status?agent_id=... with a host+jwt and
// returns the "status" string from the response.
func (c *Client) GetAgentStatus() (string, error) {
	if c.agentID == "" {
		return "", fmt.Errorf("no agent registered")
	}
	hostJwt, err := c.mintHostJwtForOp()
	if err != nil {
		return "", err
	}
	u := fmt.Sprintf("%s/agent/status?agent_id=%s", c.issuerURL, url.QueryEscape(c.agentID))
	httpReq, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("authorization", "Bearer "+hostJwt)
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GET /agent/status failed: %d %s", resp.StatusCode, string(respBody))
	}
	var out struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("decode /agent/status: %w", err)
	}
	return out.Status, nil
}

// ExecuteViaGateway executes a capability in gateway mode. Returns the
// parsed response body on 2xx, an error otherwise. Use TryExecute for
// probes that need to inspect a non-2xx.
func (c *Client) ExecuteViaGateway(capability string, args any) (any, error) {
	attempt, err := c.TryExecute(capability, args)
	if err != nil {
		return nil, err
	}
	if attempt.Status < 200 || attempt.Status >= 300 {
		bodyJSON, _ := json.Marshal(attempt.Body)
		return nil, fmt.Errorf("POST /capability/execute failed: %d %s", attempt.Status, string(bodyJSON))
	}
	return attempt.Body, nil
}

// TryExecute is ExecuteViaGateway but surfaces the HTTP status code
// instead of turning non-2xx into errors.
func (c *Client) TryExecute(capability string, args any) (ExecuteAttempt, error) {
	if c.agentKey == nil || c.agentID == "" {
		return ExecuteAttempt{}, fmt.Errorf("no agent registered")
	}
	executeURL := c.issuerURL + "/capability/execute"
	agentJwt, err := c.mintAgentJwt(executeURL)
	if err != nil {
		return ExecuteAttempt{}, err
	}
	payload := map[string]any{
		"capability": capability,
		"arguments":  args,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ExecuteAttempt{}, err
	}
	httpReq, err := http.NewRequest("POST", executeURL, bytes.NewReader(body))
	if err != nil {
		return ExecuteAttempt{}, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("authorization", "Bearer "+agentJwt)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return ExecuteAttempt{}, err
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)

	var parsed any
	if err := json.Unmarshal(text, &parsed); err != nil {
		parsed = string(text)
	}
	return ExecuteAttempt{Status: resp.StatusCode, Body: parsed}, nil
}

// IntrospectAgent asks Keycloak to validate the current agent's JWT and
// returns a structured response. active=false after revoke.
func (c *Client) IntrospectAgent() (*IntrospectResponse, error) {
	if c.agentKey == nil || c.agentID == "" {
		return nil, fmt.Errorf("no agent registered")
	}
	agentJwt, err := c.mintAgentJwt(c.issuerURL)
	if err != nil {
		return nil, err
	}
	hostJwt, err := c.mintHostJwtForOp()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{"token": agentJwt})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequest("POST", c.issuerURL+"/agent/introspect", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("authorization", "Bearer "+hostJwt)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST /agent/introspect failed: %d %s", resp.StatusCode, string(respBody))
	}
	var out IntrospectResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode /agent/introspect: %w", err)
	}
	return &out, nil
}

// RevokeAgent permanently terminates the current agent via POST /agent/revoke.
func (c *Client) RevokeAgent() error {
	if c.agentID == "" {
		return fmt.Errorf("no agent registered")
	}
	hostJwt, err := c.mintHostJwtForOp()
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"agent_id": c.agentID})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequest("POST", c.issuerURL+"/agent/revoke", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("authorization", "Bearer "+hostJwt)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST /agent/revoke failed: %d %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// ---------- JWT minting ----------

// publicJwk returns the JWK representation of an Ed25519 public key, per
// RFC 8037: {"kty":"OKP","crv":"Ed25519","x":"<base64url-no-pad>"}.
func publicJwk(pub ed25519.PublicKey) map[string]string {
	return map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// thumbprint computes the RFC 7638 JWK thumbprint of an Ed25519 public
// key: SHA-256 of the canonical JSON (lex-ordered keys, no whitespace)
// of the required JWK members, base64url-encoded without padding.
func thumbprint(pub ed25519.PublicKey) string {
	// RFC 7638 requires lex-ordered keys and no whitespace. For OKP keys
	// the required members are crv, kty, x — already in lex order.
	canonical := fmt.Sprintf(
		`{"crv":"Ed25519","kty":"OKP","x":"%s"}`,
		base64.RawURLEncoding.EncodeToString(pub),
	)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// mintHostJwtForRegistration builds a host+jwt whose payload carries BOTH
// host_public_key and agent_public_key — used exclusively for
// POST /agent/register per §4.2.
func (c *Client) mintHostJwtForRegistration() (string, error) {
	if c.agentKey == nil {
		return "", fmt.Errorf("agent key not prepared")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":              thumbprint(c.hostKey.Public),
		"aud":              c.issuerURL,
		"iat":              now.Unix(),
		"exp":              now.Add(60 * time.Second).Unix(),
		"jti":              "h-" + uuid.NewString(),
		"host_public_key":  publicJwk(c.hostKey.Public),
		"agent_public_key": publicJwk(c.agentKey.Public),
	}
	return signEdDSA(claims, "host+jwt", c.hostKey.Private)
}

// mintHostJwtForOp builds a host+jwt for non-registration host ops (status,
// revoke, introspect) — payload carries only host_public_key.
func (c *Client) mintHostJwtForOp() (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":             thumbprint(c.hostKey.Public),
		"aud":             c.issuerURL,
		"iat":             now.Unix(),
		"exp":             now.Add(60 * time.Second).Unix(),
		"jti":             "h-" + uuid.NewString(),
		"host_public_key": publicJwk(c.hostKey.Public),
	}
	return signEdDSA(claims, "host+jwt", c.hostKey.Private)
}

// mintAgentJwt builds an agent+jwt per §4.3, signed with the agent key.
// iss is the host key thumbprint, sub is the agent id.
func (c *Client) mintAgentJwt(aud string) (string, error) {
	if c.agentKey == nil || c.agentID == "" {
		return "", fmt.Errorf("agent key or id not set")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": thumbprint(c.hostKey.Public),
		"sub": c.agentID,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(60 * time.Second).Unix(),
		"jti": "a-" + uuid.NewString(),
	}
	return signEdDSA(claims, "agent+jwt", c.agentKey.Private)
}

// signEdDSA produces a compact JWS with alg=EdDSA and the given typ header.
func signEdDSA(claims jwt.MapClaims, typ string, priv ed25519.PrivateKey) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"] = typ
	// alg is already set to "EdDSA" by NewWithClaims based on the signing
	// method; we don't overwrite it.
	return tok.SignedString(priv)
}

// ensure imports stay used even if trimmed
var _ = bytes.NewReader
