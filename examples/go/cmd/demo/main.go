// demo walks both AAP journeys end-to-end against a running Keycloak +
// resource-server compose stack. Mirrors examples/js/src/demo.ts step-for-step.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/chh/keycloak-agent-auth/examples/go/internal/admin"
	"github.com/chh/keycloak-agent-auth/examples/go/internal/agent"
	"github.com/chh/keycloak-agent-auth/examples/go/internal/client"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func uniqueSuffix() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// autonomousJourney mirrors AgentAuthFullJourneyE2E.autonomousJourneyActiveImmediately:
//
//	admin registers auto-approved capability → agent registers autonomous
//	(active immediately) → execute → introspect active → revoke →
//	post-revoke execute rejected → post-revoke introspect inactive.
func autonomousJourney(kcBase, realm, rsLocation, issuer, adminToken string) error {
	capName := "greet_autonomous_" + uniqueSuffix()
	fmt.Printf("\n=== autonomous journey (capability: %s) ===\n", capName)

	// 1. admin registers an auto-approved capability
	fmt.Println("1. admin registers capability (requires_approval=false)")
	if _, err := admin.RegisterCapability(kcBase, realm, adminToken, admin.CapabilityDefinition{
		Name:             capName,
		Description:      "Demo greet, auto-approved",
		Visibility:       "authenticated",
		RequiresApproval: false,
		Location:         rsLocation,
		Input: map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
		},
		Output: map[string]any{"type": "object"},
	}); err != nil {
		return err
	}

	// 2. agent registers autonomous — active immediately
	fmt.Println("2. agent registers (mode=autonomous)")
	c, err := client.New(issuer)
	if err != nil {
		return err
	}
	reg, err := c.RegisterAgent(client.AgentRegistration{
		Name:         "demo-autonomous-agent",
		HostName:     "demo-host",
		Mode:         "autonomous",
		Capabilities: []any{capName},
		Reason:       "Demo autonomous journey",
	})
	if err != nil {
		return err
	}
	fmt.Printf("   agent_id=%s  status=%s\n", reg.AgentID, reg.Status)
	if reg.Status != "active" {
		return fmt.Errorf("expected active, got %s", reg.Status)
	}

	// 3. execute hits the backend
	fmt.Println("3. execute via gateway")
	a := agent.New(c, reg.AgentID)
	result, err := a.InvokeTool(capName, map[string]any{"name": "autonomous"})
	if err != nil {
		return err
	}
	greeting, err := extractGreeting(result)
	if err != nil {
		return err
	}
	fmt.Printf("   backend returned: \"%s\"\n", greeting)

	// 4. introspect reports active
	fmt.Println("4. introspect")
	intro1, err := c.IntrospectAgent()
	if err != nil {
		return err
	}
	fmt.Printf("   active=%v\n", intro1.Active)
	if !intro1.Active {
		return fmt.Errorf("expected active=true")
	}

	// 5. revoke
	fmt.Println("5. revoke")
	if err := c.RevokeAgent(); err != nil {
		return err
	}

	// 6. post-revoke execute is rejected
	fmt.Println("6. post-revoke execute (expected: rejected)")
	postExec, err := c.TryExecute(capName, map[string]any{"name": "autonomous"})
	if err != nil {
		return err
	}
	fmt.Printf("   status=%d\n", postExec.Status)
	if postExec.Status == 200 {
		return fmt.Errorf("expected execute to fail after revoke")
	}

	// 7. post-revoke introspect reports inactive
	fmt.Println("7. post-revoke introspect (expected: active=false)")
	intro2, err := c.IntrospectAgent()
	if err != nil {
		return err
	}
	fmt.Printf("   active=%v\n", intro2.Active)
	if intro2.Active {
		return fmt.Errorf("expected active=false")
	}

	fmt.Println("autonomous journey: OK")
	return nil
}

// delegatedJourney mirrors AgentAuthFullJourneyE2E.delegatedJourneyPendingUntilApproved:
//
//	admin registers approval-required capability → agent registers delegated
//	(pending) → admin approves grant → status=active → execute → introspect
//	active → revoke → post-revoke execute rejected → post-revoke introspect
//	inactive.
func delegatedJourney(kcBase, realm, rsLocation, issuer, adminToken string) error {
	capName := "greet_delegated_" + uniqueSuffix()
	fmt.Printf("\n=== delegated journey (capability: %s) ===\n", capName)

	// 1. admin registers an approval-required capability
	fmt.Println("1. admin registers capability (requires_approval=true)")
	if _, err := admin.RegisterCapability(kcBase, realm, adminToken, admin.CapabilityDefinition{
		Name:             capName,
		Description:      "Demo greet, approval required",
		Visibility:       "authenticated",
		RequiresApproval: true,
		Location:         rsLocation,
		Input: map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
		},
		Output: map[string]any{"type": "object"},
	}); err != nil {
		return err
	}

	// 2. agent registers delegated — lands in pending
	fmt.Println("2. agent registers (mode=delegated) → expect pending")
	c, err := client.New(issuer)
	if err != nil {
		return err
	}
	reg, err := c.RegisterAgent(client.AgentRegistration{
		Name:         "demo-delegated-agent",
		HostName:     "demo-host",
		Mode:         "delegated",
		Capabilities: []any{capName},
		Reason:       "Demo delegated journey",
	})
	if err != nil {
		return err
	}
	fmt.Printf("   agent_id=%s  status=%s\n", reg.AgentID, reg.Status)
	if reg.Status != "pending" {
		return fmt.Errorf("expected pending, got %s", reg.Status)
	}

	// 3. admin approves the grant — agent flips to active
	fmt.Println("3. admin approves grant")
	if err := admin.ApproveCapability(kcBase, realm, adminToken, reg.AgentID, capName); err != nil {
		return err
	}
	postApprove, err := c.GetAgentStatus()
	if err != nil {
		return err
	}
	fmt.Printf("   agent status=%s\n", postApprove)
	if postApprove != "active" {
		return fmt.Errorf("expected active after approve, got %s", postApprove)
	}

	// 4. execute hits the backend
	fmt.Println("4. execute via gateway")
	a := agent.New(c, reg.AgentID)
	result, err := a.InvokeTool(capName, map[string]any{"name": "delegated"})
	if err != nil {
		return err
	}
	greeting, err := extractGreeting(result)
	if err != nil {
		return err
	}
	fmt.Printf("   backend returned: \"%s\"\n", greeting)

	// 5. introspect reports active
	fmt.Println("5. introspect")
	intro1, err := c.IntrospectAgent()
	if err != nil {
		return err
	}
	fmt.Printf("   active=%v\n", intro1.Active)
	if !intro1.Active {
		return fmt.Errorf("expected active=true")
	}

	// 6. revoke
	fmt.Println("6. revoke")
	if err := c.RevokeAgent(); err != nil {
		return err
	}

	// 7. post-revoke execute is rejected
	fmt.Println("7. post-revoke execute (expected: rejected)")
	postExec, err := c.TryExecute(capName, map[string]any{"name": "delegated"})
	if err != nil {
		return err
	}
	fmt.Printf("   status=%d\n", postExec.Status)
	if postExec.Status == 200 {
		return fmt.Errorf("expected execute to fail after revoke")
	}

	// 8. post-revoke introspect reports inactive
	fmt.Println("8. post-revoke introspect (expected: active=false)")
	intro2, err := c.IntrospectAgent()
	if err != nil {
		return err
	}
	fmt.Printf("   active=%v\n", intro2.Active)
	if intro2.Active {
		return fmt.Errorf("expected active=false")
	}

	fmt.Println("delegated journey: OK")
	return nil
}

// extractGreeting walks the shape {"data": {"greeting": "..."}} returned by
// the resource server and, after gateway proxying, by Keycloak.
func extractGreeting(result any) (string, error) {
	asMap, ok := result.(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected execute response shape: %T", result)
	}
	data, ok := asMap["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("execute response missing data object: %v", asMap)
	}
	greeting, ok := data["greeting"].(string)
	if !ok {
		return "", fmt.Errorf("execute response missing greeting string: %v", data)
	}
	return greeting, nil
}

func main() {
	kcBase := envOr("KC_BASE", "http://localhost:28080")
	realm := envOr("KC_REALM", "master")
	adminUser := envOr("KC_ADMIN_USER", "admin")
	adminPass := envOr("KC_ADMIN_PASS", "admin")
	rsLocation := envOr("RS_LOCATION", "http://resource-server:3000/exec/greet")

	issuer := fmt.Sprintf("%s/realms/%s/agent-auth", kcBase, realm)

	fmt.Printf("[demo] Keycloak: %s\n", issuer)
	fmt.Printf("[demo] Resource Server (as seen by KC): %s\n", rsLocation)

	adminToken, err := admin.GetAdminToken(kcBase, realm, adminUser, adminPass)
	if err != nil {
		log.Printf("\n[demo] FAILED: %v", err)
		os.Exit(1)
	}

	if err := autonomousJourney(kcBase, realm, rsLocation, issuer, adminToken); err != nil {
		log.Printf("\n[demo] FAILED: %v", err)
		os.Exit(1)
	}
	if err := delegatedJourney(kcBase, realm, rsLocation, issuer, adminToken); err != nil {
		log.Printf("\n[demo] FAILED: %v", err)
		os.Exit(1)
	}

	fmt.Println("\nAll journeys: OK")
}
