// Package agent is a stub for the AI reasoning loop.
//
// Per AAP §2.1, an Agent is "a runtime AI actor scoped to a specific
// conversation, task, or session, that calls external services."
//
// Importantly, the Agent:
//   - does NOT hold the host keypair (the Client does)
//   - does NOT talk to the auth server directly (the Client does)
//   - does NOT sign any JWTs (the Client does)
//   - asks the Client to do things on its behalf via tool calls
//
// In a real system the Agent is an LLM (Claude, GPT-4, Llama…) reasoning
// inside an AI tool (Claude Code, ChatGPT, etc.). The reasoning loop decides
// what tool to call; the AI tool forwards the call to the Client. This type
// is a stub that stands in for that whole stack in one method.
package agent

import (
	"encoding/json"
	"fmt"

	"github.com/chh/keycloak-agent-auth/examples/go/internal/client"
)

// Agent is a thin wrapper around a Client that prints tool invocations and
// forwards them through the Client for execution.
type Agent struct {
	client *client.Client
	ID     string
}

// New wires an Agent to its owning Client.
func New(c *client.Client, id string) *Agent {
	return &Agent{client: c, ID: id}
}

// InvokeTool is the demo stand-in for "the LLM decides to invoke a tool".
// In the real world this is the output of a reasoning step; here it's a
// direct method call for demonstration.
func (a *Agent) InvokeTool(capability string, args any) (any, error) {
	argsJSON, _ := json.Marshal(args)
	short := a.ID
	if len(short) > 8 {
		short = short[:8]
	}
	fmt.Printf("[Agent %s…] invoke %s(%s)\n", short, capability, string(argsJSON))
	return a.client.ExecuteViaGateway(capability, args)
}
