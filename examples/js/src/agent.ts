import type { Client } from "./client.js";

/**
 * The **Agent** — a runtime AI actor.
 *
 * Per AAP §2.1, an Agent is "a runtime AI actor scoped to a specific
 * conversation, task, or session, that calls external services."
 *
 * Importantly, the Agent:
 *   - does NOT hold the host keypair (the Client does)
 *   - does NOT talk to the auth server directly (the Client does)
 *   - does NOT sign any JWTs (the Client does)
 *   - asks the Client to do things on its behalf via tool calls
 *
 * In a real system the Agent is an LLM (Claude, GPT-4, Llama…) reasoning
 * inside an AI tool (Claude Code, ChatGPT, etc.). The reasoning loop decides
 * what tool to call; the AI tool forwards the call to the Client. This class
 * is a stub that stands in for that whole stack in one method.
 */
export class Agent {
  constructor(
    private readonly client: Client,
    readonly id: string,
  ) {}

  /**
   * "The LLM decides to invoke a tool." In the real world this is the output
   * of a reasoning step; here it's a direct method call for demonstration.
   */
  async invokeTool(capability: string, args: unknown): Promise<unknown> {
    console.log(
      `[Agent ${this.id.slice(0, 8)}…] invoke ${capability}(${JSON.stringify(args)})`,
    );
    return await this.client.executeViaGateway(capability, args);
  }
}
