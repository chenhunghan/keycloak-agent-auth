"""The Agent  a runtime AI actor.

Per AAP 2.1, an Agent is "a runtime AI actor scoped to a specific
conversation, task, or session, that calls external services."

Importantly, the Agent:
  - does NOT hold the host keypair (the Client does)
  - does NOT talk to the auth server directly (the Client does)
  - does NOT sign any JWTs (the Client does)
  - asks the Client to do things on its behalf via tool calls

In a real system the Agent is an LLM (Claude, GPT-4, Llama) reasoning
inside an AI tool (Claude Code, ChatGPT, etc.). The reasoning loop decides
what tool to call; the AI tool forwards the call to the Client. This class
is a stub that stands in for that whole stack in one method.
"""

from __future__ import annotations

import json
from typing import Any

from .client import Client


class Agent:
    def __init__(self, client: Client, agent_id: str) -> None:
        self._client = client
        self.id = agent_id

    def invoke_tool(self, capability: str, args: Any) -> Any:
        """"The LLM decides to invoke a tool."

        In the real world this is the output of a reasoning step; here it's
        a direct method call for demonstration.
        """
        print(
            f"[Agent {self.id[:8]}] invoke {capability}({json.dumps(args)})"
        )
        return self._client.execute_via_gateway(capability, args)
