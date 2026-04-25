//! The **Agent** — a runtime AI actor.
//!
//! Per AAP §2.1, an Agent is "a runtime AI actor scoped to a specific
//! conversation, task, or session, that calls external services."
//!
//! Importantly, the Agent:
//!   - does NOT hold the host keypair (the Client does)
//!   - does NOT talk to the auth server directly (the Client does)
//!   - does NOT sign any JWTs (the Client does)
//!   - asks the Client to do things on its behalf via tool calls
//!
//! In a real system the Agent is an LLM (Claude, GPT-4, Llama…) reasoning
//! inside an AI tool (Claude Code, ChatGPT, etc.). The reasoning loop
//! decides what tool to call; the AI tool forwards the call to the Client.
//! This struct is a stub that stands in for that whole stack in one method.

use anyhow::Result;
use serde_json::Value;

use crate::client::Client;

pub struct Agent<'c> {
    client: &'c Client,
    pub id: String,
}

impl<'c> Agent<'c> {
    pub fn new(client: &'c Client, id: impl Into<String>) -> Self {
        Self {
            client,
            id: id.into(),
        }
    }

    /// "The LLM decides to invoke a tool." In the real world this is the
    /// output of a reasoning step; here it's a direct method call for
    /// demonstration.
    pub async fn invoke_tool(&self, capability: &str, arguments: &Value) -> Result<Value> {
        let short = self.id.chars().take(8).collect::<String>();
        println!(
            "[Agent {short}…] invoke {capability}({})",
            serde_json::to_string(arguments).unwrap_or_else(|_| "<unserializable>".into())
        );
        self.client.execute_via_gateway(capability, arguments).await
    }
}
