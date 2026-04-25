//! End-to-end demo: walks both AAP journeys against a live Keycloak.
//!
//! Mirrors `AgentAuthFullJourneyE2E.java` from the main test suite, from
//! the client side. Run with `cargo run --bin demo` after
//! `docker compose up -d` from this directory.

use aap_demo::admin::{approve_capability, get_admin_token, register_capability};
use aap_demo::agent::Agent;
use aap_demo::client::{AgentRegistration, Client};
use anyhow::{anyhow, Result};
use rand::Rng;
use reqwest::Client as HttpClient;
use serde_json::{json, Value};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn unique_suffix() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 4] = rng.gen();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let kc_base = env_or("KC_BASE", "http://localhost:28080");
    let realm = env_or("KC_REALM", "master");
    let admin_user = env_or("KC_ADMIN_USER", "admin");
    let admin_pass = env_or("KC_ADMIN_PASS", "admin");
    let rs_location = env_or("RS_LOCATION", "http://resource-server:3000/exec/greet");
    let issuer = format!("{kc_base}/realms/{realm}/agent-auth");

    println!("[demo] Keycloak: {issuer}");
    println!("[demo] Resource Server (as seen by KC): {rs_location}");

    let http = HttpClient::new();
    let admin_token = get_admin_token(&http, &kc_base, &realm, &admin_user, &admin_pass).await?;

    autonomous_journey(&http, &kc_base, &realm, &admin_token, &issuer, &rs_location).await?;
    delegated_journey(&http, &kc_base, &realm, &admin_token, &issuer, &rs_location).await?;

    println!("\nAll journeys: OK");
    Ok(())
}

async fn autonomous_journey(
    http: &HttpClient,
    kc_base: &str,
    realm: &str,
    admin_token: &str,
    issuer: &str,
    rs_location: &str,
) -> Result<()> {
    let cap = format!("greet_autonomous_{}", unique_suffix());
    println!("\n=== autonomous journey (capability: {cap}) ===");

    println!("1. admin registers capability (requires_approval=false)");
    register_capability(
        http,
        kc_base,
        realm,
        admin_token,
        &capability_def(&cap, false, rs_location),
    )
    .await?;

    println!("2. agent registers (mode=autonomous)");
    let mut client = Client::new(issuer).await?;
    let reg = client
        .register_agent(&AgentRegistration {
            name: "demo-autonomous-agent".into(),
            host_name: Some("demo-host".into()),
            mode: "autonomous".into(),
            capabilities: vec![Value::String(cap.clone())],
            reason: Some("Demo autonomous journey".into()),
        })
        .await?;
    println!("   agent_id={}  status={}", reg.agent_id, reg.status);
    if reg.status != "active" {
        return Err(anyhow!("expected active, got {}", reg.status));
    }

    println!("3. execute via gateway");
    let agent = Agent::new(&client, reg.agent_id.clone());
    let result = agent
        .invoke_tool(&cap, &json!({ "name": "autonomous" }))
        .await?;
    let greeting = result["data"]["greeting"].as_str().unwrap_or("?");
    println!("   backend returned: \"{greeting}\"");

    println!("4. introspect");
    let intro1 = client.introspect_agent().await?;
    println!("   active={}", intro1.active);
    if !intro1.active {
        return Err(anyhow!("expected active=true"));
    }

    println!("5. revoke");
    client.revoke_agent().await?;

    println!("6. post-revoke execute (expected: rejected)");
    let post_exec = client
        .try_execute(&cap, &json!({ "name": "autonomous" }))
        .await?;
    println!("   status={}", post_exec.status);
    if post_exec.status == 200 {
        return Err(anyhow!("expected execute to fail after revoke"));
    }

    println!("7. post-revoke introspect (expected: active=false)");
    let intro2 = client.introspect_agent().await?;
    println!("   active={}", intro2.active);
    if intro2.active {
        return Err(anyhow!("expected active=false"));
    }

    println!("autonomous journey: OK");
    Ok(())
}

async fn delegated_journey(
    http: &HttpClient,
    kc_base: &str,
    realm: &str,
    admin_token: &str,
    issuer: &str,
    rs_location: &str,
) -> Result<()> {
    let cap = format!("greet_delegated_{}", unique_suffix());
    println!("\n=== delegated journey (capability: {cap}) ===");

    println!("1. admin registers capability (requires_approval=true)");
    register_capability(
        http,
        kc_base,
        realm,
        admin_token,
        &capability_def(&cap, true, rs_location),
    )
    .await?;

    println!("2. agent registers (mode=delegated) → expect pending");
    let mut client = Client::new(issuer).await?;
    let reg = client
        .register_agent(&AgentRegistration {
            name: "demo-delegated-agent".into(),
            host_name: Some("demo-host".into()),
            mode: "delegated".into(),
            capabilities: vec![Value::String(cap.clone())],
            reason: Some("Demo delegated journey".into()),
        })
        .await?;
    println!("   agent_id={}  status={}", reg.agent_id, reg.status);
    if reg.status != "pending" {
        return Err(anyhow!("expected pending, got {}", reg.status));
    }

    println!("3. admin approves grant");
    approve_capability(http, kc_base, realm, admin_token, &reg.agent_id, &cap).await?;
    let post_approve = client.get_agent_status().await?;
    println!("   agent status={post_approve}");
    if post_approve != "active" {
        return Err(anyhow!("expected active after approve, got {post_approve}"));
    }

    println!("4. execute via gateway");
    let agent = Agent::new(&client, reg.agent_id.clone());
    let result = agent
        .invoke_tool(&cap, &json!({ "name": "delegated" }))
        .await?;
    let greeting = result["data"]["greeting"].as_str().unwrap_or("?");
    println!("   backend returned: \"{greeting}\"");

    println!("5. introspect");
    let intro1 = client.introspect_agent().await?;
    println!("   active={}", intro1.active);
    if !intro1.active {
        return Err(anyhow!("expected active=true"));
    }

    println!("6. revoke");
    client.revoke_agent().await?;

    println!("7. post-revoke execute (expected: rejected)");
    let post_exec = client
        .try_execute(&cap, &json!({ "name": "delegated" }))
        .await?;
    println!("   status={}", post_exec.status);
    if post_exec.status == 200 {
        return Err(anyhow!("expected execute to fail after revoke"));
    }

    println!("8. post-revoke introspect (expected: active=false)");
    let intro2 = client.introspect_agent().await?;
    println!("   active={}", intro2.active);
    if intro2.active {
        return Err(anyhow!("expected active=false"));
    }

    println!("delegated journey: OK");
    Ok(())
}

fn capability_def(name: &str, requires_approval: bool, location: &str) -> Value {
    json!({
        "name": name,
        "description": "Demo greet",
        "visibility": "authenticated",
        "requires_approval": requires_approval,
        "location": location,
        "input": { "type": "object", "properties": { "name": { "type": "string" } } },
        "output": { "type": "object" },
    })
}
