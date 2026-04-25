//! Admin-plane helpers. Uses Keycloak's OIDC password grant to fetch an admin
//! token, then calls the extension's admin API to register a capability and
//! approve pending grants. Not part of the Agent Auth Protocol flow itself —
//! these are deployment-time setup steps a service operator does once.

use anyhow::{anyhow, Context, Result};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

pub async fn get_admin_token(
    http: &HttpClient,
    kc_base: &str,
    realm: &str,
    username: &str,
    password: &str,
) -> Result<String> {
    let url = format!("{kc_base}/realms/{realm}/protocol/openid-connect/token");
    let form = [
        ("grant_type", "password"),
        ("client_id", "admin-cli"),
        ("username", username),
        ("password", password),
    ];
    let resp = http
        .post(&url)
        .form(&form)
        .send()
        .await
        .context("POST token endpoint")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("admin token failed: {status} {body}"));
    }
    let body: TokenResponse = resp.json().await.context("parse token response")?;
    Ok(body.access_token)
}

/// Register a capability. Returns `true` if newly created, `false` if it
/// already existed (server returned 409, treated as idempotent).
pub async fn register_capability(
    http: &HttpClient,
    kc_base: &str,
    realm: &str,
    admin_token: &str,
    capability: &Value,
) -> Result<bool> {
    let url = format!("{kc_base}/admin/realms/{realm}/agent-auth/capabilities");
    let resp = http
        .post(&url)
        .bearer_auth(admin_token)
        .json(capability)
        .send()
        .await
        .context("POST /capabilities")?;
    if resp.status().as_u16() == 409 {
        return Ok(false);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("register capability failed: {status} {body}"));
    }
    Ok(true)
}

pub async fn approve_capability(
    http: &HttpClient,
    kc_base: &str,
    realm: &str,
    admin_token: &str,
    agent_id: &str,
    capability: &str,
) -> Result<()> {
    let url = format!(
        "{kc_base}/admin/realms/{realm}/agent-auth/agents/{agent_id}/capabilities/{capability}/approve"
    );
    let resp = http
        .post(&url)
        .bearer_auth(admin_token)
        .send()
        .await
        .context("POST /approve")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("approve failed: {status} {body}"));
    }
    Ok(())
}
