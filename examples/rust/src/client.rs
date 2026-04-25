//! The **Client** — a broker process.
//!
//! Per AAP §1.5/§1.6, the Client is "the process that holds a host identity
//! and exposes protocol tools to AI systems (MCP server, CLI, SDK). It
//! manages host and agent keys, talks to servers, and signs JWTs."
//!
//! In this demo the Client:
//!   - generates an in-memory Ed25519 keypair (the Host identity)
//!   - generates a second Ed25519 keypair per Agent registered under it
//!   - mints host+jwt (§4.2) for host-scoped ops (register, revoke, introspect)
//!   - mints agent+jwt (§4.3) for /capability/execute (gateway mode)
//!
//! A production Client would persist the host key (OS keychain, secrets
//! manager, disk with correct permissions) so the Host identity survives
//! restarts.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// An Ed25519 keypair. The `SigningKey` already exposes the verifying key,
/// but we keep the public key bytes pre-split for easy JWK export.
struct Ed25519KeyPair {
    signing: SigningKey,
    public_bytes: [u8; 32],
    /// PKCS#8 DER encoding of the private key, required by `jsonwebtoken`'s
    /// `EncodingKey::from_ed_der`.
    pkcs8_der: Vec<u8>,
}

impl Ed25519KeyPair {
    fn generate() -> Result<Self> {
        let signing = SigningKey::generate(&mut OsRng);
        let public_bytes = signing.verifying_key().to_bytes();
        let pkcs8_der = signing
            .to_pkcs8_der()
            .context("pkcs8 encode ed25519 private key")?
            .as_bytes()
            .to_vec();
        Ok(Self {
            signing,
            public_bytes,
            pkcs8_der,
        })
    }

    /// Public key as a JWK (RFC 8037).
    fn public_jwk(&self) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(self.public_bytes),
        })
    }

    /// RFC 7638 thumbprint of the public key.
    ///
    /// Canonical JSON of `{"crv":"Ed25519","kty":"OKP","x":"..."}` (keys
    /// in lex order, no whitespace), SHA-256, base64url-encode (no padding).
    fn thumbprint(&self) -> String {
        let x = URL_SAFE_NO_PAD.encode(self.public_bytes);
        // Keys must be in lex order: crv, kty, x.
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
        let digest = Sha256::digest(canonical.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    fn encoding_key(&self) -> Result<EncodingKey> {
        // `from_ed_der` consumes a PKCS#8-wrapped Ed25519 private key.
        Ok(EncodingKey::from_ed_der(&self.pkcs8_der))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentRegistration {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    pub mode: String,
    pub capabilities: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AgentRegistrationResponse {
    pub agent_id: String,
    pub status: String,
    #[serde(default)]
    pub approval: Option<Value>,
    #[serde(default)]
    pub agent_capability_grants: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub agent_capability_grants: Option<Value>,
}

#[derive(Debug)]
pub struct ExecuteAttempt {
    pub status: u16,
    pub body: Value,
}

/// The Client. Holds the host keypair and (once `register_agent` is called)
/// an agent keypair + id. See module docs.
pub struct Client {
    issuer_url: String,
    host_key: Ed25519KeyPair,
    agent_key: Option<Ed25519KeyPair>,
    agent_id: Option<String>,
    http: reqwest::Client,
}

impl Client {
    /// Generate an in-memory host key and return a Client ready to register
    /// an agent against `issuer_url`.
    pub async fn new(issuer_url: impl Into<String>) -> Result<Self> {
        let host_key = Ed25519KeyPair::generate()?;
        Ok(Self {
            issuer_url: issuer_url.into(),
            host_key,
            agent_key: None,
            agent_id: None,
            http: reqwest::Client::new(),
        })
    }

    /// Register a new Agent under this Host. Returns the full response.
    pub async fn register_agent(
        &mut self,
        req: &AgentRegistration,
    ) -> Result<AgentRegistrationResponse> {
        let agent_key = Ed25519KeyPair::generate()?;
        self.agent_key = Some(agent_key);
        let host_jwt = self.mint_host_jwt_for_registration()?;

        let url = format!("{}/agent/register", self.issuer_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&host_jwt)
            .json(req)
            .send()
            .await
            .context("POST /agent/register")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!(
                "POST /agent/register failed: {} {}",
                status.as_u16(),
                text
            ));
        }
        let body: AgentRegistrationResponse = serde_json::from_str(&text)
            .with_context(|| format!("parse /agent/register body: {text}"))?;
        self.agent_id = Some(body.agent_id.clone());
        Ok(body)
    }

    /// `GET /agent/status?agent_id=…` — returns the current status string.
    pub async fn get_agent_status(&self) -> Result<String> {
        let agent_id = self
            .agent_id
            .as_ref()
            .ok_or_else(|| anyhow!("no agent registered"))?;
        let host_jwt = self.mint_host_jwt_for_op()?;
        let url = format!("{}/agent/status?agent_id={agent_id}", self.issuer_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&host_jwt)
            .send()
            .await
            .context("GET /agent/status")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!(
                "GET /agent/status failed: {} {}",
                status.as_u16(),
                text
            ));
        }
        #[derive(Deserialize)]
        struct StatusBody {
            status: String,
        }
        let parsed: StatusBody = serde_json::from_str(&text)
            .with_context(|| format!("parse /agent/status body: {text}"))?;
        Ok(parsed.status)
    }

    /// Execute a capability in gateway mode. Throws on non-2xx (for
    /// happy-path callers). Use `try_execute` to inspect a possibly-failing
    /// response (e.g. post-revocation).
    pub async fn execute_via_gateway(&self, capability: &str, arguments: &Value) -> Result<Value> {
        let attempt = self.try_execute(capability, arguments).await?;
        if !(200..300).contains(&attempt.status) {
            return Err(anyhow!(
                "POST /capability/execute failed: {} {}",
                attempt.status,
                attempt.body
            ));
        }
        Ok(attempt.body)
    }

    /// Like `execute_via_gateway` but surfaces the status code instead of
    /// throwing.
    pub async fn try_execute(&self, capability: &str, arguments: &Value) -> Result<ExecuteAttempt> {
        if self.agent_key.is_none() || self.agent_id.is_none() {
            return Err(anyhow!("no agent registered"));
        }
        let execute_url = format!("{}/capability/execute", self.issuer_url);
        let agent_jwt = self.mint_agent_jwt(&execute_url)?;
        let body = json!({
            "capability": capability,
            "arguments": arguments,
        });
        let resp = self
            .http
            .post(&execute_url)
            .bearer_auth(&agent_jwt)
            .json(&body)
            .send()
            .await
            .context("POST /capability/execute")?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let body: Value = serde_json::from_str(&text).unwrap_or_else(|_| Value::String(text));
        Ok(ExecuteAttempt { status, body })
    }

    /// `POST /agent/introspect` — asks Keycloak to validate the current
    /// agent's JWT. Returns `{ active: true, … }` or `{ active: false }`.
    pub async fn introspect_agent(&self) -> Result<IntrospectResponse> {
        if self.agent_key.is_none() || self.agent_id.is_none() {
            return Err(anyhow!("no agent registered"));
        }
        let agent_jwt = self.mint_agent_jwt(&self.issuer_url)?;
        let host_jwt = self.mint_host_jwt_for_op()?;
        let url = format!("{}/agent/introspect", self.issuer_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&host_jwt)
            .json(&json!({ "token": agent_jwt }))
            .send()
            .await
            .context("POST /agent/introspect")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!(
                "POST /agent/introspect failed: {} {}",
                status.as_u16(),
                text
            ));
        }
        let parsed: IntrospectResponse = serde_json::from_str(&text)
            .with_context(|| format!("parse /agent/introspect body: {text}"))?;
        Ok(parsed)
    }

    /// `POST /agent/revoke` — permanently terminates the current agent.
    pub async fn revoke_agent(&self) -> Result<()> {
        let agent_id = self
            .agent_id
            .as_ref()
            .ok_or_else(|| anyhow!("no agent registered"))?;
        let host_jwt = self.mint_host_jwt_for_op()?;
        let url = format!("{}/agent/revoke", self.issuer_url);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&host_jwt)
            .json(&json!({ "agent_id": agent_id }))
            .send()
            .await
            .context("POST /agent/revoke")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(anyhow!(
                "POST /agent/revoke failed: {} {}",
                status.as_u16(),
                text
            ));
        }
        Ok(())
    }

    /// Current agent id (None until `register_agent` is called).
    pub fn current_agent_id(&self) -> Option<&str> {
        self.agent_id.as_deref()
    }

    // ---------- JWT minting ----------

    /// `host+jwt` for `POST /agent/register` — includes `agent_public_key`. (§4.2)
    fn mint_host_jwt_for_registration(&self) -> Result<String> {
        let agent_key = self
            .agent_key
            .as_ref()
            .ok_or_else(|| anyhow!("agent key not prepared"))?;
        let host_pub = self.host_key.public_jwk();
        let agent_pub = agent_key.public_jwk();
        let iss = self.host_key.thumbprint();

        let now = now_secs();
        let claims = json!({
            "iss": iss,
            "aud": self.issuer_url,
            "iat": now,
            "exp": now + 60,
            "jti": format!("h-{}", Uuid::new_v4()),
            "host_public_key": host_pub,
            "agent_public_key": agent_pub,
        });

        sign_jwt(&claims, "host+jwt", &self.host_key.encoding_key()?)
    }

    /// `host+jwt` for non-registration host ops (status, revoke, introspect). (§4.2)
    fn mint_host_jwt_for_op(&self) -> Result<String> {
        let host_pub = self.host_key.public_jwk();
        let iss = self.host_key.thumbprint();
        let now = now_secs();
        let claims = json!({
            "iss": iss,
            "aud": self.issuer_url,
            "iat": now,
            "exp": now + 60,
            "jti": format!("h-{}", Uuid::new_v4()),
            "host_public_key": host_pub,
        });
        sign_jwt(&claims, "host+jwt", &self.host_key.encoding_key()?)
    }

    /// `agent+jwt` per §4.3, signed with the agent private key.
    fn mint_agent_jwt(&self, aud: &str) -> Result<String> {
        let agent_key = self
            .agent_key
            .as_ref()
            .ok_or_else(|| anyhow!("agent key not set"))?;
        let agent_id = self
            .agent_id
            .as_ref()
            .ok_or_else(|| anyhow!("agent id not set"))?;
        let iss = self.host_key.thumbprint();
        let now = now_secs();
        let claims = json!({
            "iss": iss,
            "sub": agent_id,
            "aud": aud,
            "iat": now,
            "exp": now + 60,
            "jti": format!("a-{}", Uuid::new_v4()),
        });
        sign_jwt(&claims, "agent+jwt", &agent_key.encoding_key()?)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs()
}

/// Sign a JSON claim-set as an EdDSA JWT with the given `typ` header.
fn sign_jwt(claims: &Value, typ: &str, key: &EncodingKey) -> Result<String> {
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(typ.to_string());
    encode(&header, claims, key).context("jwt encode")
}
