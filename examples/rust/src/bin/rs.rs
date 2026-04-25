//! Standalone resource-server binary used by the docker compose service.

use std::collections::HashMap;

use aap_demo::rs::{Handler, ResourceServer};
use anyhow::Result;
use serde_json::{json, Value};

#[tokio::main]
async fn main() -> Result<()> {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    let mut handlers: HashMap<String, Handler> = HashMap::new();
    handlers.insert(
        "/exec/greet".into(),
        Box::new(|args: &Value| {
            let name = args
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("world")
                .to_string();
            json!({ "greeting": format!("Hello, {name}!") })
        }),
    );

    ResourceServer::new(handlers).serve(port).await
}
