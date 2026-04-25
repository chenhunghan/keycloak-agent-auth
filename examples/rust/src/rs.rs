//! The **Resource Server** core — where capability business logic runs.
//!
//! In gateway mode (what this demo uses), Keycloak validates the agent+jwt,
//! runs constraint checks, then proxies to this server. We just execute
//! and return `{"data": {...}}` per AAP §5.11 sync response shape.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

pub type Handler = Box<dyn Fn(&Value) -> Value + Send + Sync>;

pub struct ResourceServer {
    handlers: Arc<HashMap<String, Handler>>,
}

impl ResourceServer {
    pub fn new(handlers: HashMap<String, Handler>) -> Self {
        Self {
            handlers: Arc::new(handlers),
        }
    }

    /// Bind on `0.0.0.0:port` and serve forever.
    pub async fn serve(self, port: u16) -> Result<()> {
        let addr: SocketAddr = ([0, 0, 0, 0], port).into();
        let listener = TcpListener::bind(addr).await?;
        println!("[resource-server] listening on :{port}");

        loop {
            let (stream, _) = listener.accept().await?;
            let handlers = self.handlers.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| handle(req, handlers.clone()));
                if let Err(e) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await
                {
                    eprintln!("[resource-server] connection error: {e}");
                }
            });
        }
    }
}

async fn handle(
    req: Request<Incoming>,
    handlers: Arc<HashMap<String, Handler>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::POST {
        return Ok(empty(StatusCode::METHOD_NOT_ALLOWED));
    }
    let path = req.uri().path().to_string();
    let handler = match handlers.get(&path) {
        Some(h) => h,
        None => {
            return Ok(json_response(
                StatusCode::NOT_FOUND,
                &json!({"error": "not_found", "path": path}),
            ));
        }
    };

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Ok(empty(StatusCode::BAD_REQUEST)),
    };
    let parsed: Value = if body_bytes.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&body_bytes) {
            Ok(v) => v,
            Err(_) => return Ok(empty(StatusCode::BAD_REQUEST)),
        }
    };
    let args = parsed
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    println!(
        "[resource-server] {path}  args={}",
        serde_json::to_string(&args).unwrap_or_default()
    );
    let data = handler(&args);
    Ok(json_response(StatusCode::OK, &json!({"data": data})))
}

fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}
