//! A per-run inference boundary. The agent has no network: it asks over its
//! pipes. Only the configured local model and a few read-only probes are served.

use patchriot_protocol::websites::WebsiteSnapshot;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr, time::Duration};
use tokio::sync::mpsc;

pub const MAX_REQUEST: usize = 65_536;
pub const MAX_RESPONSE: usize = 262_144;
pub const MAX_TOKENS: u64 = 192;

/// Operational counters only. Never interpolate model text, errors or IDs into
/// logs: even a provider's finish reason is untrusted, possibly private text.
#[derive(Debug)]
struct ResponseStats {
    finish: &'static str,
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
}

impl ResponseStats {
    fn read(bytes: &[u8], streaming: bool) -> Self {
        let mut stats = Self {
            finish: "not_reported",
            prompt_tokens: None,
            completion_tokens: None,
        };
        if streaming {
            // Parse after the bounded stream finishes so HTTP chunks and UTF-8
            // boundaries cannot split a data line. No response is written to disk.
            for line in bytes.split(|&b| b == b'\n') {
                if let Some(data) = line.strip_prefix(b"data:")
                    && let Ok(value) = serde_json::from_slice(data)
                {
                    stats.observe(&value);
                }
            }
        } else if let Ok(value) = serde_json::from_slice(bytes) {
            stats.observe(&value);
        }
        stats
    }

    fn observe(&mut self, value: &Value) {
        if let Some(reason) = value["choices"][0]["finish_reason"].as_str() {
            self.finish = match reason {
                "stop" => "stop",
                "length" => "length",
                "tool_calls" => "tool_calls",
                "content_filter" => "content_filter",
                "function_call" => "function_call",
                _ => "other",
            };
        }
        if value["usage"].is_object() {
            self.prompt_tokens = value["usage"]["prompt_tokens"].as_u64();
            self.completion_tokens = value["usage"]["completion_tokens"].as_u64();
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: u64,
    pub method: String,
    pub path: String,
    pub body: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Start {
        id: u64,
        status: u16,
        content_type: &'static str,
    },
    Chunk {
        id: u64,
        hex: String,
    },
    End {
        id: u64,
    },
    Failed {
        id: u64,
        reason: &'static str,
    },
}

#[derive(Clone)]
pub struct Broker {
    client: reqwest::Client,
    origin: String,
    model: String,
    show: Value,
    tags: Value,
    version: Value,
    max_tokens: u64,
    response_format: Option<Value>,
    source_only: bool,
}

/// Generation guidance, not evidence validation. A model can produce this shape
/// with invented claims or quotations; the normal result checks still apply.
fn website_response_format(snapshot: &WebsiteSnapshot) -> Value {
    // The model selects a captured resource instead of inventing or copying a
    // 64-character identifier. Only hashes enter the schema, never target text
    // or earlier agents' claims. Exact quote/source checks remain authoritative.
    let resource_hashes: BTreeSet<_> = std::iter::once(&snapshot.homepage)
        .chain(&snapshot.resources)
        .map(|resource| resource.sha256.as_str())
        .collect();
    static_response_format(resource_hashes)
}
fn static_response_format(resource_hashes: BTreeSet<&str>) -> Value {
    json!({
        "type": "json_schema",
        "json_schema": {
            "name": "website_assessment",
            "strict": true,
            "schema": {
                "type": "object", "additionalProperties": false,
                "required": ["summary", "findings", "limitations"],
                "properties": {
                    "summary": {"type": "string"},
                    "findings": {
                        "type": "array", "maxItems": 1,
                        "items": {
                            "type": "object", "additionalProperties": false,
                            "required": ["title", "support", "explanation", "suggested_action", "citations"],
                            "properties": {
                                "title": {"type": "string"},
                                "support": {"type": "string", "enum": ["observed_in_snapshot", "needs_live_test", "not_supported"]},
                                "explanation": {"type": "string"},
                                "suggested_action": {"type": "string"},
                                "citations": {
                                    "type": "array", "minItems": 1, "maxItems": 3,
                                    "items": {
                                        "type": "object", "additionalProperties": false,
                                        "required": ["resource_sha256", "quote"],
                                        "properties": {
                                            "resource_sha256": {"type": "string", "enum": resource_hashes},
                                            "quote": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "limitations": {"type": "array", "minItems": 1, "maxItems": 5, "items": {"type": "string"}}
                }
            }
        }
    })
}

pub fn origin(value: &str) -> Result<String, &'static str> {
    let url = url::Url::parse(value).map_err(|_| "invalid local model URL")?;
    let local = url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| match ip {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
            IpAddr::V6(ip) => ip.is_loopback(),
        });
    if !local
        || url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "model URL must be HTTP at an explicit loopback or private IPv4 address, without credentials or a path",
        );
    }
    Ok(url.origin().ascii_serialization())
}

fn model_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

async fn bounded_json(mut response: reqwest::Response) -> Result<Value, &'static str> {
    if !response.status().is_success() {
        return Err("model metadata unavailable");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "model metadata interrupted")?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE {
            return Err("model metadata exceeds limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid model metadata")
}

impl Broker {
    /// Website reports use a fixed format and need more space than the
    /// two-sentence example. The runtime cannot change the schema or ceiling.
    pub fn for_website_review(mut self, snapshot: &WebsiteSnapshot) -> Self {
        self.max_tokens = 512;
        self.response_format = Some(website_response_format(snapshot));
        self
    }

    pub fn for_source_review(mut self, bundle: &patchriot_protocol::sources::SourceBundle) -> Self {
        self.max_tokens = 512;
        self.source_only = true;
        self.response_format = Some(static_response_format(
            bundle.files.iter().map(|f| f.sha256.as_str()).collect(),
        ));
        self
    }

    pub fn max_tokens(&self) -> u64 {
        self.max_tokens
    }
    /// A serving profile may retain the original model name as its parent.
    /// This catches accidental configuration swaps, not a dishonest model server.
    pub fn matches_declaration(&self, declared: &str) -> bool {
        self.model == declared || self.show["details"]["parent_model"].as_str() == Some(declared)
    }

    pub async fn connect(
        url: &str,
        model: &str,
        digest: &str,
        attempt_seconds: u64,
    ) -> Result<Self, &'static str> {
        if !(patchriot_protocol::DEFAULT_AGENT_ATTEMPT_SECONDS
            ..=patchriot_protocol::MAX_AGENT_ATTEMPT_SECONDS)
            .contains(&attempt_seconds)
        {
            return Err("model timeout must fit the configured agent attempt limit");
        }
        let origin = origin(url)?;
        if !model_name(model)
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid model name or expected SHA-256 digest");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(
                attempt_seconds - patchriot_protocol::AGENT_CLEANUP_SECONDS,
            ))
            .build()
            .map_err(|_| "model client unavailable")?;
        let tags = bounded_json(
            client
                .get(format!("{origin}/api/tags"))
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .map_err(|_| "local model server unavailable")?,
        )
        .await?;
        let tag = tags["models"]
            .as_array()
            .and_then(|v| {
                v.iter()
                    .find(|v| v["name"] == model && v["digest"] == digest)
            })
            .ok_or("installed model does not match the configured name and digest")?
            .clone();
        let show = bounded_json(
            client
                .post(format!("{origin}/api/show"))
                .timeout(Duration::from_secs(5))
                .json(&json!({"model":model}))
                .send()
                .await
                .map_err(|_| "model details unavailable")?,
        )
        .await?;
        let advertised_context = show["model_info"]["general.architecture"]
            .as_str()
            .and_then(|architecture| {
                show["model_info"][format!("{architecture}.context_length")].as_u64()
            });
        if advertised_context.is_none_or(|size| size < 64_000)
            || !show["capabilities"]
                .as_array()
                .is_some_and(|values| values.iter().any(|v| v == "tools"))
        {
            return Err("model must advertise tool support and at least 64000 tokens of context");
        }
        // The compatible API ignores request-level num_ctx. Require the actual
        // model profile to carry the tested serving window; do not forge metadata.
        if !show["parameters"].as_str().is_some_and(|s| {
            s.lines()
                .any(|line| line.split_whitespace().collect::<Vec<_>>() == ["num_ctx", "64000"])
        }) {
            return Err("model profile must set num_ctx to 64000 before running this pilot");
        }
        let version = bounded_json(
            client
                .get(format!("{origin}/api/version"))
                .timeout(Duration::from_secs(5))
                .send()
                .await
                .map_err(|_| "model version unavailable")?,
        )
        .await?;
        Ok(Self {
            client,
            origin,
            model: model.into(),
            show: json!({"model_info":show["model_info"],"parameters":show["parameters"],"capabilities":show["capabilities"],"details":show["details"]}),
            tags: json!({"models":[tag]}),
            version: json!({"version":version["version"]}),
            max_tokens: MAX_TOKENS,
            response_format: None,
            source_only: false,
        })
    }

    fn metadata(&self, request: &Request) -> Result<Value, u16> {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/api/version") if request.body.is_none() => Ok(self.version.clone()),
            ("GET", "/api/tags") if request.body.is_none() => Ok(self.tags.clone()),
            ("GET", "/v1/models") if request.body.is_none() => Ok(
                json!({"object":"list","data":[{"id":self.model,"object":"model","owned_by":"local","context_length":64000}]}),
            ),
            ("POST", "/api/show") => {
                let body = request
                    .body
                    .as_ref()
                    .and_then(Value::as_object)
                    .ok_or(400u16)?;
                if !body
                    .keys()
                    .all(|k| ["model", "name", "verbose"].contains(&k.as_str()))
                    || body.get("verbose").is_some_and(|v| v != false)
                    || !(body.get("model").or_else(|| body.get("name")) == Some(&json!(self.model)))
                    || body.get("model").is_some_and(|v| v != &self.model)
                    || body.get("name").is_some_and(|v| v != &self.model)
                {
                    return Err(400);
                }
                Ok(self.show.clone())
            }
            _ => Err(404),
        }
    }

    pub fn chat(&self, request: &Request) -> Result<Value, &'static str> {
        if request.method != "POST" || request.path != "/v1/chat/completions" {
            return Err("unsupported route");
        }
        let mut body = request
            .body
            .as_ref()
            .and_then(Value::as_object)
            .cloned()
            .ok_or("expected chat object")?;
        if !body.keys().all(|k| {
            [
                "model",
                "messages",
                "tools",
                "tool_choice",
                "max_tokens",
                "stream",
                "stream_options",
                "reasoning_effort",
                "temperature",
                "top_p",
                "options",
            ]
            .contains(&k.as_str())
        }) || body.get("model") != Some(&json!(self.model))
        {
            return Err("unsupported model or fields");
        }
        let messages = body
            .get("messages")
            .and_then(Value::as_array)
            .ok_or("messages required")?;
        if !(1..=64).contains(&messages.len())
            || !messages.iter().all(|m| {
                m.as_object().is_some_and(|o| {
                    o.keys().all(|k| {
                        ["role", "content", "tool_calls", "tool_call_id", "name"]
                            .contains(&k.as_str())
                    })
                }) && m["role"]
                    .as_str()
                    .is_some_and(|r| ["system", "user", "assistant", "tool"].contains(&r))
                    && (m["content"].is_string() || m["content"].is_null())
            })
        {
            return Err("unsupported messages");
        }
        if self.source_only
            && (body.get("tools").is_some_and(|v| v != &json!([]))
                || body.get("tool_choice").is_some_and(|v| v != "none")
                || messages
                    .iter()
                    .any(|m| m["role"] == "tool" || m.get("tool_calls").is_some()))
        {
            return Err("source reviews cannot request model tools");
        }
        if body.get("tools").is_some_and(|v| {
            !v.as_array()
                .is_some_and(|v| v.len() <= 16 && v.iter().all(|t| t["type"] == "function"))
        }) || body
            .get("options")
            .is_some_and(|v| v != &json!({"num_ctx":64000}))
            || body
                .get("stream_options")
                .is_some_and(|v| v != &json!({"include_usage":true}))
            || body.get("stream").is_some_and(|v| !v.is_boolean())
            || body.get("reasoning_effort").is_some_and(|v| v != "none")
            || body.get("tool_choice").is_some_and(|v| {
                !(matches!(v.as_str(), Some("none" | "auto" | "required"))
                    || (v["type"] == "function"
                        && v["function"]["name"]
                            .as_str()
                            .is_some_and(|n| !n.is_empty() && n.len() <= 128)))
            })
            || ["temperature", "top_p"].iter().any(|k| {
                body.get(*k)
                    .is_some_and(|v| !v.as_f64().is_some_and(|n| (0.0..=1.0).contains(&n)))
            })
        {
            return Err("unsupported inference settings");
        }
        let tokens = body
            .get("max_tokens")
            .map_or(Some(self.max_tokens), Value::as_u64)
            .ok_or("invalid output limit")?;
        if tokens == 0 {
            return Err("invalid output limit");
        }
        body.remove("options");
        // Runtime retries may request a larger completion after truncation. The
        // relay owns the ceiling: forward a bounded request without raising it.
        body.insert("max_tokens".into(), json!(tokens.min(self.max_tokens)));
        body.insert("reasoning_effort".into(), json!("none"));
        if let Some(format) = &self.response_format {
            body.insert("response_format".into(), format.clone());
        }
        let body = Value::Object(body);
        // Adding the relay-owned schema must not exceed the transport budget.
        if serde_json::to_vec(&body)
            .map_err(|_| "invalid chat object")?
            .len()
            > MAX_REQUEST
        {
            return Err("prepared model request exceeds limit");
        }
        Ok(body)
    }

    pub async fn respond(&self, request: Request, output: mpsc::Sender<Frame>) {
        let id = request.id;
        if request.path != "/v1/chat/completions" {
            let (status, body) = match self.metadata(&request) {
                Ok(v) => (200, v),
                Err(status) => (
                    status,
                    json!({"error":{"message":"Unsupported model probe"}}),
                ),
            };
            let _ = output
                .send(Frame::Start {
                    id,
                    status,
                    content_type: "application/json",
                })
                .await;
            for chunk in serde_json::to_vec(&body).unwrap_or_default().chunks(4096) {
                if output
                    .send(Frame::Chunk {
                        id,
                        hex: hex::encode(chunk),
                    })
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = output.send(Frame::End { id }).await;
            return;
        }
        let Ok(body) = self.chat(&request) else {
            let _ = output
                .send(Frame::Failed {
                    id,
                    reason: "invalid_model_request",
                })
                .await;
            return;
        };
        let mut received = Vec::new();
        let result = async {
            let mut response = self
                .client
                .post(format!("{}/v1/chat/completions", self.origin))
                .json(&body)
                .send()
                .await
                .map_err(|error| {
                    if error.is_timeout() {
                        "model_timeout"
                    } else {
                        "model_connection_failed"
                    }
                })?;
            if !response.status().is_success() {
                return Err("model_rejected_request");
            }
            let content_type = if body["stream"] == true {
                "text/event-stream"
            } else {
                "application/json"
            };
            if response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| v.split(';').next() != Some(content_type))
            {
                return Err("unexpected_model_response");
            }
            output
                .send(Frame::Start {
                    id,
                    status: 200,
                    content_type,
                })
                .await
                .map_err(|_| "agent_disconnected")?;
            while let Some(chunk) = response.chunk().await.map_err(|error| {
                if error.is_timeout() {
                    "model_timeout"
                } else {
                    "model_stream_interrupted"
                }
            })? {
                if received.len() + chunk.len() > MAX_RESPONSE {
                    return Err("model_output_limit");
                }
                received.extend_from_slice(&chunk);
                for piece in chunk.chunks(4096) {
                    output
                        .send(Frame::Chunk {
                            id,
                            hex: hex::encode(piece),
                        })
                        .await
                        .map_err(|_| "agent_disconnected")?;
                }
            }
            output
                .send(Frame::End { id })
                .await
                .map_err(|_| "agent_disconnected")?;
            Ok::<_, &'static str>(())
        }
        .await;
        let stats = ResponseStats::read(&received, body["stream"] == true);
        eprintln!(
            "model response: transport={} finish={} prompt_tokens={:?} completion_tokens={:?} bytes={}",
            result.err().unwrap_or("complete"),
            stats.finish,
            stats.prompt_tokens,
            stats.completion_tokens,
            received.len(),
        );
        if let Err(reason) = result {
            let _ = output.send(Frame::Failed { id, reason }).await;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    #[test]
    fn completion_diagnostics_read_stream_usage_without_exposing_private_text() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"private answer\"},\"finish_reason\":null}]}\r\n\r\n",
            "data: {\"choices\":[{\"finish_reason\":\"length\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":4000,\"completion_tokens\":512}}\n\n",
            "data: [DONE]\n\n",
        );
        let stats = ResponseStats::read(body.as_bytes(), true);
        assert_eq!(stats.finish, "length");
        assert_eq!(stats.prompt_tokens, Some(4000));
        assert_eq!(stats.completion_tokens, Some(512));
        assert!(!format!("{stats:?}").contains("private"));
        let hostile = json!({"choices":[{"finish_reason":"private\nforged log entry", "message":{"content":"private"}}], "usage":{"prompt_tokens":-1,"completion_tokens":"private"},"error":"private"});
        let stats = ResponseStats::read(&serde_json::to_vec(&hostile).unwrap(), false);
        assert_eq!(stats.finish, "other");
        assert_eq!(stats.prompt_tokens, None);
        assert_eq!(stats.completion_tokens, None);
        assert!(!format!("{stats:?}").contains("private"));
    }

    #[test]
    fn missing_or_interrupted_metadata_does_not_invent_a_finish_reason() {
        for bytes in [b"".as_slice(), b"data: {\"choices\":[", b"data: [DONE]\n"] {
            let stats = ResponseStats::read(bytes, true);
            assert_eq!(stats.finish, "not_reported");
            assert_eq!(stats.completion_tokens, None);
        }
        let stats = ResponseStats::read(
            br#"{"choices":[{"finish_reason":"tool_calls"}],"usage":{"completion_tokens":40}}"#,
            false,
        );
        assert_eq!(stats.finish, "tool_calls");
        assert_eq!(stats.completion_tokens, Some(40));
    }

    pub(crate) fn broker() -> Broker {
        Broker {
            client: reqwest::Client::new(),
            origin: "http://127.0.0.1:1".into(),
            model: "owned-model:pilot".into(),
            show: json!({}),
            tags: json!({}),
            version: json!({}),
            max_tokens: MAX_TOKENS,
            response_format: None,
            source_only: false,
        }
    }

    #[test]
    fn source_reviews_reject_model_tools_and_bind_file_hashes() {
        let bundle = super::super::agent::source::tests::task().evidence.bundle;
        let broker = broker().for_source_review(&bundle);
        let mut request = chat();
        let result = broker.chat(&request).unwrap();
        assert!(
            result["response_format"]
                .to_string()
                .contains(&bundle.files[0].sha256)
        );
        request.body.as_mut().unwrap()["tools"] =
            json!([{"type":"function", "function":{"name":"terminal"}}]);
        assert_eq!(
            broker.chat(&request).unwrap_err(),
            "source reviews cannot request model tools"
        );
        request.body.as_mut().unwrap()["tools"] = json!([]);
        assert!(broker.chat(&request).is_ok());
        request.body.as_mut().unwrap()["tool_choice"] = json!("required");
        assert!(broker.chat(&request).is_err());
    }
    fn snapshot() -> WebsiteSnapshot {
        let mut snapshot: WebsiteSnapshot = serde_json::from_value(json!({
            "schema_version": 1,
            "scope": {"homepage": "https://example.com/", "script_origins": []},
            "homepage": {"kind": "homepage", "url": "https://example.com/", "sha256": "d".repeat(64), "bytes": 5, "content_type": "text/html", "headers": {}, "text": "owned", "collected_at": 1, "connected_ip": null},
            "resources": [], "scripts": [], "script_limit_reached": false,
            "requests_made": 1, "captured_response_bytes": 5, "started_at": 1, "finished_at": 2
        })).unwrap();
        let mut other = snapshot.homepage.clone();
        other.sha256 = "e".repeat(64);
        snapshot.resources = vec![other.clone(), other];
        snapshot
    }
    #[test]
    fn a_serving_profile_must_match_the_paired_model_or_its_declared_parent() {
        let mut broker = broker();
        assert!(broker.matches_declaration("owned-model:pilot"));
        assert!(!broker.matches_declaration("another-model"));
        broker.show = json!({"details":{"parent_model":"owned-base:small"}});
        assert!(broker.matches_declaration("owned-base:small"));
        assert!(!broker.matches_declaration("owned-base:large"));
    }
    #[test]
    fn website_budget_is_explicit_and_runtime_cannot_increase_it() {
        let mut request = chat();
        request.body.as_mut().unwrap()["max_tokens"] = json!(u64::MAX);
        assert_eq!(broker().chat(&request).unwrap()["max_tokens"], 192);
        assert_eq!(
            broker()
                .for_website_review(&snapshot())
                .chat(&request)
                .unwrap()["max_tokens"],
            512
        );
    }
    fn chat() -> Request {
        Request {
            id: 1,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            body: Some(
                json!({"model":"owned-model:pilot","messages":[{"role":"user","content":"owned test"}],"stream":true,"max_tokens":128,"options":{"num_ctx":64000}}),
            ),
        }
    }
    #[test]
    fn endpoint_cannot_be_remote_credentials_dns_or_metadata_service() {
        for url in [
            "http://8.8.8.8",
            "http://model.example",
            "http://169.254.169.254",
            "http://user:password@127.0.0.1",
            "http://127.0.0.1/api",
            "http://127.0.0.1?key=secret",
            "http://[::ffff:8.8.8.8]",
        ] {
            assert!(origin(url).is_err(), "{url}");
        }
        assert!(origin("http://127.0.0.1:11434").is_ok());
        assert!(origin("http://172.18.0.2:11434").is_ok());
    }
    #[test]
    fn agent_cannot_change_model_settings_or_add_other_capabilities() {
        let broker = broker();
        let prepared = broker.chat(&chat()).unwrap();
        assert_eq!(prepared["max_tokens"], 128);
        assert!(prepared.get("options").is_none());
        for (key, value) in [
            ("model", json!("another-model")),
            ("max_tokens", json!(0)),
            ("max_tokens", json!(-1)),
            ("max_tokens", json!(1.2)),
            ("reasoning_effort", json!("high")),
            ("options", json!({"num_ctx":64000,"num_predict":-1})),
            (
                "messages",
                json!([{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://private"}}]}]),
            ),
            ("store", json!(true)),
            ("response_format", json!({"type":"text"})),
            ("tools", json!([{"type":"web_search"}])),
            ("tool_choice", json!({"type":"web_search"})),
            (
                "messages",
                json!([{"role":"user","content":"text","images":["http://private"]}]),
            ),
        ] {
            let mut request = chat();
            request.body.as_mut().unwrap()[key] = value;
            assert!(broker.chat(&request).is_err(), "{key}");
        }
    }
    #[tokio::test]
    async fn management_routes_never_reach_the_upstream() {
        let broker = broker();
        for path in [
            "/api/delete",
            "/api/create",
            "/api/pull",
            "/api/generate",
            "http://127.0.0.1/api/tags",
            "/v1/chat/completions?admin=1",
        ] {
            let (tx, mut rx) = mpsc::channel(4);
            broker
                .respond(
                    Request {
                        id: 1,
                        method: "POST".into(),
                        path: path.into(),
                        body: Some(json!({"model":"owned-model:pilot"})),
                    },
                    tx,
                )
                .await;
            assert!(
                matches!(rx.recv().await, Some(Frame::Start { status: 404, .. })),
                "{path}"
            );
        }
    }

    /// Owned HTTP fixture: finite responses, no external hosts or credentials.
    fn server(
        responses: Vec<(u16, &'static str, Vec<u8>)>,
    ) -> (String, thread::JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for (status, content_type, body) in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut stream = loop {
                    if let Ok((stream, _)) = listener.accept() {
                        break stream;
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "fixture request did not arrive"
                    );
                    thread::sleep(Duration::from_millis(5));
                };
                // Accepted sockets can inherit nonblocking mode on macOS.
                // The fixture uses blocking reads with a timeout after accept.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut raw = Vec::new();
                let mut byte = [0];
                while !raw.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    raw.push(byte[0]);
                    assert!(raw.len() < 8192);
                }
                let headers = String::from_utf8(raw).unwrap();
                let length = headers
                    .lines()
                    .find_map(|s| {
                        s.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .map_or(0, |v| v.parse::<usize>().unwrap());
                assert!(length <= MAX_REQUEST);
                let mut payload = vec![0; length];
                stream.read_exact(&mut payload).unwrap();
                requests.push(json!({"line":headers.lines().next(),"body":serde_json::from_slice::<Value>(&payload).unwrap_or(Value::Null)}));
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                // A deliberately rejected/oversized body can close early.
                let _ = stream.write_all(&body);
            }
            requests
        });
        (origin, handle)
    }

    fn metadata(context: u32) -> Vec<(u16, &'static str, Vec<u8>)> {
        [
            json!({"models":[{"name":"owned-model:pilot","digest":"a".repeat(64)}]}),
            json!({"parameters":format!("num_ctx {context}\nnum_predict 192"),"model_info":{"general.architecture":"owned","owned.context_length":64000},"capabilities":["tools"]}),
            json!({"version":"owned-fixture"}),
        ].into_iter().map(|v| (200,"application/json",serde_json::to_vec(&v).unwrap())).collect()
    }

    async fn collect(broker: Broker, request: Request) -> Vec<Frame> {
        let (tx, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            broker.respond(request, tx).await;
        });
        let mut frames = Vec::new();
        while let Some(frame) = rx.recv().await {
            frames.push(frame);
        }
        task.await.unwrap();
        frames
    }

    #[tokio::test]
    async fn preflight_rejects_changed_model_or_wrong_serving_window() {
        let (origin, fixture) = server(metadata(64000).into_iter().take(1).collect());
        assert!(
            Broker::connect(&origin, "owned-model:pilot", &"b".repeat(64), 600)
                .await
                .is_err()
        );
        assert_eq!(fixture.join().unwrap().len(), 1);
        let (origin, fixture) = server(metadata(4096).into_iter().take(2).collect());
        assert!(
            Broker::connect(&origin, "owned-model:pilot", &"a".repeat(64), 600)
                .await
                .is_err()
        );
        assert_eq!(fixture.join().unwrap().len(), 2);
        for field in ["context", "tools"] {
            let mut replies = metadata(64000);
            replies.truncate(2);
            let mut show: Value = serde_json::from_slice(&replies[1].2).unwrap();
            if field == "context" {
                show["model_info"]["owned.context_length"] = json!(32768);
            } else {
                show["capabilities"] = json!(["completion"]);
            }
            replies[1].2 = serde_json::to_vec(&show).unwrap();
            let (origin, fixture) = server(replies);
            assert!(
                Broker::connect(&origin, "owned-model:pilot", &"a".repeat(64), 600)
                    .await
                    .is_err()
            );
            assert_eq!(fixture.join().unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn bounded_stream_preserves_bytes_and_uses_only_the_pinned_endpoint() {
        let expected =
            "data: {\"choices\":[{\"delta\":{\"content\":\"owned answer\"}}]}\n\ndata: [DONE]\n\n";
        let mut replies = metadata(64000);
        replies.push((200, "text/event-stream", expected.as_bytes().to_vec()));
        let (origin, fixture) = server(replies);
        let broker = Broker::connect(&origin, "owned-model:pilot", &"a".repeat(64), 600)
            .await
            .unwrap();
        let frames = collect(broker, chat()).await;
        assert!(matches!(
            frames.first(),
            Some(Frame::Start { status: 200, .. })
        ));
        assert!(matches!(frames.last(), Some(Frame::End { .. })));
        let actual: Vec<_> = frames
            .iter()
            .flat_map(|f| match f {
                Frame::Chunk { hex, .. } => hex::decode(hex).unwrap(),
                _ => vec![],
            })
            .collect();
        assert_eq!(actual, expected.as_bytes());
        let requests = fixture.join().unwrap();
        assert_eq!(requests[3]["line"], "POST /v1/chat/completions HTTP/1.1");
        assert_eq!(requests[3]["body"]["model"], "owned-model:pilot");
        assert_eq!(requests[3]["body"]["max_tokens"], 128);
        assert_eq!(requests[3]["body"]["reasoning_effort"], "none");
        assert!(requests[3]["body"].get("options").is_none());
        assert!(requests[3]["body"].get("response_format").is_none());
    }

    #[tokio::test]
    async fn website_format_reaches_provider_without_changing_tools_or_trusting_its_reply() {
        // A provider may ignore the schema. Its answer must arrive unchanged so
        // result validation can reject it, rather than silently repairing it.
        let answer =
            br#"{"choices":[{"message":{"content":"not a report"},"finish_reason":"stop"}]}"#;
        let (origin, fixture) = server(vec![(200, "application/json", answer.to_vec())]);
        let snapshot = snapshot();
        let mut broker = broker().for_website_review(&snapshot);
        broker.origin = origin;
        let mut request = chat();
        let body = request.body.as_mut().unwrap();
        body["max_tokens"] = json!(u64::MAX);
        body["stream"] = json!(false);
        let tools = json!([{"type":"function", "function":{"name":"terminal", "parameters":{"type":"object"}}}]);
        body["tools"] = tools.clone();
        body["tool_choice"] = json!("auto");
        let frames = collect(broker, request).await;
        assert!(matches!(frames.last(), Some(Frame::End { .. })));
        let received: Vec<_> = frames
            .iter()
            .flat_map(|frame| match frame {
                Frame::Chunk { hex, .. } => hex::decode(hex).unwrap(),
                _ => vec![],
            })
            .collect();
        assert_eq!(received, answer);
        let requests = fixture.join().unwrap();
        let body = &requests[0]["body"];
        assert_eq!(body["tools"], tools);
        assert_eq!(body["tool_choice"], "auto");
        assert_eq!(body["max_tokens"], 512);
        assert_eq!(body["response_format"]["type"], "json_schema");
        let schema = &body["response_format"]["json_schema"]["schema"];
        assert_eq!(
            schema["required"],
            json!(["summary", "findings", "limitations"])
        );
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["findings"]["maxItems"], 1);
        let hashes = &schema["properties"]["findings"]["items"]["properties"]["citations"]["items"]
            ["properties"]["resource_sha256"]["enum"];
        assert_eq!(hashes, &json!(["d".repeat(64), "e".repeat(64)]));
        let snapshot_hash = patchriot_protocol::website_reviews::snapshot_hash(&snapshot).unwrap();
        assert!(!hashes.as_array().unwrap().contains(&json!(snapshot_hash)));
        assert!(!schema.to_string().contains("owned"));
    }

    #[test]
    fn runtime_cannot_override_website_format_or_exceed_total_request_budget() {
        let snapshot = snapshot();
        let website = broker().for_website_review(&snapshot);
        for format in [
            json!(null),
            json!({"type":"text"}),
            website_response_format(&snapshot),
        ] {
            let mut request = chat();
            request.body.as_mut().unwrap()["response_format"] = format;
            assert!(website.chat(&request).is_err());
        }
        let mut request = chat();
        request.body.as_mut().unwrap()["messages"][0]["content"] =
            json!("x".repeat(MAX_REQUEST - 256));
        assert!(broker().chat(&request).is_ok());
        assert_eq!(
            website.chat(&request).unwrap_err(),
            "prepared model request exceeds limit"
        );
    }

    #[tokio::test]
    async fn runtime_retries_cannot_raise_the_output_ceiling() {
        let replies = vec![(200, "text/event-stream", b"data: [DONE]\n\n".to_vec()); 2];
        let (origin, fixture) = server(replies);
        let mut broker = broker();
        broker.origin = origin;
        for requested in [MAX_TOKENS + 1, u64::MAX] {
            let mut request = chat();
            request.body.as_mut().unwrap()["max_tokens"] = json!(requested);
            let frames = collect(broker.clone(), request).await;
            assert!(matches!(frames.last(), Some(Frame::End { .. })));
        }
        let requests = fixture.join().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_eq!(request["body"]["max_tokens"], MAX_TOKENS);
            assert_eq!(request["body"]["model"], "owned-model:pilot");
        }
    }

    #[tokio::test]
    async fn metadata_is_chunked_to_fit_the_pipe_even_for_a_large_model_card() {
        let mut broker = broker();
        broker.show = json!({"model_info":{"description":"x".repeat(100_000)}});
        let request = Request {
            id: 1,
            method: "POST".into(),
            path: "/api/show".into(),
            body: Some(json!({"model":"owned-model:pilot"})),
        };
        let frames = collect(broker, request).await;
        assert!(matches!(frames.last(), Some(Frame::End { .. })));
        assert!(
            frames
                .iter()
                .all(|f| serde_json::to_vec(f).unwrap().len() < MAX_REQUEST)
        );
    }

    #[tokio::test]
    async fn upstream_errors_wrong_content_and_oversized_streams_fail_closed() {
        for (status, content, body) in [
            (403, "application/json", b"private provider error".to_vec()),
            (200, "text/html", b"wrong endpoint".to_vec()),
            (200, "text/event-stream", vec![b'x'; MAX_RESPONSE + 1]),
        ] {
            let (origin, fixture) = server(vec![(status, content, body)]);
            let mut broker = broker();
            broker.origin = origin;
            let frames = collect(broker, chat()).await;
            assert!(matches!(frames.last(), Some(Frame::Failed { .. })));
            let expected_reason = if status != 200 {
                "model_rejected_request"
            } else if content != "text/event-stream" {
                "unexpected_model_response"
            } else {
                "model_output_limit"
            };
            assert!(
                matches!(frames.last(), Some(Frame::Failed { reason, .. }) if *reason == expected_reason)
            );
            assert!(!frames.iter().any(|f| matches!(f, Frame::End { .. })));
            if status != 200 || content != "text/event-stream" {
                assert_eq!(frames.len(), 1);
            }
            fixture.join().unwrap();
        }
    }

    #[tokio::test]
    async fn abort_drops_a_stalled_model_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut broker = broker();
        broker.origin = format!("http://{}", listener.local_addr().unwrap());
        let fixture = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut raw = Vec::new();
            let mut byte = [0];
            while !raw.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                raw.push(byte[0]);
            }
            let headers = String::from_utf8(raw).unwrap();
            let length = headers
                .lines()
                .find_map(|s| {
                    s.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse::<usize>()
                .unwrap();
            socket.read_exact(&mut vec![0; length]).unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 100\r\n\r\nx").unwrap();
            assert_eq!(
                socket.read(&mut byte).unwrap(),
                0,
                "upstream connection should close on abort"
            );
        });
        let (tx, mut rx) = mpsc::channel(4);
        let task = tokio::spawn(async move {
            broker.respond(chat(), tx).await;
        });
        assert!(matches!(rx.recv().await, Some(Frame::Start { .. })));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        // Yield so the HTTP client's connection task can observe the dropped response.
        tokio::time::sleep(Duration::from_millis(50)).await;
        fixture.join().unwrap();
    }
}
