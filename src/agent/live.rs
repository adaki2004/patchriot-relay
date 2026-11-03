//! Live target access is outside the agent container. The relay checks every
//! destination, pins DNS answers, records evidence and owns the provider key.
use super::*;
use patchriot_protocol::{ReviewRole, pentests::*, website_reviews::WebsiteRunState};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, net::SocketAddr, sync::Mutex};
mod access;

pub const MODEL: &str = "abliterated-model-large-v2";
const API: &str = "https://api.abliteration.ai/v1";
pub const MAX_FRAME: usize = 512 * 1024;
pub const ENGINE_CHAT: &str = "/patchriot/artex/v1/chat/completions";
pub fn is_chat_path(path: &str) -> bool {
    path == "/v1/chat/completions" || path == ENGINE_CHAT
}
const MAX_SPEND: u64 = 3_000_000; // $3 reservation per role; never retried by this broker.
pub type Progress = Mutex<LiveProgress>;

fn assessment_format() -> Value {
    let text = |max| json!({"type":"string","minLength":1,"maxLength":max});
    json!({"type":"json_schema","json_schema":{"name":"live_assessment","strict":true,"schema":{
        "type":"object","additionalProperties":false,
        "required":["summary","findings","limitations"],"properties":{
            "summary":text(1600),
            "findings":{"type":"array","maxItems":6,"items":{
                "type":"object","additionalProperties":false,
                "required":["title","severity","support","explanation","reproduction","suggested_action","evidence_ids"],
                "properties":{
                    "title":text(180),
                    "severity":{"type":"string","enum":["info","low","medium","high","critical"]},
                    "support":{"type":"string","enum":["observed","reproduced","not_reproduced","needs_review"]},
                    "explanation":text(1200),"reproduction":text(800),"suggested_action":text(800),
                    "evidence_ids":{"type":"array","minItems":1,"maxItems":24,"items":{"type":"integer","minimum":1}}
                }
            }},
            "limitations":{"type":"array","maxItems":8,"items":text(700)}
        }
    }}})
}

const RECORDED_HEADERS: &[&str] = &[
    "content-type",
    "content-security-policy",
    "content-security-policy-report-only",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "cache-control",
    "vary",
    "age",
    "etag",
    "last-modified",
    "expires",
    "location",
    "server",
];

pub struct Task {
    pub role: ReviewRole,
    pub scope_sha256: String,
    pub evidence: PentestEvidence,
}
impl Task {
    pub fn input(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.evidence.context.scope.normalized()? != self.evidence.context.scope
            || self.evidence.context.scope.hash()? != self.scope_sha256
            || self.evidence.context.scope_sha256 != self.scope_sha256
            || self.evidence.context.provider != "abliteration.ai"
            || self.evidence.previous_reports.len() > 2
        {
            return Err("invalid live assignment".into());
        }
        let mut bytes = serde_json::to_vec(
            &json!({"kind":"live_http_v1","role":self.role,"evidence":{"context":self.evidence.context,"previous_reports":self.evidence.previous_reports}}),
        )?;
        if bytes.len() > 3 * 1024 * 1024 {
            return Err("live assignment exceeds limit".into());
        }
        bytes.push(b'\n');
        Ok(bytes)
    }
}
#[derive(Default)]
struct Counters {
    reserved: u64,
    calls: u16,
    evidence: Vec<HttpEvidence>,
    evidence_bytes: usize,
}
pub struct LiveBroker {
    client: reqwest::Client,
    key: zeroize::Zeroizing<String>,
    scope: LiveScope,
    deadline: Instant,
    counters: Mutex<Counters>,
    access: access::Access,
}
impl LiveBroker {
    pub(super) fn valid_tool_record(&self, data: &Value) -> bool {
        serde_json::from_value::<LiveToolRun>(data.clone()).is_ok_and(|run| {
            self.counters
                .lock()
                .is_ok_and(|count| run.valid(&count.evidence))
        })
    }
    pub(super) fn update_progress(
        &self,
        progress: &Progress,
        phase: LivePhase,
        completed_tools: u8,
    ) {
        if let (Ok(count), Ok(mut current)) = (self.counters.lock(), progress.lock()) {
            *current = LiveProgress {
                phase,
                http_requests: count.evidence.len() as u16,
                inference_calls: count.calls,
                completed_tools,
            };
        }
    }
    #[cfg(test)]
    pub fn new(
        key_file: &Path,
        scope: LiveScope,
        deadline: Instant,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        Self::new_with_credentials(key_file, scope, deadline, None)
    }
    pub fn new_with_credentials(
        key_file: &Path,
        scope: LiveScope,
        deadline: Instant,
        credentials: Option<&TestCredentials>,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(key_file)?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.mode() & 0o077 != 0
            || meta.len() > 4096
            || meta.uid() != rustix::process::geteuid().as_raw()
        {
            return Err("provider key file must be private and owned by the relay user".into());
        }
        let mut key = zeroize::Zeroizing::new(String::new());
        file.read_to_string(&mut key)?;
        let key = zeroize::Zeroizing::new(key.trim().to_owned());
        if key.len() < 16 || key.chars().any(char::is_whitespace) {
            return Err("invalid provider key file".into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(180))
            .build()?;
        let access = access::Access::new(&scope, credentials)?;
        Ok(Arc::new(Self {
            client,
            key,
            scope,
            deadline,
            counters: Mutex::new(Counters::default()),
            access,
        }))
    }
    pub fn chat(&self, request: &Request) -> Result<Value, &'static str> {
        let engine = request.path == ENGINE_CHAT;
        if !is_chat_path(&request.path)
            || engine && !self.scope.tools.contains(&LiveToolProfile::ArtexEngineV1)
        {
            return Err("engine_not_selected");
        }
        if request.method != "POST" {
            return Err("unsupported_model_method");
        }
        let input = request
            .body
            .as_ref()
            .and_then(Value::as_object)
            .ok_or("invalid_model_request")?;
        if input.get("model") != Some(&json!(MODEL)) {
            return Err("wrong_model");
        }
        let messages = input
            .get("messages")
            .and_then(Value::as_array)
            .ok_or("messages_required")?;
        if messages.is_empty()
            || messages.len() > 160
            || messages.iter().any(|m| {
                !matches!(
                    m["role"].as_str(),
                    Some("user" | "system" | "assistant" | "tool")
                ) || !(m["content"].is_string() || m["content"].is_null())
            })
        {
            return Err("invalid_model_messages");
        }
        // Construct the provider request: URLs, credentials and arbitrary routing
        // fields supplied by a model or runtime never reach provider configuration.
        // Large v2 defaults to maximum reasoning. Select the intended effort
        // explicitly. Do not request a response schema here: the current provider
        // skips tool calls when a schema is present, even with a forced tool choice.
        let mut body = json!({"model":MODEL,"messages":messages,"max_tokens":8192,"stream":input.get("stream")==Some(&json!(true)),"temperature":0.2,
            "reasoning_effort":"high"});
        if let Some(tools) = input.get("tools") {
            if !tools.as_array().is_some_and(|v| {
                v.len() <= if engine { 64 } else { 16 } && v.iter().all(|t| t["type"] == "function")
            }) {
                return Err("invalid_tools");
            }
            body["tools"] = tools.clone();
        }
        if body["stream"] == true {
            body["stream_options"] = json!({"include_usage":true});
        }
        if serde_json::to_vec(&body)
            .map_err(|_| "invalid_model_request")?
            .len()
            > MAX_FRAME
        {
            return Err("model_request_too_large");
        }
        Ok(body)
    }
    async fn model(
        &self,
        request: &Request,
        output: &mpsc::Sender<Frame>,
    ) -> Result<(), &'static str> {
        let mut body = self.chat(request)?;
        let engine = request.path == ENGINE_CHAT;
        if !engine {
            self.finish_before_limit(&mut body)?;
        }
        let bytes = serde_json::to_vec(&body).map_err(|_| "invalid_model_request")?;
        if bytes.len() > MAX_FRAME {
            return Err("model_request_too_large");
        }
        // UTF-8 bytes conservatively bound text token usage. Reserve the entire
        // output allowance at published uncached prices, even if a call fails.
        let reservation = (bytes.len() as u64 + 4096) * 3 + 8192 * 5;
        {
            let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
            // ARTEX has its own response format and planner. Stop it cleanly
            // instead of injecting the later reviewer's final-report schema.
            // Leave time and inference for that reviewer to check its leads.
            if engine && self.engine_budget_reached(&count, reservation) {
                return Err("engine_budget_reached");
            }
            if count.calls >= 48 || count.reserved + reservation > MAX_SPEND {
                return Err("provider_budget_reached");
            }
            count.calls += 1;
            count.reserved += reservation;
        }
        let mut response = self
            .client
            .post(format!("{API}/chat/completions"))
            .bearer_auth(self.key.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|_| "provider_unavailable")?;
        if !response.status().is_success() {
            return Err("provider_rejected_request");
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
            return Err("unexpected_provider_response");
        }
        output
            .send(Frame::Start {
                id: request.id,
                status: 200,
                content_type,
            })
            .await
            .map_err(|_| "agent_disconnected")?;
        let mut received = 0;
        let mut usage_bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "provider_stream_interrupted")?
        {
            received += chunk.len();
            if received > 2 * 1024 * 1024 {
                return Err("provider_response_limit");
            }
            usage_bytes.extend_from_slice(&chunk);
            for chunk in chunk.chunks(4096) {
                output
                    .send(Frame::Chunk {
                        id: request.id,
                        hex: hex::encode(chunk),
                    })
                    .await
                    .map_err(|_| "agent_disconnected")?;
            }
        }
        if let Some(cost) = reported_cost(&usage_bytes, body["stream"] == true) {
            let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
            count.reserved = count
                .reserved
                .saturating_sub(reservation)
                .saturating_add(cost);
        }
        output
            .send(Frame::End { id: request.id })
            .await
            .map_err(|_| "agent_disconnected")?;
        Ok(())
    }
    fn engine_budget_reached(&self, count: &Counters, reservation: u64) -> bool {
        count.calls >= 24
            || count.reserved.saturating_add(reservation) > MAX_SPEND - 750_000
            || self.deadline.saturating_duration_since(Instant::now()) <= Duration::from_secs(240)
    }
    fn finish_before_limit(&self, body: &mut Value) -> Result<(), &'static str> {
        let count = self.counters.lock().map_err(|_| "counter_unavailable")?;
        let next = (serde_json::to_vec(body)
            .map_err(|_| "invalid_model_request")?
            .len() as u64
            + 4096)
            * 3
            + 8192 * 5;
        if count.calls >= 36
            || self.deadline.saturating_duration_since(Instant::now()) <= Duration::from_secs(180)
            || MAX_SPEND.saturating_sub(count.reserved) < next.saturating_mul(2) + 150_000
        {
            body.as_object_mut()
                .ok_or("invalid_model_request")?
                .remove("tools");
            body["tool_choice"] = json!("none");
            body["reasoning_effort"] = json!("low");
            // Formatting helps the closing turn, but cannot establish evidence.
            body["response_format"] = assessment_format();
            body["messages"].as_array_mut().ok_or("invalid_model_messages")?.push(json!({"role":"user","content":"The relay is reserving the remaining time and inference allowance for your final report. Tools are now closed for this role. Return the required JSON assessment now using only evidence already collected. Explicitly list unfinished checks and uncertainty. Do not request another tool or claim an unperformed test."}));
        }
        Ok(())
    }

    async fn http(&self, body: Value) -> Result<Value, &'static str> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Probe {
            method: String,
            url: String,
            #[serde(default)]
            headers: BTreeMap<String, String>,
            #[serde(default)]
            data: Option<String>,
            #[serde(default = "enabled")]
            authenticated: bool,
        }
        fn enabled() -> bool {
            true
        }
        let probe: Probe = serde_json::from_value(body).map_err(|_| "invalid_probe")?;
        let url = self.scope.permits(&probe.method, &probe.url)?;
        if let Some(data) = &probe.data {
            let content = probe
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.split(';').next().unwrap_or("").trim());
            if probe.method != "POST"
                || data.len() > 16384
                || data.contains('\0')
                || !matches!(
                    content,
                    Some("application/json" | "application/x-www-form-urlencoded")
                )
            {
                return Err("unsupported_probe_body");
            }
            if content == Some("application/json") && serde_json::from_str::<Value>(data).is_err() {
                return Err("invalid_json_probe_body");
            }
        }
        if probe.headers.len() > 12
            || probe
                .headers
                .keys()
                .map(|k| k.to_ascii_lowercase())
                .collect::<std::collections::HashSet<_>>()
                .len()
                != probe.headers.len()
            || probe.headers.iter().any(|(k, v)| {
                k.len() > 80
                    || v.len() > 1024
                    || k.chars().any(char::is_control)
                    || v.chars().any(char::is_control)
                    || [
                        "host",
                        "authorization",
                        "cookie",
                        "connection",
                        "content-length",
                        "transfer-encoding",
                        "proxy-authorization",
                    ]
                    .contains(&k.to_ascii_lowercase().as_str())
            })
        {
            return Err("unsupported_probe_headers");
        }
        {
            let count = self.counters.lock().map_err(|_| "counter_unavailable")?;
            if count.evidence.len() >= MAX_HTTP_REQUESTS || count.evidence_bytes > 600 * 1024 {
                return Err("target_request_budget_reached");
            }
        }
        // Calls are serialized by the supervised bridge. This pause caps the
        // rate even when the model launches a loop in its terminal tool.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let host = url.host_str().ok_or("target_hostname_required")?;
        let addresses: Vec<SocketAddr> =
            tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 443)))
                .await
                .map_err(|_| "target_dns_timeout")?
                .map_err(|_| "target_dns_failed")?
                .collect();
        if addresses.is_empty()
            || addresses.len() > 32
            || addresses.iter().any(|a| !public_ip(a.ip()))
        {
            return Err("target_dns_not_public");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| "target_client_unavailable")?;
        let method = reqwest::Method::from_bytes(probe.method.as_bytes())
            .map_err(|_| "unsupported_method")?;
        let mut request = client
            .request(method, url.clone())
            .header("user-agent", "Patchriot-authorized-review/0.0.2");
        for (key, value) in &probe.headers {
            request = request.header(key, value);
        }
        let authorization = self.access.authorization(probe.authenticated);
        request = self.access.apply(request, &url, probe.authenticated);
        if let Some(data) = &probe.data {
            request = request.body(data.clone());
        }
        let response = request.send().await;
        let retained_body = probe.data.as_ref().map(|v| self.access.redact(v));
        let mut evidence = HttpEvidence {
            request_body_excerpt: retained_body
                .as_ref()
                .map(|v| v.chars().take(2048).collect()),
            request_body_sha256: retained_body
                .as_ref()
                .map(|v| hex::encode(Sha256::digest(v.as_bytes()))),
            authenticated: authorization.is_some(),
            id: 0,
            method: probe.method,
            url: probe.url,
            request_headers: probe.headers,
            status: None,
            headers: BTreeMap::new(),
            body_excerpt: String::new(),
            body_sha256: None,
            truncated: false,
            error: None,
            observed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        };
        let mut received = Vec::new();
        match response {
            Err(_) => evidence.error = Some("target_request_failed".into()),
            Ok(mut response) => {
                self.access
                    .remember(&url, response.headers(), probe.authenticated);
                evidence.status = Some(response.status().as_u16());
                for &name in RECORDED_HEADERS {
                    if let Some(value) = response.headers().get(name).and_then(|v| v.to_str().ok())
                    {
                        evidence.headers.insert(
                            name.into(),
                            self.access.redact(value).chars().take(1024).collect(),
                        );
                    }
                }
                loop {
                    match response.chunk().await {
                        Ok(Some(chunk)) => {
                            let available = (256 * 1024usize).saturating_sub(received.len());
                            received.extend_from_slice(&chunk[..available.min(chunk.len())]);
                            if chunk.len() > available {
                                evidence.truncated = true;
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            evidence.error = Some("target_body_interrupted".into());
                            evidence.truncated = true;
                            break;
                        }
                    }
                }
                received = self
                    .access
                    .redact(&String::from_utf8_lossy(&received))
                    .into_bytes();
                evidence.body_sha256 = Some(hex::encode(Sha256::digest(&received)));
                evidence.body_excerpt = String::from_utf8_lossy(&received)
                    .chars()
                    .take(2048)
                    .collect();
                evidence.truncated |= evidence.body_excerpt.len() < received.len();
            }
        }
        let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
        evidence.id = count.evidence.len() as u32 + 1;
        count.evidence_bytes += serde_json::to_vec(&evidence)
            .map_err(|_| "evidence_encoding_failed")?
            .len();
        let reply = json!({"remaining_cost_allowance_microusd":MAX_SPEND.saturating_sub(count.reserved),"recorded_header_names":RECORDED_HEADERS,"evidence":evidence,"body":String::from_utf8_lossy(&received),"body_truncated":received.len()==256*1024});
        count.evidence.push(evidence);
        Ok(reply)
    }
    pub async fn respond(&self, request: Request, output: mpsc::Sender<Frame>) {
        if is_chat_path(&request.path) {
            match self.model(&request, &output).await {
                Err("engine_budget_reached") => {
                    // Upstream pauses after consecutive 429s. Its wrapper
                    // collects the partial report and shuts down the engine.
                    // No provider request is sent for these rejected calls.
                    let _ = output
                        .send(Frame::Start {
                            id: request.id,
                            status: 429,
                            content_type: "application/json",
                        })
                        .await;
                    let _ = output
                        .send(Frame::Chunk {
                            id: request.id,
                            hex: hex::encode(br#"{"error":"engine_budget_reached"}"#),
                        })
                        .await;
                    let _ = output.send(Frame::End { id: request.id }).await;
                }
                Err(reason) => {
                    let _ = output
                        .send(Frame::Failed {
                            id: request.id,
                            reason,
                        })
                        .await;
                }
                Ok(()) => {}
            }
            return;
        }
        let (status, body) = match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/v1/models") => (
                200,
                json!({"object":"list","data":[{"id":MODEL,"object":"model","context_length":200000}]}),
            ),
            ("POST", "/patchriot/http") => {
                match self.http(request.body.unwrap_or(Value::Null)).await {
                    Ok(v) => (200, v),
                    Err(e) => (400, json!({"error":e})),
                }
            }
            _ => (404, json!({"error":"unsupported_bridge_route"})),
        };
        let _ = output
            .send(Frame::Start {
                id: request.id,
                status,
                content_type: "application/json",
            })
            .await;
        for chunk in serde_json::to_vec(&body).unwrap_or_default().chunks(4096) {
            if output
                .send(Frame::Chunk {
                    id: request.id,
                    hex: hex::encode(chunk),
                })
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = output.send(Frame::End { id: request.id }).await;
    }
    pub(super) fn result(
        &self,
        report: &AgentRun,
        settings: &Settings,
        passed: bool,
        cleanup: bool,
    ) -> PentestResult {
        let raw = report
            .events
            .iter()
            .rev()
            .find(|e| e["event"] == "result")
            .and_then(|e| e["data"]["final_response"].as_str())
            .unwrap_or("");
        let cleaned = raw
            .trim()
            .strip_prefix("```json")
            .or_else(|| raw.trim().strip_prefix("```"))
            .and_then(|s| s.trim().strip_suffix("```"))
            .unwrap_or(raw)
            .trim();
        let assessment = parse_assessment(cleaned);
        let count = self.counters.lock().expect("live counters poisoned");
        let (mut tool_runs, tools_valid) = tool_records(&report.events, &count.evidence);
        for run in &mut tool_runs {
            run.arguments
                .iter_mut()
                .for_each(|v| *v = self.access.redact(v));
            let cleaned = self.access.redact(&run.output_excerpt);
            if cleaned != run.output_excerpt {
                run.output_sha256 = hex::encode(Sha256::digest(cleaned.as_bytes()));
                run.output_excerpt = cleaned;
            }
        }
        let passed = passed && tools_valid;
        let mut result = PentestResult {
            kind: PentestResultKind::PentestAgentV1,
            scope_sha256: self.scope.hash().unwrap_or_default(),
            execution: LiveExecution {
                state: if passed {
                    WebsiteRunState::Completed
                } else {
                    WebsiteRunState::Failed
                },
                provider: "abliteration.ai".into(),
                model: MODEL.into(),
                image_digest: settings.image.clone(),
                duration_ms: report.duration_ms.min(u128::from(u64::MAX)) as u64,
                inference_calls: count.calls,
                http_requests: count.evidence.len() as u16,
                cost_upper_microusd: count.reserved,
                cleanup_confirmed: cleanup,
                failure_reason: if !tools_valid {
                    Some("invalid_tool_records".into())
                } else if passed {
                    None
                } else {
                    Some(report.failure_reason.unwrap_or(report.outcome).to_owned())
                },
            },
            assessment: assessment.and_then(|a| {
                let mut value = serde_json::to_value(a).ok()?;
                self.access.redact_json(&mut value);
                serde_json::from_value(value).ok()
            }),
            evidence: count.evidence.clone(),
            tool_runs,
            raw_summary: {
                let redacted = self.access.redact(raw);
                let raw = redacted.as_str();
                let mut end = raw.len().min(24000);
                while !raw.is_char_boundary(end) {
                    end -= 1;
                }
                raw[..end].to_owned()
            },
        };
        result.omit_binary_excerpts();
        if !result.valid(&self.scope) {
            result.assessment = None;
        }
        result
    }
}

/// Only the fixed startup phase may attach tool transcripts. A later terminal
/// print from the model cannot masquerade as that phase. HTTP evidence is still
/// recorded separately by the Rust broker; neither source attests operator honesty.
fn tool_records(events: &[Value], evidence: &[HttpEvidence]) -> (Vec<LiveToolRun>, bool) {
    let mut records = Vec::new();
    let mut bytes = 0;
    let mut valid = true;
    for event in events
        .iter()
        .take_while(|e| !(e["event"] == "phase" && e["data"]["name"] == "agent_ready"))
        .filter(|e| e["event"] == "live_tool")
    {
        let parsed = serde_json::from_value::<LiveToolRun>(event["data"]["run"].clone());
        if let Ok(run) = parsed {
            bytes += serde_json::to_vec(&run).map_or(usize::MAX / 16, |b| b.len());
            if records.len() < 20 && bytes <= 256 * 1024 && run.valid(evidence) {
                records.push(run);
                continue;
            }
        }
        valid = false;
    }
    (records, valid)
}

/// Provider usage is a billing observation, not proof of an invoice. Charge
/// uncached rates conservatively. Missing usage keeps the original reservation.
fn reported_cost(bytes: &[u8], stream: bool) -> Option<u64> {
    fn cost(v: &Value) -> Option<u64> {
        let p = v["usage"]["prompt_tokens"].as_u64()?;
        let c = v["usage"]["completion_tokens"].as_u64()?;
        if p == 0 || p > 10_000_000 || c > 1_000_000 {
            return None;
        }
        p.checked_mul(3)?.checked_add(c.checked_mul(5)?)
    }
    if stream {
        bytes
            .split(|b| *b == b'\n')
            .filter_map(|line| line.strip_prefix(b"data:"))
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
            .filter_map(|v| cost(&v))
            .next_back()
    } else {
        serde_json::from_slice(bytes).ok().and_then(|v| cost(&v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tool_records_only_come_from_startup_and_must_reference_real_requests() {
        let run = json!({"tool":"nuclei","version":"3.11.1","arguments":[],
            "started_at":1,"duration_ms":1,"exit_code":0,"failure":null,"evidence_ids":[],
            "output_sha256":format!("{:x}", Sha256::digest(b"")),
            "output_excerpt":"","output_truncated":false});
        let mut events = vec![
            json!({"event":"live_tool","data":{"run":run}}),
            json!({"event":"phase","data":{"name":"agent_ready"}}),
            json!({"event":"live_tool","data":{"run":{"tool":"invented"}}}),
        ];
        let (saved, valid) = tool_records(&events, &[]);
        assert!(valid);
        assert_eq!(saved.len(), 1);
        events[0]["data"]["run"]["evidence_ids"] = json!([1]);
        let (saved, valid) = tool_records(&events, &[]);
        assert!(!valid);
        assert!(saved.is_empty());
    }
    #[test]
    fn literal_line_breaks_are_preserved_but_malformed_claims_are_not_guessed() {
        let report = "{\"summary\":\"Line one\nLine two\",\"findings\":[],\"limitations\":[\"Owned test only\"]}";
        assert_eq!(
            parse_assessment(report).unwrap().summary,
            "Line one\nLine two"
        );
        for malformed in [
            "{\"summary\":\"partial",
            "{\"summary\":\"missing fields\"}",
            "{\"summary\":\"x\",\"findings\":[],\"limitations\":[],\"approved\":true}",
        ] {
            assert!(parse_assessment(malformed).is_none());
        }
    }
    fn broker() -> Arc<LiveBroker> {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "fixture-provider-credential-not-real").unwrap();
        LiveBroker::new(
            file.path(),
            LiveScope {
                authentication: None,
                auth_check_path: None,
                origins: vec!["https://example.com".into()],
                objective: "Owned fixture".into(),
                methods: vec!["GET".into(), "HEAD".into(), "OPTIONS".into()],
                profile: None,
                tools: vec![],
            },
            Instant::now() + Duration::from_secs(600),
        )
        .unwrap()
    }
    #[tokio::test]
    async fn live_tool_events_survive_the_supervised_pipe_without_provider_calls() {
        let events = [
            json!({"type":"event","event":"phase","data":{"name":"scoped_tools"}}),
            json!({"type":"event","event":"live_tool","data":{"run":{
                "tool":"nuclei","version":"3.11.1","arguments":[],"started_at":1,
                "duration_ms":1,"exit_code":0,"failure":null,"evidence_ids":[],
                "output_sha256":format!("{:x}", Sha256::digest(b"")),"output_excerpt":"","output_truncated":false}}}),
            json!({"type":"event","event":"phase","data":{"name":"agent_ready"}}),
            json!({"type":"event","event":"result","data":{"completed":true}}),
        ];
        // All values above are fixed test literals, not target/model strings.
        let script = events
            .iter()
            .map(|e| format!("printf '%s\\n' '{e}'"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\nsleep 0.1";
        let mut command = std::process::Command::new("/bin/sh");
        command.env_clear().args(["-c", &script]);
        let broker = broker();
        let progress = Progress::default();
        let report = supervise(
            command,
            Bridge::Live(broker.clone()),
            &|| false,
            Duration::from_secs(2),
            None,
            Some(&progress),
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, "completed");
        assert_eq!(tool_records(&report.events, &[]).0.len(), 1);
        assert_eq!(broker.counters.lock().unwrap().calls, 0);
        let observed = progress.lock().unwrap();
        assert_eq!(observed.phase, LivePhase::Finishing);
        assert_eq!(observed.completed_tools, 1);
        assert_eq!(observed.http_requests, 0);
        assert_eq!(observed.inference_calls, 0);
    }
    #[tokio::test]
    async fn rejected_engine_retries_do_not_consume_the_reviewers_call_allowance() {
        let mut broker = broker();
        Arc::get_mut(&mut broker).unwrap().scope.tools = vec![LiveToolProfile::ArtexEngineV1];
        broker.counters.lock().unwrap().calls = 24;
        // Exercise the real supervised pipe and real 429 responses. The engine
        // has spent its allowance; these retries must never contact a provider
        // or prevent the subsequent final report from arriving.
        let script = r#"
            i=1
            while [ "$i" -le 60 ]; do
                printf '%s\n' '{"type":"request","request":{"id":'"$i"',"method":"POST","path":"/patchriot/artex/v1/chat/completions","body":{"model":"abliterated-model-large-v2","messages":[{"role":"user","content":"fixture"}]}}}'
                while IFS= read -r frame; do
                    case "$frame" in *'"type":"end"'*) break ;; esac
                done
                i=$((i + 1))
            done
            printf '%s\n' '{"type":"event","event":"phase","data":{"name":"agent_ready"}}'
            printf '%s\n' '{"type":"event","event":"result","data":{"completed":true,"final_response":"saved fixture report"}}'
        "#;
        let mut command = std::process::Command::new("/bin/sh");
        command.env_clear().args(["-c", script]);
        let report = supervise(
            command,
            Bridge::Live(broker.clone()),
            &|| false,
            Duration::from_secs(10),
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, "completed");
        assert_eq!(
            report.inference_calls, 60,
            "transport attempts are distinct from paid calls"
        );
        assert_eq!(
            report.events.last().unwrap()["data"]["final_response"],
            "saved fixture report"
        );
        {
            let count = broker.counters.lock().unwrap();
            assert_eq!(count.calls, 24);
            assert_eq!(count.reserved, 0);
        }
        // The spend and provider-call cap are still enforced by model(), as
        // covered by the exhausted-budget regression below.
        assert_eq!(Bridge::Live(broker.clone()).max_requests(), 600);
        broker.counters.lock().unwrap().calls = 48;
        let (tx, _rx) = mpsc::channel(4);
        let request = Request {
            id: 61,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            body: Some(json!({"model":MODEL,"messages":[{"role":"user","content":"fixture"}]})),
        };
        assert_eq!(
            broker.model(&request, &tx).await,
            Err("provider_budget_reached")
        );
        assert_eq!(broker.counters.lock().unwrap().reserved, 0);
    }

    #[tokio::test]
    async fn prohibited_targets_and_credentials_never_reach_network_or_provider() {
        let broker = broker();
        for body in [
            json!({"method":"GET","url":"http://169.254.169.254/latest/meta-data"}),
            json!({"method":"GET","url":"https://elsewhere.example"}),
            json!({"method":"POST","url":"https://example.com"}),
            json!({"method":"GET","url":"https://example.com","headers":{"Authorization":"private"}}),
            json!({"method":"GET","url":"https://example.com","headers":{"Host":"internal"}}),
        ] {
            assert!(broker.http(body).await.is_err());
        }
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 0);
        assert!(count.evidence.is_empty());
        assert_eq!(count.reserved, 0);
    }
    #[test]
    fn plaintext_credentials_never_enter_the_container_assignment() {
        let scope:LiveScope=serde_json::from_value(json!({"origins":["https://example.com"],"methods":["GET","HEAD","OPTIONS"],"profile":"web_baseline_v1","tools":["authenticated_http_v1"],"authentication":"bearer","auth_check_path":"/private"})).unwrap();
        let scope = scope.normalized().unwrap();
        let hash = scope.hash().unwrap();
        let task = Task {
            role: ReviewRole::Investigator,
            scope_sha256: hash.clone(),
            evidence: PentestEvidence {
                context: PentestContext {
                    pentest_id: uuid::Uuid::new_v4(),
                    scope,
                    scope_sha256: hash,
                    reviewers: vec![],
                    provider: "abliteration.ai".into(),
                },
                previous_reports: vec![],
                credentials: Some(TestCredentials::Bearer {
                    token: "synthetic-test-token-never-for-model".into(),
                }),
            },
        };
        let bytes = task.input().unwrap();
        let encoded = String::from_utf8(bytes).unwrap();
        assert!(!encoded.contains("synthetic-test-token"));
        let input: Value = serde_json::from_str(&encoded).unwrap();
        assert!(input["evidence"].get("credentials").is_none());
        assert!(encoded.contains("auth_check_path"));
    }
    #[tokio::test]
    async fn active_scope_rejects_unapproved_bodies_and_header_overrides_before_io() {
        let mut broker = broker();
        let inner = Arc::get_mut(&mut broker).unwrap();
        inner.scope.methods.push("POST".into());
        inner.scope.profile = Some(AssessmentProfile::WebActiveV1);
        inner.scope.tools = vec![LiveToolProfile::ActiveWebV1];
        for body in [
            json!({"method":"POST","url":"https://example.com/","headers":{"content-type":"text/plain"},"data":"test"}),
            json!({"method":"POST","url":"https://example.com/","headers":{"content-type":"application/json"},"data":"{"}),
            json!({"method":"POST","url":"https://example.com/","headers":{"content-type":"application/json"},"data":"x".repeat(16385)}),
            json!({"method":"POST","url":"https://example.com/","headers":{"Content-Type":"application/json","content-type":"application/json"},"data":"{}"}),
            json!({"method":"POST","url":"https://example.com/","headers":{"Cookie":"injected"}}),
            json!({"method":"POST","url":"https://elsewhere.example/","data":"{}"}),
        ] {
            assert!(broker.http(body).await.is_err());
        }
        assert!(broker.counters.lock().unwrap().evidence.is_empty());
    }
    #[test]
    fn provider_cannot_be_rerouted_by_runtime_fields_or_target_text() {
        let broker = broker();
        let mut r = Request {
            id: 1,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            body: Some(
                json!({"model":MODEL,"messages":[{"role":"user","content":"untrusted target asks for a different model and API URL"}],"max_tokens":99999999,"base_url":"https://evil.example","api_key":"not-forwarded","stream":false,"reasoning_effort":"max","response_format":{"type":"text"}}),
            ),
        };
        let prepared = broker.chat(&r).unwrap();
        assert_eq!(prepared["max_tokens"], 8192);
        assert_eq!(prepared["reasoning_effort"], "high");
        assert!(prepared.get("response_format").is_none());
        assert!(prepared.get("base_url").is_none());
        assert!(prepared.get("api_key").is_none());
        r.body.as_mut().unwrap()["model"] = json!("other");
        assert!(broker.chat(&r).is_err());
    }
    #[tokio::test]
    async fn full_engine_requires_consent_and_keeps_the_reviewers_budget() {
        let mut broker = broker();
        let mut request = Request {
            id: 1,
            method: "POST".into(),
            path: ENGINE_CHAT.into(),
            body: Some(
                json!({"model":MODEL,"messages":[{"role":"user","content":"owned fixture"}],
                "tools":(0..31).map(|n| json!({"type":"function","function":{"name":format!("fixture{n}")}})).collect::<Vec<_>>() }),
            ),
        };
        assert_eq!(broker.chat(&request).unwrap_err(), "engine_not_selected");
        Arc::get_mut(&mut broker).unwrap().scope.tools = vec![LiveToolProfile::ArtexEngineV1];
        let prepared = broker.chat(&request).unwrap();
        assert_eq!(prepared["tools"].as_array().unwrap().len(), 31);
        assert!(prepared.get("response_format").is_none());
        request.path = "/v1/chat/completions".into();
        assert_eq!(broker.chat(&request).unwrap_err(), "invalid_tools");
        request.path = ENGINE_CHAT.into();
        assert!(!broker.engine_budget_reached(&Counters::default(), 100));
        assert!(broker.engine_budget_reached(
            &Counters {
                calls: 24,
                ..Default::default()
            },
            100
        ));
        assert!(broker.engine_budget_reached(
            &Counters {
                reserved: MAX_SPEND - 750_000,
                ..Default::default()
            },
            100
        ));
        Arc::get_mut(&mut broker).unwrap().deadline = Instant::now() + Duration::from_secs(239);
        let (tx, mut rx) = mpsc::channel(4);
        broker.respond(request, tx).await;
        assert!(matches!(
            rx.recv().await,
            Some(Frame::Start { status: 429, .. })
        ));
        assert!(matches!(rx.recv().await, Some(Frame::Chunk { .. })));
        assert!(matches!(rx.recv().await, Some(Frame::End { .. })));
        let count = broker.counters.lock().unwrap();
        assert_eq!(
            count.calls, 0,
            "local budget rejection must not contact provider"
        );
        assert_eq!(count.reserved, 0);
    }
    #[test]
    fn reserves_a_final_report_before_cost_or_turn_limits_stop_the_agent() {
        let broker = broker();
        let request = Request {
            id: 1,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            body: Some(
                json!({"model":MODEL,"messages":[{"role":"user","content":"owned test"}],"tools":[{"type":"function","function":{"name":"terminal"}}]}),
            ),
        };
        let normal = broker.chat(&request).unwrap();
        let mut prepared = normal.clone();
        broker.finish_before_limit(&mut prepared).unwrap();
        assert_eq!(normal, prepared);
        for (calls, reserved) in [(0, MAX_SPEND - 200_000), (36, 0)] {
            {
                let mut count = broker.counters.lock().unwrap();
                count.calls = calls;
                count.reserved = reserved;
            }
            let mut final_call = normal.clone();
            broker.finish_before_limit(&mut final_call).unwrap();
            assert!(final_call.get("tools").is_none());
            assert_eq!(final_call["tool_choice"], "none");
            assert_eq!(final_call["reasoning_effort"], "low");
            assert_eq!(final_call["response_format"]["type"], "json_schema");
            let schema = &final_call["response_format"]["json_schema"];
            assert_eq!(schema["strict"], true);
            assert_eq!(schema["schema"]["additionalProperties"], false);
            assert_eq!(
                schema["schema"]["properties"]["findings"]["items"]["properties"]["evidence_ids"]["minItems"],
                1
            );
            assert_eq!(final_call["messages"].as_array().unwrap().len(), 2);
            let final_reservation =
                (serde_json::to_vec(&final_call).unwrap().len() as u64 + 4096) * 3 + 8192 * 5;
            assert!(reserved + final_reservation < MAX_SPEND);
        }
    }
    #[test]
    fn provider_usage_uses_uncached_prices_and_incomplete_usage_keeps_the_reservation() {
        let body = br#"{"usage":{"prompt_tokens":1000,"completion_tokens":200,"prompt_tokens_details":{"cached_tokens":900}}}"#;
        assert_eq!(reported_cost(body, false), Some(4000));
        let stream = b"data: {\"choices\":[]}\n\ndata: {\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":200}}\n\ndata: [DONE]\n\n";
        assert_eq!(reported_cost(stream, true), Some(4000));
        for missing in [
            b"{}".as_slice(),
            br#"{"usage":{"prompt_tokens":1000}}"#,
            br#"{"usage":{"prompt_tokens":0,"completion_tokens":200}}"#,
        ] {
            assert_eq!(reported_cost(missing, false), None);
        }
        assert_eq!(reported_cost(b"data: {\"usage\":", true), None);
    }
    #[tokio::test]
    async fn exhausted_cost_reservation_fails_before_a_provider_request() {
        let broker = broker();
        broker.counters.lock().unwrap().reserved = MAX_SPEND;
        let r = Request {
            id: 1,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            body: Some(json!({"model":MODEL,"messages":[{"role":"user","content":"fixture"}]})),
        };
        let (tx, _rx) = mpsc::channel(2);
        assert_eq!(broker.model(&r, &tx).await, Err("provider_budget_reached"));
        assert_eq!(broker.counters.lock().unwrap().calls, 0);
    }
    #[test]
    fn shared_or_symlinked_provider_keys_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        std::fs::write(&key, "fixture-provider-credential-not-real").unwrap();
        let scope = broker().scope.clone();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(600);
        assert!(LiveBroker::new(&key, scope.clone(), deadline).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&key, &link).unwrap();
        assert!(LiveBroker::new(&link, scope, deadline).is_err());
    }
    #[test]
    fn a_slow_role_gets_time_to_write_its_report_before_lease_expiry() {
        let mut broker = broker();
        Arc::get_mut(&mut broker).unwrap().deadline = Instant::now() + Duration::from_secs(120);
        let mut body = json!({"messages":[{"role":"user","content":"fixture"}],"tools":[]});
        broker.finish_before_limit(&mut body).unwrap();
        assert_eq!(body["tool_choice"], "none");
        assert_eq!(body["messages"].as_array().unwrap().len(), 2);
        assert_eq!(broker.counters.lock().unwrap().calls, 0);
    }
}
