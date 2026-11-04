//! Explicit owned-example check through a pinned, network-isolated agent image.
//! The server selects an owned scenario; only the operator configures execution.

use crate::{
    docker::{Container, Docker, immutable_image, no_entries},
    inference::{Broker, Frame, MAX_REQUEST, Request},
    process::Outcome,
};
use patchriot_protocol::{
    AgentFixtureObservation, AgentOutcome, AgentResult, AgentResultKind,
    DEFAULT_AGENT_ATTEMPT_SECONDS, MAX_AGENT_ATTEMPT_SECONDS, WorkResult,
    default_agent_attempt_seconds,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
};

pub mod live;
pub mod source;
pub mod website;

const IMAGE_ENTRY: [&str; 2] = ["/opt/hermes/.venv/bin/python", "/patchriot/adapter.py"];
const TMPFS: [(&str, &str); 3] = [
    (
        "/opt/data",
        "rw,nosuid,nodev,noexec,size=134217728,uid=65534,gid=65534",
    ),
    (
        "/tmp",
        "rw,nosuid,nodev,noexec,size=134217728,uid=65534,gid=65534",
    ),
    (
        "/work",
        "rw,nosuid,nodev,noexec,size=67108864,uid=65534,gid=65534",
    ),
];

fn temporary_storage(engine: bool) -> [(&'static str, &'static str); 3] {
    let mut mounts = TMPFS;
    if engine {
        // The selected engine needs a disposable PostgreSQL data directory.
        // Still memory-backed, non-executable, and inside the same 2 GiB cap.
        mounts[2].1 = "rw,nosuid,nodev,noexec,size=536870912,uid=65534,gid=65534";
    }
    mounts
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    docker_socket: PathBuf,
    image: String,
    model_url: String,
    model: String,
    model_digest: String,
    #[serde(default)]
    live_provider_key_file: Option<PathBuf>,
    #[serde(default)]
    venice_fallback_key_file: Option<PathBuf>,
    #[serde(default = "default_agent_attempt_seconds")]
    max_attempt_seconds: u64,
}

impl Settings {
    pub(crate) fn model_name(&self) -> &str {
        &self.model
    }

    /// Inspects installed files only. Labels describe capabilities; they do not
    /// prove model weights, operator trust or successful penetration testing.
    pub(crate) fn installed_capabilities(&self) -> Result<Value, Box<dyn std::error::Error>> {
        let image = Docker::new(&self.docker_socket)?.inspect("image", &self.image)?;
        if image["Id"] != self.image
            || image["Config"]["Entrypoint"] != json!(IMAGE_ENTRY)
            || image["Config"]["User"] != "65534:65534"
        {
            return Err(
                "installed image must use the pinned Patchriot entrypoint and unprivileged user"
                    .into(),
            );
        }
        self.require_website_adapter()?;
        let tools = if self.live_provider_key_file.is_some() {
            self.live_tools()?
        } else {
            Vec::new()
        };
        Ok(
            json!({"image":self.image,"model":self.model,"adapter":image["Config"]["Labels"]["io.patchriot.agent-adapter"],
            "website_review":true,"source_review":self.require_source_adapter().is_ok(),"live_tools":tools,
            "model_weights_verified":false,"probe_executed":false}),
        )
    }

    pub fn max_attempt_seconds(&self) -> u64 {
        self.max_attempt_seconds
    }

    pub fn require_website_adapter(&self) -> Result<(), Box<dyn std::error::Error>> {
        let docker = Docker::new(&self.docker_socket)?;
        let image = docker.inspect("image", &self.image)?;
        if image["Id"] != self.image
            || !["2", "3", "4", "5", "6", "7", "8", "9", "10", "11"].contains(
                &image["Config"]["Labels"]["io.patchriot.agent-adapter"]
                    .as_str()
                    .unwrap_or(""),
            )
            || self.max_attempt_seconds > DEFAULT_AGENT_ATTEMPT_SECONDS
                && !["3", "4", "5", "6", "7", "8", "9", "10", "11"].contains(
                    &image["Config"]["Labels"]["io.patchriot.agent-adapter"]
                        .as_str()
                        .unwrap_or(""),
                )
        {
            return Err(
                "website reviews require adapter 2–11; longer CPU budgets require adapter 3–11"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn require_live_adapter(&self) -> Result<(), Box<dyn std::error::Error>> {
        // This runs before the first heartbeat/poll and before each later poll.
        // Do not offer capacity that cannot read its private provider credential.
        live::read_provider_key(
            self.live_provider_key_file
                .as_deref()
                .ok_or("live tests require a private provider key file")?,
        )?;
        if let Some(path) = &self.venice_fallback_key_file {
            live::read_provider_key(path)?;
        }
        let image = Docker::new(&self.docker_socket)?.inspect("image", &self.image)?;
        if patchriot_protocol::pentests::LiveProvider::from_model(&self.model)
            == Some(patchriot_protocol::pentests::LiveProvider::Venice)
            && image["Config"]["Labels"]["io.patchriot.agent-adapter"] != "11"
        {
            return Err("Venice live tests require adapter 11".into());
        }
        if self.live_provider_key_file.is_none()
            || image["Id"] != self.image
            || !matches!(
                image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
                Some("5" | "6" | "7" | "8" | "9" | "10" | "11")
            )
        {
            return Err(
                "live tests require the inspected adapter 5–11 and a private provider key file"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn live_tools(
        &self,
    ) -> Result<Vec<patchriot_protocol::pentests::LiveToolProfile>, Box<dyn std::error::Error>>
    {
        self.require_live_adapter()?;
        let image = Docker::new(&self.docker_socket)?.inspect("image", &self.image)?;
        Ok(
            if matches!(
                image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
                Some("10" | "11")
            ) {
                vec![
                    patchriot_protocol::pentests::LiveToolProfile::ArtexEngineV1,
                    patchriot_protocol::pentests::LiveToolProfile::ActiveWebV1,
                    patchriot_protocol::pentests::LiveToolProfile::AuthenticatedHttpV1,
                    patchriot_protocol::pentests::LiveToolProfile::SessionLoginV1,
                ]
            } else if matches!(
                image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
                Some("8" | "9")
            ) {
                vec![
                    patchriot_protocol::pentests::LiveToolProfile::ArtexEngineV1,
                    patchriot_protocol::pentests::LiveToolProfile::ActiveWebV1,
                    patchriot_protocol::pentests::LiveToolProfile::AuthenticatedHttpV1,
                ]
            } else if image["Config"]["Labels"]["io.patchriot.agent-adapter"] == "7" {
                vec![patchriot_protocol::pentests::LiveToolProfile::ArtexEngineV1]
            } else {
                vec![]
            },
        )
    }
    pub fn require_source_adapter(&self) -> Result<(), Box<dyn std::error::Error>> {
        let image = Docker::new(&self.docker_socket)?.inspect("image", &self.image)?;
        if image["Id"] != self.image
            || !matches!(
                image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
                Some("4" | "5" | "6" | "7" | "8" | "9" | "10" | "11")
            )
        {
            return Err("source reviews require the inspected adapter 4 image".into());
        }
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(8193)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Err("agent configuration exceeds 8 KiB".into());
        }
        let settings: Self =
            serde_json::from_slice(&bytes).map_err(|_| "invalid agent configuration")?;
        if !immutable_image(&settings.image) {
            return Err("agent image must be an immutable local sha256 image ID".into());
        }
        if !(DEFAULT_AGENT_ATTEMPT_SECONDS..=MAX_AGENT_ATTEMPT_SECONDS)
            .contains(&settings.max_attempt_seconds)
        {
            return Err("max_attempt_seconds must be 600..3600".into());
        }
        if settings.live_provider_key_file.is_some() {
            if patchriot_protocol::pentests::LiveProvider::from_model(&settings.model)
                .is_none_or(|provider| settings.model_url != provider.api_url())
            {
                return Err("live model configuration must use the declared provider".into());
            }
        } else {
            crate::inference::origin(&settings.model_url)?;
        }
        if settings.venice_fallback_key_file.is_some()
            && (settings.live_provider_key_file.is_none()
                || settings.model
                    != patchriot_protocol::pentests::LiveProvider::NearDeepSeek.model())
        {
            return Err("Venice fallback requires the NEAR primary route".into());
        }
        Ok(settings)
    }
}

pub struct Assignment<'a> {
    pub device_id: uuid::Uuid,
    pub lease_id: uuid::Uuid,
    pub declared_model: &'a str,
    /// Stop execution early enough to clean up and submit a timeout report while
    /// the lease is still valid. Preflight time counts against this deadline.
    pub execution_deadline: Instant,
    pub progress: Option<&'a live::Progress>,
}

pub struct Check {
    pub result: WorkResult,
    /// Detailed traces are retained only for the bundled owned example. Customer
    /// snapshots and tool transcripts are not saved to a relay diagnostic file.
    pub report: Option<Value>,
}

/// Remove only this device's labelled leftovers before polling after a restart.
/// The daemon lock prevents another process for the same identity running work.
pub fn recover(
    settings: &Settings,
    device_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let docker = Docker::new(&settings.docker_socket)?;
    let label = format!("label=io.patchriot.device={device_id}");
    let result = docker.control(&[
        "container",
        "ls",
        "--all",
        "--filter",
        "label=io.patchriot.agent-check=1",
        "--filter",
        &label,
        "--format",
        "{{.Names}}",
    ])?;
    if result.outcome != Outcome::Completed {
        return Err("could not inspect this device's previous agent containers".into());
    }
    let names = std::str::from_utf8(&result.stdout)?;
    let names: Vec<_> = names.lines().collect();
    if names.len() > 16
        || names.iter().any(|name| {
            !name
                .strip_prefix("patchriot-agent-")
                .is_some_and(|tail| tail.len() == 32 && tail.bytes().all(|b| b.is_ascii_hexdigit()))
        })
    {
        return Err("unexpected agent container list; inspect the local runtime".into());
    }
    for name in names {
        let mut previous = Container {
            docker: &docker,
            name: name.into(),
            cleaned: false,
        };
        if !previous.cleanup() {
            return Err("previous agent container cleanup could not be confirmed".into());
        }
    }
    Ok(())
}

#[derive(Clone)]
enum Bridge {
    Local(Box<Broker>),
    Live(Arc<live::LiveBroker>),
}
impl From<Broker> for Bridge {
    fn from(b: Broker) -> Self {
        Self::Local(Box::new(b))
    }
}
impl Bridge {
    fn max_frame(&self) -> usize {
        match self {
            Self::Local(_) => MAX_REQUEST,
            Self::Live(_) => live::MAX_FRAME,
        }
    }
    fn output_limit(&self) -> usize {
        match self {
            Self::Local(_) => 1_048_576,
            Self::Live(_) => 32 * 1024 * 1024,
        }
    }
    fn max_requests(&self) -> usize {
        match self {
            Self::Local(_) => 32,
            // Leave room for all allowed target/model calls and rejected local
            // retries, so transport does not silently shorten either allowance.
            Self::Live(_) => {
                patchriot_protocol::pentests::MAX_HTTP_REQUESTS
                    + usize::from(patchriot_protocol::pentests::MAX_LIVE_INFERENCE_CALLS)
                    + 100
            }
        }
    }
    fn model_attempt_limit(&self) -> Option<usize> {
        match self {
            Self::Local(_) => Some(4),
            // The live broker caps actual provider calls and spend. ARTEX may
            // retry its locally rejected requests while shutting down; charging
            // those attempts to the provider-call allowance killed the final report.
            // Transport still has its own bounded allowance and execution deadline.
            Self::Live(_) => None,
        }
    }
    fn max_tokens(&self) -> u64 {
        match self {
            Self::Local(b) => b.max_tokens(),
            Self::Live(_) => 8192,
        }
    }
    fn chat(&self, r: &Request) -> Result<Value, &'static str> {
        match self {
            Self::Local(b) => b.chat(r),
            Self::Live(b) => b.chat(r),
        }
    }
    fn matches_declaration(&self, s: &str) -> bool {
        match self {
            Self::Local(b) => b.matches_declaration(s),
            Self::Live(b) => s == b.model_id(),
        }
    }
    async fn respond(&self, r: Request, tx: mpsc::Sender<Frame>) {
        match self {
            Self::Local(b) => b.respond(r, tx).await,
            Self::Live(b) => b.respond(r, tx).await,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Wire {
    Request { request: Request },
    Event { event: String, data: Value },
}

#[derive(Default, Serialize)]
struct AgentRun {
    outcome: &'static str,
    failure_reason: Option<&'static str>,
    duration_ms: u128,
    output_bytes: usize,
    requests: usize,
    inference_calls: usize,
    exit_code: Option<i32>,
    events: Vec<Value>,
}

struct RequestTask(Option<JoinHandle<()>>);
impl Drop for RequestTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// A Docker attach client is a trusted helper, not the task boundary. The outer
/// caller kills/removes the actual container even if the attach process exits.
async fn supervise(
    command: std::process::Command,
    broker: impl Into<Bridge>,
    cancelled: &impl Fn() -> bool,
    timeout: Duration,
    input: Option<Vec<u8>>,
    progress: Option<&live::Progress>,
) -> io::Result<AgentRun> {
    let broker = broker.into();
    if cancelled() {
        return Ok(AgentRun {
            outcome: "cancelled",
            ..AgentRun::default()
        });
    }
    if timeout.is_zero() {
        return Ok(AgentRun {
            outcome: "timed_out",
            ..AgentRun::default()
        });
    }
    let started = Instant::now();
    let deadline_at = tokio::time::Instant::from_std(started + timeout);
    let mut child = tokio::process::Command::from(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing agent input"))?;
    if let Some(input) = input {
        // The adapter consumes one bounded frame before starting its model bridge.
        // This carries data, never a shell command or a host-mounted file.
        if !matches!(
            tokio::time::timeout_at(
                deadline_at.min(tokio::time::Instant::now() + Duration::from_secs(5)),
                stdin.write_all(&input),
            )
            .await,
            Ok(Ok(()))
        ) {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            return Ok(AgentRun {
                outcome: if tokio::time::Instant::now() >= deadline_at {
                    "timed_out"
                } else {
                    "agent_input_stalled"
                },
                duration_ms: started.elapsed().as_millis(),
                ..AgentRun::default()
            });
        }
    }
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing agent output"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing agent errors"))?;
    let (tx, mut rx) = mpsc::channel(4);
    let mut task = RequestTask(None);
    let mut active = None;
    let mut last_id = 0;
    let mut pending = Vec::new();
    let mut out = [0u8; 8192];
    let mut err = [0u8; 8192];
    let mut out_open = true;
    let mut err_open = true;
    let mut exited = false;
    let mut final_seen = false;
    let mut live_phase = patchriot_protocol::pentests::LivePhase::Starting;
    let mut completed_tools = 0u8;
    let mut report = AgentRun {
        outcome: "completed",
        failure_reason: None,
        duration_ms: 0,
        output_bytes: 0,
        requests: 0,
        inference_calls: 0,
        exit_code: None,
        events: Vec::new(),
    };
    let deadline = tokio::time::sleep_until(deadline_at);
    tokio::pin!(deadline);
    let mut tick = tokio::time::interval(Duration::from_millis(25));
    eprintln!("running isolated agent check");
    'running: while !exited || out_open || err_open {
        tokio::select! {
            biased;
            _ = &mut deadline => {
                report.outcome = "timed_out";
                break;
            }
            _ = tick.tick() => {
                if cancelled() {
                    report.outcome = "cancelled";
                    break;
                }
                if let (Bridge::Live(broker), Some(progress)) = (&broker, progress) {
                    broker.update_progress(progress, live_phase, completed_tools);
                }
            }
            n = stderr.read(&mut err), if err_open => {
                let n = n?;
                err_open = n != 0;
                report.output_bytes += n;
                if report.output_bytes > broker.output_limit() {
                    report.outcome = "output_limit";
                    break;
                }
            }
            n = stdout.read(&mut out), if out_open => {
                let n = n?;
                out_open = n != 0;
                report.output_bytes += n;
                if report.output_bytes > broker.output_limit() {
                    report.outcome = "output_limit";
                    break;
                }
                pending.extend_from_slice(&out[..n]);
                while let Some(end) = pending.iter().position(|&b| b == b'\n') {
                    if end > broker.max_frame() {
                        report.outcome = "invalid_protocol";
                        report.failure_reason = Some("agent_frame_limit");
                        break 'running;
                    }
                    let wire = serde_json::from_slice::<Wire>(&pending[..end]);
                    pending.drain(..=end);
                    match wire {
                        Ok(Wire::Request { request }) => {
                            report.requests += 1;
                            if active.is_some() || request.id <= last_id || report.requests > broker.max_requests() || final_seen {
                                report.outcome = "invalid_protocol";
                                report.failure_reason = Some(if final_seen {
                                    "agent_request_after_result"
                                } else if active.is_some() {
                                    "agent_overlapping_request"
                                } else if request.id <= last_id {
                                    "agent_request_replayed"
                                } else {
                                    "agent_request_limit"
                                });
                                break 'running;
                            }
                            last_id = request.id;
                            active = Some(request.id);
                            if live::is_chat_path(&request.path) {
                                if broker.model_attempt_limit().is_some_and(|limit| report.inference_calls >= limit) {
                                    report.outcome = "inference_limit";
                                    break 'running;
                                }
                                if let Err(reason) = broker.chat(&request) {
                                    eprintln!("agent request rejected: {reason}");
                                    report.outcome = "invalid_model_request";
                                    report.failure_reason = Some(reason);
                                    break 'running;
                                }
                                if request.body.as_ref()
                                    .and_then(|body| body["max_tokens"].as_u64())
                                    .is_some_and(|tokens| tokens > broker.max_tokens())
                                {
                                    eprintln!("runtime output request capped at {} tokens", broker.max_tokens());
                                }
                                report.inference_calls += 1;
                                eprintln!("agent requested model attempt {}", report.inference_calls);
                            }
                            if let Some(previous) = task.0.take() {
                                previous.abort();
                            }
                            let broker = broker.clone();
                            let tx = tx.clone();
                            task.0 = Some(tokio::spawn(async move { broker.respond(request, tx).await; }));
                        }
                        Ok(Wire::Event { event, data })
                            if (["phase", "tool_start", "tool_complete", "result"].contains(&event.as_str())
                                || matches!(&broker, Bridge::Live(_)) && event == "live_tool") && !final_seen => {
                            if event == "result" {
                                final_seen = true;
                                live_phase = patchriot_protocol::pentests::LivePhase::Finishing;
                            }
                            if event == "phase" && data["name"] == "scoped_tools" && report.inference_calls == 0 {
                                live_phase = patchriot_protocol::pentests::LivePhase::ScopedTools;
                            }
                            if event == "phase" && data["name"] == "agent_ready" {
                                live_phase = patchriot_protocol::pentests::LivePhase::Investigating;
                            }
                            if event == "live_tool" && report.inference_calls == 0
                                && matches!(&broker, Bridge::Live(b) if b.valid_tool_record(&data["run"])) {
                                completed_tools = completed_tools.saturating_add(1).min(16);
                            }
                            if event == "tool_start" {
                                eprintln!("agent started a tool");
                            }
                            report.events.push(json!({"event":event,"data":data}));
                        }
                        Ok(_) => {
                            report.outcome = "invalid_protocol";
                            report.failure_reason = Some("agent_event_invalid");
                            break 'running;
                        }
                        Err(_) => {
                            report.outcome = "invalid_protocol";
                            report.failure_reason = Some("agent_frame_invalid");
                            break 'running;
                        }
                    }
                }
                if pending.len() > broker.max_frame() {
                    report.outcome = "invalid_protocol";
                    report.failure_reason = Some("agent_frame_limit");
                    break;
                }
            }
            frame = rx.recv(), if active.is_some() => {
                let Some(frame) = frame else {
                    report.outcome = "model_request_failed";
                    break;
                };
                if let Frame::Failed { reason, .. } = frame {
                    eprintln!("model request stopped: {reason}");
                    report.outcome = "model_request_failed";
                    report.failure_reason = Some(reason);
                    break;
                }
                let end = matches!(frame, Frame::End { .. });
                let mut bytes = serde_json::to_vec(&frame).map_err(io::Error::other)?;
                bytes.push(b'\n');
                if !matches!(tokio::time::timeout(Duration::from_secs(1), stdin.write_all(&bytes)).await, Ok(Ok(()))) {
                    report.outcome = "agent_input_stalled";
                    break;
                }
                if end {
                    active = None;
                }
            }
            status = child.wait(), if !exited => {
                report.exit_code = status?.code();
                exited = true;
            }
        }
    }
    drop(task); // Dropping the response task also drops its HTTP stream.
    if !exited {
        let _ = child.start_kill();
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        if let Ok(Ok(status)) = status {
            report.exit_code = status.code();
        } else {
            report.outcome = "attach_cleanup_unconfirmed";
        }
    }
    if report.outcome == "completed"
        && (report.exit_code != Some(0) || !final_seen || !pending.is_empty() || active.is_some())
    {
        report.outcome = "agent_failed";
    }
    report.duration_ms = started.elapsed().as_millis();
    // Log only fixed reason codes and counts. Frames may contain credentials,
    // target responses or private model messages and must not enter the log.
    eprintln!(
        "agent stopped: outcome={} reason={:?} exit_code={:?} requests={} output_bytes={} inference_attempts={} final_event={} duration_ms={}",
        report.outcome,
        report.failure_reason,
        report.exit_code,
        report.requests,
        report.output_bytes,
        report.inference_calls,
        final_seen,
        report.duration_ms,
    );
    Ok(report)
}

fn policy(container: &Value, image: &str, args: &[&str], seconds: u64, engine: bool) -> bool {
    let h = &container["HostConfig"];
    let c = &container["Config"];
    container["Image"] == image
        && container["State"]["Status"] == "created"
        && h["NetworkMode"] == "none"
        && h["ReadonlyRootfs"] == true
        && h["Privileged"] == false
        && h["Init"] == true
        && h["CapDrop"] == json!(["ALL"])
        && no_entries(&h["CapAdd"])
        && h["SecurityOpt"] == json!(["no-new-privileges"])
        && h["Memory"] == 2_147_483_648u64
        && h["MemorySwap"] == 2_147_483_648u64
        && h["NanoCpus"] == 2_000_000_000u64
        && h["PidsLimit"] == 128
        && h["CgroupnsMode"] == "private"
        && h["PidMode"] == ""
        && h["IpcMode"] == "private"
        && h["UTSMode"] == ""
        && h["UsernsMode"] != "host"
        && h["LogConfig"]["Type"] == "none"
        && h["RestartPolicy"]["Name"] == "no"
        && h["Tmpfs"]
            == json!(
                temporary_storage(engine)
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>()
            )
        && [
            "Binds",
            "VolumesFrom",
            "Devices",
            "DeviceRequests",
            "DeviceCgroupRules",
            "GroupAdd",
            "PortBindings",
        ]
        .iter()
        .all(|k| no_entries(&h[*k]))
        && no_entries(&container["Mounts"])
        && no_entries(&c["Healthcheck"])
        && c["User"] == "65534:65534"
        && c["WorkingDir"] == "/work"
        && c["Entrypoint"] == json!(IMAGE_ENTRY)
        && c["Cmd"] == json!(args)
        && c["Tty"] == false
        && c["OpenStdin"] == true
        && c["Env"].as_array().is_some_and(|env| {
            env.iter()
                .any(|value| value == &format!("PATCHRIOT_AGENT_MAX_SECONDS={seconds}"))
        })
}

pub fn execute(args: &[String]) -> Result<u8, Box<dyn std::error::Error>> {
    if args.len() != 3 || args[1] != "--config" {
        return Err("usage: patchriot-relay agent-check --config PATH".into());
    }
    let settings = Settings::load(Path::new(&args[2]))?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    let check = run(&settings, None, None, None, None, &|| {
        cancelled.load(Ordering::Relaxed)
    })?;
    serde_json::to_writer_pretty(io::stdout().lock(), &check.report)?;
    println!();
    Ok(u8::from(!check.result.matches_fixture()))
}

pub fn run(
    settings: &Settings,
    assignment: Option<Assignment<'_>>,
    website: Option<&website::Task>,
    source: Option<&source::Task>,
    live: Option<&live::Task>,
    cancelled: &impl Fn() -> bool,
) -> Result<Check, Box<dyn std::error::Error>> {
    if [website.is_some(), source.is_some(), live.is_some()]
        .into_iter()
        .filter(|v| *v)
        .count()
        > 1
    {
        return Err("assignment has conflicting material".into());
    }
    if cancelled() {
        return Err("agent check cancelled before startup".into());
    }
    let docker = Docker::new(Path::new(&settings.docker_socket))?;
    let image = docker.inspect("image", &settings.image)?;
    if image["Id"] != settings.image
        || image["Os"] != "linux"
        || image["Config"]["Entrypoint"] != json!(IMAGE_ENTRY)
        || image["Config"]["User"] != "65534:65534"
        || !["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"].contains(
            &image["Config"]["Labels"]["io.patchriot.agent-adapter"]
                .as_str()
                .unwrap_or(""),
        )
        || website.is_some()
            && !["2", "3", "4", "5", "6", "7", "8", "9", "10", "11"].contains(
                &image["Config"]["Labels"]["io.patchriot.agent-adapter"]
                    .as_str()
                    .unwrap_or(""),
            )
        || source.is_some()
            && !matches!(
                image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
                Some("4" | "5" | "6" | "7" | "8" | "9" | "10" | "11")
            )
        || live
            .as_ref()
            .is_some_and(|task| !task.evidence.context.scope.tools.is_empty())
            && !matches!(
                image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
                Some("7" | "8" | "9" | "10" | "11")
            )
        || live.as_ref().is_some_and(|task| {
            task.evidence
                .context
                .scope
                .tools
                .iter()
                .any(|tool| *tool != patchriot_protocol::pentests::LiveToolProfile::ArtexEngineV1)
        }) && !matches!(
            image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
            Some("8" | "9" | "10" | "11")
        )
        || live
            .as_ref()
            .is_some_and(|task| task.evidence.context.scope.session_login.is_some())
            && !matches!(
                image["Config"]["Labels"]["io.patchriot.agent-adapter"].as_str(),
                Some("10" | "11")
            )
        || settings.max_attempt_seconds > DEFAULT_AGENT_ATTEMPT_SECONDS
            && !["3", "4", "5", "6", "7", "8", "9", "10", "11"].contains(
                &image["Config"]["Labels"]["io.patchriot.agent-adapter"]
                    .as_str()
                    .unwrap_or(""),
            )
        || !no_entries(&image["Config"]["OnBuild"])
        || !no_entries(&image["Config"]["Healthcheck"])
    {
        return Err("build the pinned agent/Dockerfile image before this check".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let live_broker = live
        .map(|task| {
            if task.model() != Some(settings.model.as_str()) {
                return Err("configured provider differs from the consented role".into());
            }
            live::LiveBroker::new_with_credentials(
                patchriot_protocol::pentests::LiveProvider::from_model(&settings.model)
                    .ok_or("unsupported live provider")?,
                settings
                    .live_provider_key_file
                    .as_deref()
                    .ok_or("live provider not configured")?,
                task.evidence.context.scope.clone(),
                assignment
                    .as_ref()
                    .map(|a| a.execution_deadline)
                    .unwrap_or_else(|| {
                        Instant::now() + Duration::from_secs(settings.max_attempt_seconds)
                    })
                    .min(Instant::now() + Duration::from_secs(settings.max_attempt_seconds)),
                task.evidence.credentials.as_ref(),
                if task.evidence.context.allows_venice_fallback {
                    settings.venice_fallback_key_file.as_deref()
                } else {
                    None
                },
            )
        })
        .transpose()?;
    let broker = if let Some(broker) = &live_broker {
        settings.require_live_adapter()?;
        Bridge::Live(broker.clone())
    } else {
        if settings.live_provider_key_file.is_some() {
            return Err("hosted inference accepts only opted-in live work".into());
        }
        let broker = runtime.block_on(Broker::connect(
            &settings.model_url,
            &settings.model,
            &settings.model_digest,
            settings.max_attempt_seconds,
        ))?;
        Bridge::from(if let Some(task) = website {
            broker.for_website_review(&task.evidence.snapshot)
        } else if let Some(task) = source {
            broker.for_source_review(&task.evidence.bundle)
        } else {
            broker
        })
    };
    let input = if let Some(task) = live {
        Some(task.input()?)
    } else if let Some(task) = source {
        Some(task.input()?)
    } else {
        website.map(website::Task::input).transpose()?
    };
    let mut args = vec![settings.model.as_str()];
    if live.is_some() {
        args.push("--pentest");
    }
    if website.is_some() {
        args.push("--website");
    }
    if source.is_some() {
        args.push("--source");
    }
    if let Some(assignment) = &assignment
        && !broker.matches_declaration(assignment.declared_model)
    {
        return Err(
            "configured model does not match this device's declaration or its serving profile"
                .into(),
        );
    }
    if cancelled() {
        return Err("agent check cancelled during preflight".into());
    }
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_| "random source unavailable")?;
    let mut owned = Container {
        docker: &docker,
        name: format!("patchriot-agent-{}", hex::encode(nonce)),
        cleaned: false,
    };
    let mut command = vec![
        "container".to_owned(),
        "create".into(),
        "--pull=never".into(),
        "--name".into(),
        owned.name.clone(),
        "--env".into(),
        format!(
            "PATCHRIOT_AGENT_MAX_SECONDS={}",
            settings.max_attempt_seconds
        ),
    ];
    if let Some(assignment) = &assignment {
        command.extend([
            "--label".into(),
            format!("io.patchriot.device={}", assignment.device_id),
            "--label".into(),
            format!("io.patchriot.lease={}", assignment.lease_id),
        ]);
    }
    command.extend(
        [
            "--label",
            "io.patchriot.agent-check=1",
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "65534:65534",
            "--memory",
            "2g",
            "--memory-swap",
            "2g",
            "--cpus",
            "2",
            "--pids-limit",
            "128",
            "--init",
            "--cgroupns",
            "private",
            "--ipc",
            "private",
            "--restart",
            "no",
            "--log-driver",
            "none",
            "--workdir",
            "/work",
        ]
        .map(str::to_owned),
    );
    let engine = live.is_some_and(|task| {
        task.evidence
            .context
            .scope
            .tools
            .contains(&patchriot_protocol::pentests::LiveToolProfile::ArtexEngineV1)
    });
    for (path, options) in temporary_storage(engine) {
        command.extend(["--tmpfs".into(), format!("{path}:{options}")]);
    }
    command.push(settings.image.clone());
    command.extend(args.iter().map(|arg| (*arg).to_owned()));
    let result = (|| -> Result<_, Box<dyn std::error::Error>> {
        if docker
            .control(&command.iter().map(String::as_str).collect::<Vec<_>>())?
            .outcome
            != Outcome::Completed
        {
            return Err("agent container creation failed".into());
        }
        if !policy(
            &docker.inspect("container", &owned.name)?,
            &settings.image,
            &args,
            settings.max_attempt_seconds,
            engine,
        ) {
            return Err("agent container policy rejected".into());
        }
        let report = runtime.block_on(supervise(
            docker.command(&[
                "container",
                "start",
                "--attach",
                "--interactive",
                &owned.name,
            ]),
            broker,
            cancelled,
            assignment
                .as_ref()
                .map(|a| {
                    a.execution_deadline
                        .saturating_duration_since(Instant::now())
                })
                .unwrap_or(Duration::from_secs(settings.max_attempt_seconds))
                .min(Duration::from_secs(settings.max_attempt_seconds)),
            input,
            assignment.as_ref().and_then(|a| a.progress),
        ))?;
        if report.outcome != "completed" {
            let _ = docker.control(&["container", "kill", &owned.name]);
        }
        let state = docker.inspect("container", &owned.name)?;
        let stopped = state["State"]["Running"] == false && state["State"]["Status"] == "exited";
        let passed = report.outcome == "completed"
            && stopped
            && state["State"]["ExitCode"] == 0
            && state["State"]["OOMKilled"] == false
            && report.events.iter().any(|e| {
                e["event"] == "result"
                    && (website.is_some()
                        || source.is_some()
                        || live.is_some()
                        || e["data"]["observed_fixture_regression"] == true)
                    && e["data"]["completed"] == true
            });
        Ok((report, stopped, state["State"]["OOMKilled"].clone(), passed))
    })();
    let cleanup = owned.cleanup();
    if !cleanup {
        return Err("agent cleanup could not be confirmed; inspect containers labelled io.patchriot.agent-check=1".into());
    }
    let (report, stopped, oom, passed) = result?;
    if let Some(broker) = live_broker {
        let result = broker.result(&report, settings, passed, cleanup);
        if !result.valid(&live.ok_or("missing live task")?.evidence.context.scope) {
            return Err("live result exceeded limits".into());
        }
        return Ok(Check {
            result: WorkResult::Pentest(result),
            report: None,
        });
    }
    if let Some(task) = website {
        let result = website::evidence(
            &report,
            settings,
            assignment.as_ref().map(|a| a.declared_model),
            task,
            passed,
            cleanup,
        );
        if !result.valid() {
            return Err("website evidence exceeded the report limits".into());
        }
        return Ok(Check {
            result: WorkResult::Website(result),
            report: None,
        });
    }
    if let Some(task) = source {
        let result = source::evidence(
            &report,
            settings,
            assignment.as_ref().map(|a| a.declared_model),
            task,
            passed,
            cleanup,
        );
        if !result.valid() {
            return Err("source evidence exceeded the report limits".into());
        }
        return Ok(Check {
            result: WorkResult::Source(result),
            report: None,
        });
    }
    let evidence = evidence(
        &report,
        settings,
        assignment.as_ref().map(|a| a.declared_model),
        passed,
        cleanup,
    );
    if !evidence.valid() {
        return Err("agent evidence exceeded the report limits".into());
    }
    Ok(Check {
        report: Some(
            json!({"schema_version":1,"mode":"owned_agent_check","evidence_source":"agent_reported_owned_example_not_independent_verification","container":owned.name,"model":settings.model,"model_digest":settings.model_digest,"image":settings.image,"policy_verified":true,"network":"none; bounded model requests over pipes","container_stopped":stopped,"oom_killed":oom,"cleanup_confirmed":cleanup,"passed":evidence.matches_fixture(),"run":report}),
        ),
        result: WorkResult::Agent(evidence),
    })
}

fn evidence(
    report: &AgentRun,
    settings: &Settings,
    declared: Option<&str>,
    passed: bool,
    cleanup: bool,
) -> AgentResult {
    let mut observation: Option<AgentFixtureObservation> = None;
    let mut terminal_calls = 0;
    let mut inconsistent = false;
    for event in &report.events {
        if event["event"] != "tool_complete" || event["data"]["args"][1] != "terminal" {
            continue;
        }
        terminal_calls += 1;
        let args = &event["data"]["args"];
        let observed = (|| {
            if args[2]["command"] != "cat /patchriot/access.py && python /patchriot/check.py" {
                return None;
            }
            let tool: Value = serde_json::from_str(args[3].as_str()?).ok()?;
            if tool["exit_code"] != 0 || !tool["error"].is_null() {
                return None;
            }
            serde_json::from_str::<AgentFixtureObservation>(
                tool["output"].as_str()?.lines().last()?,
            )
            .ok()
        })();
        if observed.is_none()
            || observation
                .as_ref()
                .is_some_and(|old| Some(old) != observed.as_ref())
        {
            inconsistent = true;
        }
        observation = observed;
    }
    if inconsistent {
        observation = None;
    }
    let response = report
        .events
        .iter()
        .find(|e| e["event"] == "result")
        .and_then(|e| e["data"]["final_response"].as_str())
        .unwrap_or("");
    let mut summary = String::new();
    for c in response
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
    {
        if summary.len() + c.len_utf8() > 4_000 {
            break;
        }
        summary.push(c);
    }
    AgentResult {
        kind: AgentResultKind::OwnedAgentV1,
        outcome: match report.outcome {
            "completed" if passed => AgentOutcome::Passed,
            "timed_out" => AgentOutcome::TimedOut,
            "cancelled" => AgentOutcome::Cancelled,
            _ => AgentOutcome::Failed,
        },
        declared_model: declared.unwrap_or(&settings.model).into(),
        model: settings.model.clone(),
        model_digest: settings.model_digest.clone(),
        image_digest: settings.image.clone(),
        duration_ms: report.duration_ms.try_into().unwrap_or(u64::MAX),
        inference_calls: report.inference_calls.try_into().unwrap_or(u16::MAX),
        terminal_calls,
        cleanup_confirmed: cleanup,
        observation,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn settings() -> Settings {
        Settings {
            live_provider_key_file: None,
            venice_fallback_key_file: None,
            docker_socket: "/var/run/docker.sock".into(),
            image: format!("sha256:{}", "b".repeat(64)),
            model_url: "http://127.0.0.1:11434".into(),
            model: "test-profile".into(),
            model_digest: "a".repeat(64),
            max_attempt_seconds: DEFAULT_AGENT_ATTEMPT_SECONDS,
        }
    }

    fn tool_event(blocked_after: bool) -> Value {
        let observations = json!({"original":{"owner_reads":true,"blocks_other_user":false},"patched":{"owner_reads":true,"blocks_other_user":blocked_after}});
        let tool = json!({"output":observations.to_string(),"exit_code":0,"error":null});
        json!({"event":"tool_complete","data":{"args":["call-1","terminal",{"command":"cat /patchriot/access.py && python /patchriot/check.py"},tool.to_string()]}})
    }

    #[test]
    fn published_agent_evidence_comes_from_the_exact_tool_not_the_final_answer() {
        let mut report = AgentRun {
            outcome: "completed",
            inference_calls: 2,
            duration_ms: 500_000,
            events: vec![
                json!({"event":"result","data":{"completed":true,"observed_fixture_regression":true,"final_response":"Definitely fixed."}}),
            ],
            ..AgentRun::default()
        };
        assert!(!evidence(&report, &settings(), None, true, true).matches_fixture());
        report.events.insert(0, tool_event(true));
        let result = evidence(&report, &settings(), Some("test-parent"), true, true);
        assert!(result.matches_fixture());
        assert_eq!(result.declared_model, "test-parent");
        assert_eq!(result.model, "test-profile");
        assert!(!evidence(&report, &settings(), None, true, false).matches_fixture());
        report.events.insert(1, tool_event(false));
        assert!(!evidence(&report, &settings(), None, true, true).matches_fixture());
        report.events.remove(1);
        report.events[0]["data"]["args"][2]["command"] = json!("echo invented-results");
        assert!(!evidence(&report, &settings(), None, true, true).matches_fixture());
    }

    #[test]
    fn agent_summary_is_bounded_utf8_and_terminal_control_sequences_are_removed() {
        let report = AgentRun {
            events: vec![
                json!({"event":"result","data":{"final_response": format!("\u{1b}{}\n", "é".repeat(3000))}}),
            ],
            ..AgentRun::default()
        };
        let result = evidence(&report, &settings(), None, false, true);
        assert_eq!(result.summary.len(), 4_000);
        assert!(!result.summary.contains('\u{1b}'));
        assert!(result.valid());
    }

    #[tokio::test]
    async fn cancellation_before_start_never_executes_the_attach_command() {
        let report = run("exit 99", &AtomicBool::new(true), Duration::from_secs(2)).await;
        assert_eq!(report.outcome, "cancelled");
        assert_eq!(report.exit_code, None);
        assert_eq!(report.requests, 0);
    }

    #[tokio::test]
    async fn spent_execution_budget_does_not_start_work_and_input_time_counts() {
        let report = supervise(
            std::process::Command::new("/nonexistent-patchriot-budget-probe"),
            crate::inference::tests::broker(),
            &|| false,
            Duration::ZERO,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, "timed_out");
        assert_eq!(report.exit_code, None);
        let started = Instant::now();
        let report = supervise(
            command("exec sleep 10"),
            crate::inference::tests::broker(),
            &|| false,
            Duration::from_millis(40),
            Some(vec![b'x'; 1024 * 1024]),
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.outcome, "timed_out");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(report.duration_ms >= 30);
        assert_eq!(report.requests, 0);
    }

    fn command(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new("/bin/sh");
        command.env_clear().args(["-c", script]);
        command
    }
    async fn run(script: &str, cancelled: &AtomicBool, timeout: Duration) -> AgentRun {
        supervise(
            command(script),
            crate::inference::tests::broker(),
            &|| cancelled.load(Ordering::Relaxed),
            timeout,
            None,
            None,
        )
        .await
        .unwrap()
    }
    const RESULT: &str =
        r#"printf '%s\n' '{"type":"event","event":"result","data":{"completed":true}}'"#;

    #[tokio::test]
    async fn completion_requires_a_single_final_event_and_zero_exit() {
        let cancelled = AtomicBool::new(false);
        let completed = run(RESULT, &cancelled, Duration::from_secs(2)).await;
        assert_eq!(completed.outcome, "completed");
        assert_eq!(completed.events.len(), 1);
        for script in ["exit 0".into(), format!("{RESULT}; exit 7")] {
            assert_eq!(
                run(&script, &cancelled, Duration::from_secs(2))
                    .await
                    .outcome,
                "agent_failed"
            );
        }
        let duplicate = run(
            &format!("{RESULT}; {RESULT}"),
            &cancelled,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(duplicate.outcome, "invalid_protocol");
        assert_eq!(duplicate.failure_reason, Some("agent_event_invalid"));
    }

    #[tokio::test]
    async fn malformed_or_replayed_requests_cannot_continue_execution() {
        let cancelled = AtomicBool::new(false);
        let request = r#"printf '%s\n' '{"type":"request","request":{"id":1,"method":"GET","path":"/api/version","body":null}}'"#;
        for script in [
            "printf 'not-json\\n'".into(),
            format!("{request}; {request}; exec sleep 2"),
        ] {
            assert_eq!(
                run(&script, &cancelled, Duration::from_secs(1))
                    .await
                    .outcome,
                "invalid_protocol"
            );
        }
        assert_eq!(run(r#"printf '%s\n' '{"type":"request","request":{"id":1,"method":"POST","path":"/v1/chat/completions","body":{"model":"other"}}}'"#,&cancelled,Duration::from_secs(1)).await.outcome,"invalid_model_request");
        let malformed = run("printf 'not-json\\n'", &cancelled, Duration::from_secs(1)).await;
        assert_eq!(malformed.failure_reason, Some("agent_frame_invalid"));
        let after_result = run(
            &format!("{RESULT}; {request}"),
            &cancelled,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(
            after_result.failure_reason,
            Some("agent_request_after_result")
        );
    }

    #[tokio::test]
    async fn timeout_and_operator_cancellation_stop_the_attach_client() {
        let cancelled = AtomicBool::new(false);
        let timed = run("exec sleep 10", &cancelled, Duration::from_millis(60)).await;
        assert_eq!(timed.outcome, "timed_out");
        assert!(timed.duration_ms < 2000);
        let report = run(
            "exec sleep 10",
            &AtomicBool::new(true),
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(report.outcome, "cancelled");
        assert!(report.duration_ms < 2000);
    }

    #[tokio::test]
    async fn untrusted_output_cannot_grow_without_bound() {
        let cancelled = AtomicBool::new(false);
        let report=run("while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' >&2; done",&cancelled,Duration::from_secs(5)).await;
        assert_eq!(report.outcome, "output_limit");
        assert!(report.output_bytes <= 1_048_576 + 8192);
        let report=run("while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done",&cancelled,Duration::from_secs(5)).await;
        assert_eq!(report.outcome, "invalid_protocol");
        assert_eq!(report.failure_reason, Some("agent_frame_limit"));
        assert!(report.output_bytes <= MAX_REQUEST + 8192);
    }

    fn container() -> Value {
        json!({
            "Image":"owned-image","State":{"Status":"created"},"Mounts":[],
            "Config":{"Env":["PATCHRIOT_AGENT_MAX_SECONDS=600"],"User":"65534:65534","WorkingDir":"/work","Entrypoint":IMAGE_ENTRY,"Cmd":["owned-model"],"Tty":false,"OpenStdin":true},
            "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"Init":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":2147483648u64,"MemorySwap":2147483648u64,"NanoCpus":2000000000u64,"PidsLimit":128,"CgroupnsMode":"private","PidMode":"","IpcMode":"private","UTSMode":"","UsernsMode":"","LogConfig":{"Type":"none"},"RestartPolicy":{"Name":"no"},"Tmpfs":TMPFS.into_iter().collect::<std::collections::BTreeMap<_,_>>()}
        })
    }
    #[test]
    fn docker_configuration_must_preserve_the_execution_boundary() {
        assert!(policy(
            &container(),
            "owned-image",
            &["owned-model"],
            600,
            false
        ));
        let mut expanded = container();
        expanded["HostConfig"]["Tmpfs"] = json!(
            temporary_storage(true)
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>()
        );
        assert!(!policy(
            &expanded,
            "owned-image",
            &["owned-model"],
            600,
            false
        ));
        assert!(policy(
            &expanded,
            "owned-image",
            &["owned-model"],
            600,
            true
        ));
        assert!(!policy(
            &container(),
            "owned-image",
            &["owned-model"],
            600,
            true
        ));
        for (pointer, value) in [
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/Memory", json!(0)),
            ("/HostConfig/PidsLimit", json!(-1)),
            ("/HostConfig/SecurityOpt", json!(["seccomp=unconfined"])),
            ("/HostConfig/PidMode", json!("host")),
            ("/Config/Cmd", json!(["other-model"])),
            ("/Config/User", json!("root")),
            ("/Config/Env", json!(["PATCHRIOT_AGENT_MAX_SECONDS=1800"])),
            ("/Mounts", json!([{"Source":"/var/run/docker.sock"}])),
        ] {
            let mut value_container = container();
            *value_container.pointer_mut(pointer).unwrap() = value;
            assert!(
                !policy(
                    &value_container,
                    "owned-image",
                    &["owned-model"],
                    600,
                    false
                ),
                "{pointer}"
            );
        }
        for key in ["Binds", "Devices", "CapAdd", "PortBindings"] {
            let mut value = container();
            value["HostConfig"][key] = json!(["unexpected"]);
            assert!(
                !policy(&value, "owned-image", &["owned-model"], 600, false),
                "{key}"
            );
        }
    }

    #[test]
    fn operator_configuration_defaults_to_ten_minutes_and_rejects_unbounded_budgets() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut input = json!({"docker_socket":"/var/run/docker.sock", "image":format!("sha256:{}", "b".repeat(64)), "model_url":"http://127.0.0.1:11434", "model":"owned-model", "model_digest":"a".repeat(64)});
        std::fs::write(file.path(), serde_json::to_vec(&input).unwrap()).unwrap();
        assert_eq!(
            Settings::load(file.path()).unwrap().max_attempt_seconds(),
            600
        );
        input["max_attempt_seconds"] = json!(3600);
        std::fs::write(file.path(), serde_json::to_vec(&input).unwrap()).unwrap();
        assert_eq!(
            Settings::load(file.path()).unwrap().max_attempt_seconds(),
            3600
        );
        for value in [
            json!(599),
            json!(3601),
            json!("3600"),
            json!(-1),
            json!(null),
        ] {
            input["max_attempt_seconds"] = value;
            std::fs::write(file.path(), serde_json::to_vec(&input).unwrap()).unwrap();
            assert!(Settings::load(file.path()).is_err());
        }
    }
    #[test]
    fn invalid_provider_key_stops_live_admission_before_docker_or_work_polling() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("provider.key");
        let config = directory.path().join("agent.json");
        std::fs::write(&key, "synthetic-provider-credential-for-tests").unwrap();
        std::fs::write(
            &config,
            serde_json::to_vec(&json!({
                "docker_socket": directory.path().join("absent-docker.sock"),
                "image": format!("sha256:{}", "b".repeat(64)),
                "model_url":"https://api.venice.ai/api/v1",
                "model":"abliteration-abliterated-model-large-v2",
                "model_digest":"", "live_provider_key_file":key
            }))
            .unwrap(),
        )
        .unwrap();
        let settings = Settings::load(&config).unwrap();
        for mode in [0o644, 0o640] {
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                settings.require_live_adapter().unwrap_err().to_string(),
                "provider key file must be private and owned by the relay user"
            );
        }
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            !settings
                .require_live_adapter()
                .unwrap_err()
                .to_string()
                .contains("provider key")
        );
        std::fs::write(&key, "invalid").unwrap();
        assert_eq!(
            settings.require_live_adapter().unwrap_err().to_string(),
            "invalid provider key file"
        );
    }

    #[test]
    fn hosted_model_configuration_requires_the_matching_fixed_provider() {
        use patchriot_protocol::pentests::LiveProvider;
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut input = json!({"docker_socket":"/var/run/docker.sock", "image":format!("sha256:{}", "b".repeat(64)),
            "model_url":"", "model":"", "model_digest":"", "live_provider_key_file":"/private/provider.key"});
        for provider in [
            LiveProvider::Abliteration,
            LiveProvider::Venice,
            LiveProvider::NearDeepSeek,
        ] {
            input["model"] = json!(provider.model());
            input["model_url"] = json!(provider.api_url());
            std::fs::write(file.path(), serde_json::to_vec(&input).unwrap()).unwrap();
            assert!(Settings::load(file.path()).is_ok());
            for url in [
                "https://unapproved.example/v1",
                "https://api.venice.ai/api/v1/other",
            ] {
                input["model_url"] = json!(url);
                std::fs::write(file.path(), serde_json::to_vec(&input).unwrap()).unwrap();
                assert!(Settings::load(file.path()).is_err());
            }
        }
    }
}
