//! Explicit owned-example check through a pinned, network-isolated agent image.
//! This is not yet an admission path for customer code or queued model work.

use crate::{
    docker::{Container, Docker, immutable_image, no_entries},
    inference::{Broker, Frame, MAX_REQUEST, Request},
    process::Outcome,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    docker_socket: PathBuf,
    image: String,
    model_url: String,
    model: String,
    model_digest: String,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Wire {
    Request { request: Request },
    Event { event: String, data: Value },
}

#[derive(Serialize)]
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
    broker: Broker,
    cancelled: &AtomicBool,
    timeout: Duration,
) -> io::Result<AgentRun> {
    let started = Instant::now();
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
    let deadline = tokio::time::sleep(timeout);
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
                if cancelled.load(Ordering::Relaxed) {
                    report.outcome = "cancelled";
                    break;
                }
            }
            n = stderr.read(&mut err), if err_open => {
                let n = n?;
                err_open = n != 0;
                report.output_bytes += n;
                if report.output_bytes > 1_048_576 {
                    report.outcome = "output_limit";
                    break;
                }
            }
            n = stdout.read(&mut out), if out_open => {
                let n = n?;
                out_open = n != 0;
                report.output_bytes += n;
                if report.output_bytes > 1_048_576 {
                    report.outcome = "output_limit";
                    break;
                }
                pending.extend_from_slice(&out[..n]);
                while let Some(end) = pending.iter().position(|&b| b == b'\n') {
                    if end > MAX_REQUEST {
                        report.outcome = "invalid_protocol";
                        break 'running;
                    }
                    let wire = serde_json::from_slice::<Wire>(&pending[..end]);
                    pending.drain(..=end);
                    match wire {
                        Ok(Wire::Request { request }) => {
                            report.requests += 1;
                            if active.is_some() || request.id <= last_id || report.requests > 32 || final_seen {
                                report.outcome = "invalid_protocol";
                                break 'running;
                            }
                            last_id = request.id;
                            active = Some(request.id);
                            if request.path == "/v1/chat/completions" {
                                report.inference_calls += 1;
                                if report.inference_calls > 4 {
                                    report.outcome = "inference_limit";
                                    break 'running;
                                }
                                if let Err(reason) = broker.chat(&request) {
                                    eprintln!("agent request rejected: {reason}");
                                    report.outcome = "invalid_model_request";
                                    break 'running;
                                }
                                eprintln!("agent requested model call {}", report.inference_calls);
                            }
                            if let Some(previous) = task.0.take() {
                                previous.abort();
                            }
                            let broker = broker.clone();
                            let tx = tx.clone();
                            task.0 = Some(tokio::spawn(async move { broker.respond(request, tx).await; }));
                        }
                        Ok(Wire::Event { event, data })
                            if ["phase", "tool_start", "tool_complete", "result"].contains(&event.as_str()) && !final_seen => {
                            if event == "result" {
                                final_seen = true;
                            }
                            if event == "tool_start" {
                                eprintln!("agent started a tool");
                            }
                            report.events.push(json!({"event":event,"data":data}));
                        }
                        _ => {
                            report.outcome = "invalid_protocol";
                            break 'running;
                        }
                    }
                }
                if pending.len() > MAX_REQUEST {
                    report.outcome = "invalid_protocol";
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
    Ok(report)
}

fn policy(container: &Value, image: &str, model: &str) -> bool {
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
                TMPFS
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
        && c["Cmd"] == json!([model])
        && c["Tty"] == false
        && c["OpenStdin"] == true
}

pub fn execute(args: &[String]) -> Result<u8, Box<dyn std::error::Error>> {
    if args.len() != 3 || args[1] != "--config" {
        return Err("usage: patchriot-relay agent-check --config PATH".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&args[2])?
        .take(8193)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err("agent configuration exceeds 8 KiB".into());
    }
    let settings: Settings =
        serde_json::from_slice(&bytes).map_err(|_| "invalid agent configuration")?;
    if !immutable_image(&settings.image) {
        return Err("agent image must be an immutable local sha256 image ID".into());
    }
    let docker = Docker::new(Path::new(&settings.docker_socket))?;
    let image = docker.inspect("image", &settings.image)?;
    if image["Id"] != settings.image
        || image["Os"] != "linux"
        || image["Config"]["Entrypoint"] != json!(IMAGE_ENTRY)
        || image["Config"]["User"] != "65534:65534"
        || image["Config"]["Labels"]["io.patchriot.agent-adapter"] != "1"
        || !no_entries(&image["Config"]["OnBuild"])
        || !no_entries(&image["Config"]["Healthcheck"])
    {
        return Err("build the pinned agent/Dockerfile image before this check".into());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let broker = runtime.block_on(Broker::connect(
        &settings.model_url,
        &settings.model,
        &settings.model_digest,
    ))?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
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
    ];
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
    for (path, options) in TMPFS {
        command.extend(["--tmpfs".into(), format!("{path}:{options}")]);
    }
    command.push(settings.image.clone());
    command.push(settings.model.clone());
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
            &settings.model,
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
            &cancelled,
            Duration::from_secs(600),
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
                    && e["data"]["observed_fixture_regression"] == true
                    && e["data"]["completed"] == true
            });
        Ok((report, stopped, state["State"]["OOMKilled"].clone(), passed))
    })();
    let cleanup = owned.cleanup();
    if !cleanup {
        return Err("agent cleanup could not be confirmed; inspect containers labelled io.patchriot.agent-check=1".into());
    }
    let (report, stopped, oom, passed) = result?;
    serde_json::to_writer_pretty(
        io::stdout().lock(),
        &json!({"schema_version":1,"mode":"owned_agent_check","evidence_source":"agent_reported_owned_example_not_independent_verification","container":owned.name,"model":settings.model,"model_digest":settings.model_digest,"image":settings.image,"policy_verified":true,"network":"none; bounded model requests over pipes","container_stopped":stopped,"oom_killed":oom,"cleanup_confirmed":cleanup,"passed":passed && cleanup,"run":report}),
    )?;
    println!();
    Ok(u8::from(!(passed && cleanup)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new("/bin/sh");
        command.env_clear().args(["-c", script]);
        command
    }
    async fn run(script: &str, cancelled: &AtomicBool, timeout: Duration) -> AgentRun {
        supervise(
            command(script),
            crate::inference::tests::broker(),
            cancelled,
            timeout,
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
        assert_eq!(
            run(
                &format!("{RESULT}; {RESULT}"),
                &cancelled,
                Duration::from_secs(2)
            )
            .await
            .outcome,
            "invalid_protocol"
        );
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
        assert!(report.output_bytes <= MAX_REQUEST + 8192);
    }

    fn container() -> Value {
        json!({
            "Image":"owned-image","State":{"Status":"created"},"Mounts":[],
            "Config":{"User":"65534:65534","WorkingDir":"/work","Entrypoint":IMAGE_ENTRY,"Cmd":["owned-model"],"Tty":false,"OpenStdin":true},
            "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"Init":true,"CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Memory":2147483648u64,"MemorySwap":2147483648u64,"NanoCpus":2000000000u64,"PidsLimit":128,"CgroupnsMode":"private","PidMode":"","IpcMode":"private","UTSMode":"","UsernsMode":"","LogConfig":{"Type":"none"},"RestartPolicy":{"Name":"no"},"Tmpfs":TMPFS.into_iter().collect::<std::collections::BTreeMap<_,_>>()}
        })
    }
    #[test]
    fn docker_configuration_must_preserve_the_execution_boundary() {
        assert!(policy(&container(), "owned-image", "owned-model"));
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
            ("/Mounts", json!([{"Source":"/var/run/docker.sock"}])),
        ] {
            let mut value_container = container();
            *value_container.pointer_mut(pointer).unwrap() = value;
            assert!(
                !policy(&value_container, "owned-image", "owned-model"),
                "{pointer}"
            );
        }
        for key in ["Binds", "Devices", "CapAdd", "PortBindings"] {
            let mut value = container();
            value["HostConfig"][key] = json!(["unexpected"]);
            assert!(!policy(&value, "owned-image", "owned-model"), "{key}");
        }
    }
}
