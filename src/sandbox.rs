//! An opt-in, local Docker check using our finite probes. This is deliberately
//! separate from the fixture queue: no requester can choose commands or images.
//! The host/runtime remains trusted; these checks are not remote attestation.

use crate::{
    docker::{Container, Docker, immutable_image, no_entries},
    process::{self, Limits, Outcome, ProcessReport},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const TMPFS: &str = "rw,noexec,nosuid,nodev,size=16m,mode=1777";
const LABEL: &str = "io.patchriot.sandbox-check=1";
const POLICY_CHECKS: &[&str] = &[
    "non_root",
    "no_capabilities",
    "no_new_privileges",
    "seccomp_filter",
    "network_isolated",
    "root_read_only",
    "workspace_writable",
    "workspace_noexec",
    "host_canary_hidden",
    "symlink_cannot_read_host",
    "no_runtime_socket",
    "no_parent_environment",
    "memory_limited",
    "swap_disabled",
    "cpu_limited",
    "tasks_limited",
];

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Check {
    name: String,
    passed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    schema_version: u8,
    checks: Vec<Check>,
}

#[derive(Serialize)]
struct ProbeReport {
    probe: &'static str,
    container: String,
    policy_verified: bool,
    process: Option<ProcessReport>,
    container_started: bool,
    container_stopped: bool,
    oom_killed: bool,
    exit_code: Option<i64>,
    checks: Vec<Check>,
    error: Option<&'static str>,
    cleanup_confirmed: bool,
    passed: bool,
}

fn image_allowed(image: &Value, expected: &str) -> bool {
    image["Id"] == expected
        && image["Os"] == "linux"
        && image["Config"]["Entrypoint"] == json!(["/probe"])
        && image["Config"]["User"] == "65534:65534"
        && image["Config"]["Labels"]["io.patchriot.fixture-probe"] == "1"
        && no_entries(&image["Config"]["Volumes"])
        && no_entries(&image["Config"]["OnBuild"])
        && no_entries(&image["Config"]["Healthcheck"])
        && environment_allowed(&image["Config"]["Env"])
}

fn environment_allowed(value: &Value) -> bool {
    let Some(vars) = value.as_array() else {
        return false;
    };
    vars.len() == 2 && vars.contains(&json!("PATH=/")) && vars.contains(&json!("HOME=/work"))
}

/// Check what the engine created, not only which flags we asked it to accept.
fn policy_allowed(container: &Value, image: &str) -> bool {
    let host = &container["HostConfig"];
    let config = &container["Config"];
    container["Image"] == image
        && container["State"]["Status"] == "created"
        && host["NetworkMode"] == "none"
        && host["ReadonlyRootfs"] == true
        && host["Privileged"] == false
        && host["Init"] == true
        && host["CapDrop"] == json!(["ALL"])
        && no_entries(&host["CapAdd"])
        && host["SecurityOpt"] == json!(["no-new-privileges"])
        && host["Memory"] == 67_108_864
        && host["MemorySwap"] == 67_108_864
        && host["NanoCpus"] == 500_000_000
        && host["PidsLimit"] == 32
        && host["CgroupnsMode"] == "private"
        && host["PidMode"] == ""
        && host["IpcMode"] == "private"
        && host["UTSMode"] == ""
        && host["UsernsMode"] != "host"
        && host["LogConfig"]["Type"] == "none"
        && host["RestartPolicy"]["Name"] == "no"
        && host["Tmpfs"] == json!({"/work": TMPFS, "/tmp": TMPFS})
        && [
            "Binds",
            "VolumesFrom",
            "Devices",
            "DeviceRequests",
            "DeviceCgroupRules",
            "GroupAdd",
        ]
        .iter()
        .all(|key| no_entries(&host[*key]))
        && no_entries(&container["Mounts"])
        && no_entries(&config["Volumes"])
        && no_entries(&config["Healthcheck"])
        && config["User"] == "65534:65534"
        && config["WorkingDir"] == "/work"
        && config["Entrypoint"] == json!(["/probe"])
        && config["Tty"] == false
        && config["OpenStdin"] == false
        && environment_allowed(&config["Env"])
}

fn evidence_matches(stdout: &[u8], expected: &[&str]) -> Option<Vec<Check>> {
    let evidence: Evidence = serde_json::from_slice(stdout).ok()?;
    (evidence.schema_version == 1
        && evidence.checks.len() == expected.len()
        && evidence
            .checks
            .iter()
            .zip(expected)
            .all(|(check, name)| check.name == *name))
    .then_some(evidence.checks)
}

fn run_probe(
    docker: &Docker,
    image: &str,
    probe: &'static str,
    canary: &str,
    cancelled: &AtomicBool,
) -> io::Result<ProbeReport> {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce)
        .map_err(|_| io::Error::other("cannot generate a container name"))?;
    let mut owned = Container {
        docker,
        name: format!("patchriot-check-{}", hex::encode(nonce)),
        cleaned: false,
    };
    let mut report = ProbeReport {
        probe,
        container: owned.name.clone(),
        policy_verified: false,
        process: None,
        container_started: false,
        container_stopped: false,
        oom_killed: false,
        exit_code: None,
        checks: Vec::new(),
        error: None,
        cleanup_confirmed: false,
        passed: false,
    };
    let actual_probe = if probe == "timeout" || probe == "cancellation" {
        "slow"
    } else {
        probe
    };
    let work_mount = format!("/work:{TMPFS}");
    let temp_mount = format!("/tmp:{TMPFS}");
    let mut args = vec![
        "container",
        "create",
        "--pull=never",
        "--name",
        &owned.name,
        "--label",
        LABEL,
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
        "64m",
        "--memory-swap",
        "64m",
        "--cpus",
        "0.5",
        "--pids-limit",
        "32",
        "--init",
        "--cgroupns",
        "private",
        "--ipc",
        "private",
        "--restart",
        "no",
        "--log-driver",
        "none",
        "--tmpfs",
        &work_mount,
        "--tmpfs",
        &temp_mount,
        "--workdir",
        "/work",
        "--entrypoint",
        "/probe",
        "--env",
        "PATH=/",
        "--env",
        "HOME=/work",
        image,
        actual_probe,
    ];
    if probe == "policy" {
        args.push(canary);
    }
    let operation = (|| -> Result<(), &'static str> {
        let created = docker
            .control(&args)
            .map_err(|_| "container_create_failed")?;
        if created.outcome != Outcome::Completed {
            return Err("container_create_unconfirmed");
        }
        let inspection = docker
            .inspect("container", &owned.name)
            .map_err(|_| "container_inspect_failed")?;
        if !policy_allowed(&inspection, image) {
            return Err("runtime_policy_rejected");
        }
        report.policy_verified = true;
        let limits = Limits {
            timeout_ms: if probe == "timeout" { 2_000 } else { 10_000 },
            max_output_bytes: 8_192,
        };
        let cancel_after = (probe == "cancellation").then_some(Duration::from_secs(2));
        report.process = Some(
            process::run(
                docker.command(&["container", "start", "--attach", &owned.name]),
                limits,
                cancelled,
                cancel_after,
                || eprintln!("running sandbox probe: {probe}"),
            )
            .map_err(|_| "container_attach_failed")?,
        );
        if report
            .process
            .as_ref()
            .is_some_and(|p| !matches!(p.outcome, Outcome::Completed | Outcome::ProcessFailed))
        {
            // Killing the attached CLI alone does not stop a container after a
            // timeout/cancellation/output limit. Ordinary nonzero exits first
            // retain Docker's own exit/OOM state instead of racing it with kill.
            let _ = docker.control(&["container", "kill", &owned.name]);
        }
        let mut state = docker
            .inspect("container", &owned.name)
            .map_err(|_| "container_state_unconfirmed")?;
        // Docker can publish the attach exit before the daemon's OOM event has
        // settled. Wait briefly for that evidence; exit 137 alone is NOT proof
        // of memory enforcement, and the success check below still requires OOM.
        if probe == "memory" {
            for _ in 0..10 {
                if state["State"]["OOMKilled"] == true && state["State"]["Running"] == false {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
                state = docker
                    .inspect("container", &owned.name)
                    .map_err(|_| "container_state_unconfirmed")?;
            }
        }
        if state["State"]["Running"] == true {
            let _ = docker.control(&["container", "kill", &owned.name]);
            state = docker
                .inspect("container", &owned.name)
                .map_err(|_| "container_state_unconfirmed")?;
        }
        report.container_started = state["State"]["StartedAt"]
            .as_str()
            .is_some_and(|v| !v.is_empty() && !v.starts_with("0001-"));
        report.oom_killed = state["State"]["OOMKilled"] == true;
        report.container_stopped =
            state["State"]["Status"] == "exited" && state["State"]["Running"] == false;
        // A running container's zero ExitCode is only a placeholder, not a
        // successful exit. Timeout/cancel cleanup is confirmed separately.
        report.exit_code = (state["State"]["Status"] == "exited")
            .then(|| state["State"]["ExitCode"].as_i64())
            .flatten();
        let process = report.process.as_ref().ok_or("missing_process_result")?;
        let expected = match probe {
            "policy" => POLICY_CHECKS,
            "disk" => &["workspace_size_enforced"],
            "tasks" => &["task_limit_enforced"],
            "descendant" => &["separate_process_group_started"],
            _ => &[],
        };
        report.passed = report.container_started
            && report.container_stopped
            && match probe {
                "memory" => {
                    process.outcome == Outcome::ProcessFailed
                        && report.oom_killed
                        && report.exit_code == Some(137)
                }
                "timeout" => process.outcome == Outcome::TimedOut,
                "cancellation" => {
                    process.outcome == Outcome::Cancelled && !cancelled.load(Ordering::Relaxed)
                }
                "noisy" => process.outcome == Outcome::OutputLimit,
                _ => {
                    report.checks = evidence_matches(&process.stdout, expected).unwrap_or_default();
                    process.outcome == Outcome::Completed
                        && report.exit_code == Some(0)
                        && report.checks.len() == expected.len()
                        && report.checks.iter().all(|check| check.passed)
                }
            };
        Ok(())
    })();
    report.error = operation.err();
    report.cleanup_confirmed = owned.cleanup();
    report.passed &= report.error.is_none() && report.cleanup_confirmed;
    Ok(report)
}

pub fn execute(args: &[String]) -> Result<u8, Box<dyn std::error::Error>> {
    let mut socket = None;
    let mut image = None;
    let mut flags = args[1..].chunks_exact(2);
    for pair in &mut flags {
        match pair[0].as_str() {
            "--socket" if socket.is_none() => socket = Some(pair[1].as_str()),
            "--image" if image.is_none() => image = Some(pair[1].as_str()),
            _ => return Err("unknown or duplicate sandbox option; see --help".into()),
        }
    }
    if !flags.remainder().is_empty() {
        return Err("sandbox option is missing its value".into());
    }
    let image = image
        .filter(|v| immutable_image(v))
        .ok_or("--image requires the locally built probe's sha256 image ID")?;
    let socket = Path::new(socket.ok_or("--socket requires the local Docker Unix socket path")?);
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || signal.store(true, Ordering::Relaxed))?;
    let docker = Docker::new(socket)?;
    if !image_allowed(&docker.inspect("image", image)?, image) {
        return Err(
            "image does not match the owned probe configuration; build sandbox/Dockerfile".into(),
        );
    }
    let canary = tempfile::Builder::new()
        .prefix("patchriot-host-canary-")
        .tempdir()?;
    let canary_path = canary.path().join("host-only");
    std::fs::write(
        &canary_path,
        b"owned host canary; never mounted into a task",
    )?;
    let path = canary_path.to_str().ok_or("canary path must be UTF-8")?;
    let mut runs = Vec::new();
    for probe in [
        "policy",
        "disk",
        "tasks",
        "descendant",
        "memory",
        "timeout",
        "cancellation",
        "noisy",
    ] {
        if cancelled.load(Ordering::Relaxed) {
            break;
        }
        let report = run_probe(&docker, image, probe, path, &cancelled)?;
        let passed = report.passed;
        runs.push(report);
        if !passed {
            break;
        }
    }
    let passed =
        runs.len() == 8 && runs.iter().all(|r| r.passed) && !cancelled.load(Ordering::Relaxed);
    serde_json::to_writer_pretty(
        io::stdout().lock(),
        &json!({"schema_version": 1, "mode": "owned_sandbox_checks", "image": image, "passed": passed, "cancelled": cancelled.load(Ordering::Relaxed), "runs": runs}),
    )?;
    println!();
    Ok(u8::from(!passed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_reference_is_immutable_and_cannot_be_an_option_or_registry() {
        assert!(immutable_image(&format!("sha256:{}", "a0".repeat(32))));
        for bad in [
            "latest",
            "--privileged",
            "sha256:abc",
            "registry/image:tag",
            "SHA256:abc",
        ] {
            assert!(!immutable_image(bad));
        }
    }

    #[test]
    fn evidence_rejects_missing_duplicate_or_invented_checks() {
        for bad in [
            json!({"schema_version":1,"checks":[]}),
            json!({"schema_version":1,"checks":[{"name":"a","passed":true},{"name":"a","passed":true}]}),
            json!({"schema_version":1,"checks":[{"name":"a","passed":true},{"name":"b","passed":true}],"override":true}),
        ] {
            assert!(evidence_matches(&serde_json::to_vec(&bad).unwrap(), &["a", "b"]).is_none());
        }
    }

    #[test]
    fn failed_checks_are_preserved_for_diagnosis() {
        let evidence = br#"{"schema_version":1,"checks":[{"name":"a","passed":false}]}"#;
        assert!(!evidence_matches(evidence, &["a"]).unwrap()[0].passed);
    }

    #[test]
    fn probe_image_must_not_introduce_hidden_code_mounts_or_environment() {
        let image = json!({
            "Id":"owned-image", "Os":"linux", "Config":{
                "User":"65534:65534", "Entrypoint":["/probe"],
                "Labels":{"io.patchriot.fixture-probe":"1"}, "Env":["PATH=/","HOME=/work"],
                "Volumes":null, "OnBuild":null, "Healthcheck":null
            }
        });
        assert!(image_allowed(&image, "owned-image"));
        for (field, change) in [
            ("/Id", json!("other-image")),
            ("/Os", json!("windows")),
            ("/Config/User", json!("root")),
            ("/Config/Entrypoint", json!(["/shell"])),
            ("/Config/Labels/io.patchriot.fixture-probe", json!("2")),
            ("/Config/Volumes", json!({"/hidden":{}})),
            ("/Config/OnBuild", json!(["RUN unexpected"])),
            ("/Config/Healthcheck", json!({"Test":["CMD","/unexpected"]})),
            (
                "/Config/Env",
                json!(["PATH=/", "HOME=/work", "LD_PRELOAD=/unexpected"]),
            ),
        ] {
            let mut changed = image.clone();
            *changed.pointer_mut(field).unwrap() = change;
            assert!(!image_allowed(&changed, "owned-image"), "{field}");
        }
    }

    fn valid_policy() -> Value {
        json!({
            "Image":"owned-image", "State":{"Status":"created"}, "Mounts":[],
            "HostConfig":{
                "NetworkMode":"none", "ReadonlyRootfs":true, "Privileged":false, "Init":true,
                "CapDrop":["ALL"], "CapAdd":null, "SecurityOpt":["no-new-privileges"],
                "Memory":67108864, "MemorySwap":67108864, "NanoCpus":500000000, "PidsLimit":32,
                "CgroupnsMode":"private", "PidMode":"", "IpcMode":"private", "UTSMode":"", "UsernsMode":"",
                "LogConfig":{"Type":"none"}, "RestartPolicy":{"Name":"no"},
                "Tmpfs":{"/work":TMPFS,"/tmp":TMPFS}, "Binds":null, "VolumesFrom":null,
                "Devices":[], "DeviceRequests":null, "DeviceCgroupRules":null, "GroupAdd":null
            },
            "Config":{
                "User":"65534:65534", "WorkingDir":"/work", "Entrypoint":["/probe"],
                "Tty":false, "OpenStdin":false, "Volumes":null, "Healthcheck":null,
                "Env":["HOME=/work","PATH=/"]
            }
        })
    }

    #[test]
    fn runtime_cannot_silently_weaken_the_requested_policy() {
        let valid = valid_policy();
        assert!(policy_allowed(&valid, "owned-image"));
        for (field, weaker) in [
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/CapAdd", json!(["SYS_ADMIN"])),
            ("/HostConfig/SecurityOpt", json!(["seccomp=unconfined"])),
            ("/HostConfig/Memory", json!(0)),
            ("/HostConfig/MemorySwap", json!(-1)),
            ("/HostConfig/NanoCpus", json!(0)),
            ("/HostConfig/PidsLimit", json!(-1)),
            ("/HostConfig/CgroupnsMode", json!("host")),
            ("/HostConfig/PidMode", json!("host")),
            ("/HostConfig/IpcMode", json!("host")),
            ("/HostConfig/UsernsMode", json!("host")),
            ("/HostConfig/Tmpfs", json!({"/work":"rw,exec,size=1g"})),
            ("/HostConfig/Binds", json!(["/home:/host"])),
            (
                "/Mounts",
                json!([{"Type":"bind","Source":"/var/run/docker.sock"}]),
            ),
            ("/Config/User", json!("0")),
            (
                "/Config/Env",
                json!(["HOME=/work", "PATH=/", "PRIVATE_TOKEN=synthetic"]),
            ),
            ("/Config/Volumes", json!({"/hidden":{}})),
            ("/Config/Healthcheck", json!({"Test":["CMD","/unexpected"]})),
            ("/Config/Entrypoint", json!(["/unexpected"])),
            ("/State/Status", json!("running")),
            ("/Image", json!("different-image")),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(field).unwrap() = weaker;
            assert!(!policy_allowed(&changed, "owned-image"), "{field}");
        }
        assert!(!policy_allowed(&json!({}), "owned-image"));
    }
}
