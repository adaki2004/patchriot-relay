use serde_json::Value;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Output},
};

fn invoke(path: &Path, action: &str, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_patchriot-relay"))
        .args([action, "--state-dir"])
        .arg(path)
        .args(extra)
        .output()
        .unwrap()
}

fn initialize(path: &Path, endpoint: &str) -> Output {
    invoke(
        path,
        "init",
        &[
            "--dispatcher",
            endpoint,
            "--audience",
            "fixture-deployment",
            "--label",
            "Local relay",
            "--compute-group",
            "shared-fixture-host",
        ],
    )
}

#[test]
fn initialization_creates_private_identity_and_never_rotates_an_existing_key() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    let output = initialize(&path, "http://127.0.0.1:7411");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["state"], "initialized");
    assert_eq!(result["public_key"].as_str().unwrap().len(), 64);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    for name in ["device.key", "relay.json", "state.lock"] {
        assert_eq!(fs::metadata(path.join(name)).unwrap().mode() & 0o777, 0o600);
    }
    let key_before = fs::read(path.join("device.key")).unwrap();
    assert_eq!(key_before.len(), 32);
    let retry = initialize(&path, "http://127.0.0.1:7411");
    assert!(!retry.status.success());
    assert_eq!(fs::read(path.join("device.key")).unwrap(), key_before);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&hex::encode(&key_before)));
}

#[test]
fn pause_and_resume_persist_without_network_or_leaking_key_material() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    assert!(
        initialize(&path, "https://dispatcher.invalid")
            .status
            .success()
    );
    for (action, expected) in [
        ("pause", true),
        ("status", true),
        ("resume", false),
        ("status", false),
    ] {
        let output = invoke(&path, action, &[]);
        assert!(output.status.success());
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(body["paused"], expected);
        assert!(body.get("private_key").is_none());
        assert!(body.get("key").is_none());
        assert_eq!(body["sequence"], 0);
    }
}

#[test]
fn public_http_and_world_readable_state_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("relay");
    assert!(!initialize(&path, "http://example.com").status.success());
    assert!(!path.exists());
    assert!(
        initialize(&path, "https://dispatcher.invalid")
            .status
            .success()
    );
    fs::set_permissions(path.join("relay.json"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!invoke(&path, "status", &[]).status.success());
}

#[test]
fn hermes_pairing_preserves_the_declaration_and_cannot_run_the_fixture_queue() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("hermes");
    let output = invoke(
        &path,
        "init",
        &[
            "--dispatcher",
            "https://dispatcher.invalid",
            "--audience",
            "pilot",
            "--label",
            "CPU agent",
            "--compute-group",
            "one-machine",
            "--runtime",
            "hermes",
            "--runtime-version",
            "0.22.2",
            "--model",
            "publisher/model:small",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = invoke(&path, "status", &[]);
    let value: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(value["runtime"], "hermes");
    assert_eq!(value["runtime_version"], "0.22.2");
    assert_eq!(value["declared_model"], "publisher/model:small");
    assert_eq!(value["reported_os"], std::env::consts::OS);
    let denied = invoke(&path, "connect", &["--once", "--fixtures"]);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("presence only"));
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(path.join("relay.json")).unwrap()).unwrap()["sequence"],
        0
    );
}

#[test]
fn incomplete_or_misleading_runtime_declarations_do_not_create_an_identity() {
    for extra in [
        vec!["--runtime", "hermes"],
        vec![
            "--runtime",
            "hermes",
            "--runtime-version",
            "1",
            "--model",
            " ",
        ],
        vec!["--runtime", "unknown"],
        vec!["--model", "publisher/model"],
        vec!["--runtime-version", "pretend-version"],
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("rejected");
        let mut args = vec![
            "--dispatcher",
            "https://dispatcher.invalid",
            "--audience",
            "pilot",
            "--label",
            "CPU agent",
            "--compute-group",
            "one-machine",
        ];
        args.extend(extra);
        assert!(!invoke(&path, "init", &args).status.success());
        assert!(!path.exists());
    }
}

#[test]
fn agent_work_requires_explicit_opt_in_and_cannot_run_on_a_fixture_identity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("fixture");
    assert!(
        initialize(&path, "https://dispatcher.invalid")
            .status
            .success()
    );
    for args in [
        vec!["--agents"],
        vec!["--agent-config", "/not/read"],
        vec!["--agents", "--fixtures", "--agent-config", "/not/read"],
        vec!["--agents", "--agent-config", "/not/read"],
    ] {
        assert!(!invoke(&path, "connect", &args).status.success());
        let state: Value =
            serde_json::from_slice(&fs::read(path.join("relay.json")).unwrap()).unwrap();
        assert_eq!(
            state["sequence"], 0,
            "must reject before a network heartbeat or work poll"
        );
        assert_eq!(state["work_sequence"], 0);
    }
}
