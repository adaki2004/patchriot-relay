//! Local maintenance never resets pairing, discards an outbox or installs host code.
use super::*;
use crate::agent::Settings;
use serde_json::{Value, json};
use sha2::Digest;

fn option<'a>(options: &HashMap<&str, &'a str>, name: &str) -> Result<&'a str, Error> {
    options
        .get(name)
        .copied()
        .ok_or_else(|| format!("missing {name}; see --help").into())
}

fn stopped(directory: &Path) -> Result<File, Error> {
    let lock = private_open(&directory.join("daemon.lock"), true)?;
    lock.try_lock().map_err(|_| "stop this relay service before maintenance; its process still holds the connection lock")?;
    Ok(lock)
}

fn idle(config: &Config) -> Result<(), Error> {
    if !config.paused {
        return Err("pause the relay before maintenance".into());
    }
    if config.active_assignment.is_some() || config.pending_result.is_some() {
        return Err("saved work or an undelivered result remains; reconnect with the current configuration to finish delivery, then pause and stop again".into());
    }
    Ok(())
}

fn gateway(config: &Config) -> bool {
    (|| -> Result<bool, Error> {
        let response = client()?
            .get(validate_url(&config.dispatcher)?.join("/health")?)
            .send()?;
        if !response.status().is_success() {
            return Ok(false);
        }
        let mut bytes = Vec::new();
        response.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Ok(false);
        }
        let body: Value = serde_json::from_slice(&bytes)?;
        Ok(body["status"] == "ok" && body["service"] == "patchriot-relay-gateway")
    })()
    .unwrap_or(false)
}

/// The replacement belongs to this device, even when its previous configuration
/// was shared by several services. The operator restarts with the returned path.
fn save_settings(directory: &Path, settings: &Settings) -> Result<PathBuf, Error> {
    let destination = directory.join("agent-settings.json");
    if fs::symlink_metadata(&destination).is_ok() {
        let mut current = Vec::new();
        private_open(&destination, false)?
            .take(8193)
            .read_to_end(&mut current)?;
        if current.len() > 8192 {
            return Err("previous agent configuration exceeds 8 KiB".into());
        }
        let digest = hex::encode(sha2::Sha256::digest(&current));
        let backup = directory.join(format!("agent-settings.before-{digest}.json"));
        if backup.try_exists()? {
            let mut existing = Vec::new();
            private_open(&backup, false)?
                .take(8193)
                .read_to_end(&mut existing)?;
            if existing != current {
                return Err("configuration backup does not match".into());
            }
        } else {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(backup)?;
            file.write_all(&current)?;
            file.sync_all()?;
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer(&mut temporary, settings)?;
    temporary.as_file().sync_all()?;
    temporary.persist(&destination)?;
    File::open(directory)?.sync_all()?;
    Ok(destination)
}

fn new_model_state(
    directory: &Path,
    config: &Config,
    settings: &Settings,
    version: &str,
) -> Result<(), Error> {
    if fs::symlink_metadata(directory).is_ok() {
        return Err(
            "choose a new, nonexistent state directory; the old identity stays intact".into(),
        );
    }
    let options = HashMap::from([
        ("--dispatcher", config.dispatcher.as_str()),
        ("--audience", config.audience.as_str()),
        ("--label", config.introduction.label.as_str()),
        (
            "--compute-group",
            config.introduction.compute_group.as_str(),
        ),
        ("--runtime", "hermes"),
        ("--runtime-version", version),
        ("--model", settings.model_name()),
    ]);
    initialize(directory, &options)?;
    let _lock = state_lock(directory)?;
    let mut next = read_config(directory)?;
    next.paused = true;
    write_config(directory, &next)?;
    save_settings(directory, settings)?;
    Ok(())
}

pub(crate) fn execute(args: &[String]) -> Result<u8, Error> {
    let action = args[0].as_str();
    let mut options = HashMap::new();
    let mut pairs = args[1..].chunks_exact(2);
    for pair in &mut pairs {
        let allowed = match action {
            "doctor" | "self-heal" | "skills" => {
                ["--state-dir", "--agent-config"].contains(&pair[0].as_str())
            }
            "update-agent" => {
                ["--state-dir", "--agent-config", "--candidate-config"].contains(&pair[0].as_str())
            }
            "install-skill" => [
                "--state-dir",
                "--agent-config",
                "--candidate-config",
                "--skill",
            ]
            .contains(&pair[0].as_str()),
            "update-model" => [
                "--state-dir",
                "--candidate-config",
                "--new-state-dir",
                "--runtime-version",
            ]
            .contains(&pair[0].as_str()),
            _ => false,
        };
        if !allowed || options.insert(pair[0].as_str(), pair[1].as_str()).is_some() {
            return Err("unknown or duplicate maintenance option; see --help".into());
        }
    }
    if !pairs.remainder().is_empty() {
        return Err("missing maintenance option value".into());
    }
    let directory = Path::new(option(&options, "--state-dir")?);
    check_state_directory(directory)?;
    if action == "doctor" {
        let _lock = state_lock(directory)?;
        let config = read_config(directory)?;
        let key_ok = read_key(directory).is_ok();
        let running = stopped(directory).is_err();
        drop(_lock);
        let connected = gateway(&config);
        let agent = options
            .get("--agent-config")
            .map(|path| Settings::load(Path::new(path)).and_then(|s| s.installed_capabilities()));
        let healthy = key_ok && connected && agent.as_ref().is_none_or(Result::is_ok);
        let agent = agent.map(|value|value.unwrap_or_else(|_|json!({"ready":false,"next":"Check the pinned image, local Docker socket and private model credentials."})));
        println!(
            "{}",
            json!({"device_id":config.device_id,"connection_process_running":running,"device_key_readable":key_ok,
            "gateway_reachable":connected,"paused":config.paused,"active_work":config.active_assignment.is_some(),"pending_result":config.pending_result.is_some(),"agent":agent,
            "approval_checked":false,"next":if connected {"Gateway reached. Approval and readiness still depend on the signed heartbeat."} else {"Check DNS, HTTPS, the gateway and the configured network route. Never disable TLS verification."}})
        );
        return Ok(u8::from(!healthy));
    }
    if action == "skills" {
        let settings = Settings::load(Path::new(option(&options, "--agent-config")?))?;
        println!("{}", settings.installed_capabilities()?);
        return Ok(0);
    }
    // Take locks in the same order as connect. Re-read state under both locks.
    let _daemon = stopped(directory)?;
    let mut state_guard = state_lock(directory)?;
    let mut config = read_config(directory)?;
    if action == "self-heal" && config.paused && config.pending_result.is_some() {
        // Retry only delivery of the saved receipt. Never poll for an assignment
        // or rerun inference. A failed connection leaves the outbox untouched.
        drop(state_guard);
        send_result(directory, &client()?)?;
        state_guard = state_lock(directory)?;
        config = read_config(directory)?;
    }
    let _state = state_guard;
    idle(&config)?;
    read_key(directory)?;
    if action == "self-heal" {
        let settings = Settings::load(Path::new(option(&options, "--agent-config")?))?;
        settings.installed_capabilities()?;
        if let Some(id) = config.device_id {
            crate::agent::recover(&settings, id)?;
        }
        println!(
            "{}",
            json!({"cleaned_device_containers":true,"pairing_preserved":true,"paused":true,
            "next":"Run doctor, restart the service with the same state/configuration, then resume. Saved results and paid-work markers have not been deleted."})
        );
        return Ok(0);
    }
    let candidate = Settings::load(Path::new(option(&options, "--candidate-config")?))?;
    let capabilities = candidate.installed_capabilities()?;
    if action == "update-model" {
        let next = Path::new(option(&options, "--new-state-dir")?);
        new_model_state(
            next,
            &config,
            &candidate,
            option(&options, "--runtime-version")?,
        )?;
        println!(
            "{}",
            json!({"new_state_dir":next,"agent_config":next.join("agent-settings.json"),"old_identity_preserved":true,"requires_pairing":true,
            "next":"Pair the new device and obtain approval. Future requests need consent for this model. Keep the old device paused or revoke it after its work finishes."})
        );
    } else {
        let current = Settings::load(Path::new(option(&options, "--agent-config")?))?;
        if candidate.model_name() != current.model_name()
            || config.introduction.declared_model.as_deref() != Some(candidate.model_name())
        {
            return Err("model changes require update-model and fresh approval/consent".into());
        }
        if action == "install-skill" {
            let skill = option(&options, "--skill")?;
            if !capabilities["live_tools"]
                .as_array()
                .is_some_and(|tools| tools.iter().any(|tool| tool.as_str() == Some(skill)))
            {
                return Err("the inspected image does not provide this approved skill; use skills to list supported names".into());
            }
        }
        let path = save_settings(directory, &candidate)?;
        println!(
            "{}",
            json!({"agent_config":path,"capabilities":capabilities,"pairing_preserved":true,"paused":true,
            "next":"Restart this service with the returned --agent-config path, run doctor, then resume. Existing shared settings were not changed. Changed Hermes/runtime declarations need a newly paired device."})
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(root: &Path) -> PathBuf {
        let path = root.join("relay");
        initialize(
            &path,
            &HashMap::from([
                ("--dispatcher", "http://127.0.0.1:1"),
                ("--audience", "owned"),
                ("--label", "owned"),
                ("--compute-group", "one"),
            ]),
        )
        .unwrap();
        path
    }
    #[test]
    fn maintenance_refuses_running_unpaused_and_pending_work_without_modifying_state() {
        let root = tempfile::tempdir().unwrap();
        let directory = fixture(root.path());
        let before = fs::read(directory.join("relay.json")).unwrap();
        let lock = stopped(&directory).unwrap();
        assert!(stopped(&directory).is_err());
        drop(lock);
        let mut config = read_config(&directory).unwrap();
        assert!(idle(&config).is_err());
        config.paused = true;
        assert!(idle(&config).is_ok());
        // A pending completion is valuable even after its lease has expired.
        config.pending_result = Some(CompleteWork {
            lease_id: Uuid::nil(),
            result: WorkResult::Fixture(patchriot_protocol::FixtureResult { runs: Vec::new() }),
        });
        assert!(idle(&config).is_err());
        let original_key = fs::read(directory.join("device.key")).unwrap();
        assert_eq!(before, fs::read(directory.join("relay.json")).unwrap());
        assert_eq!(
            original_key,
            fs::read(directory.join("device.key")).unwrap()
        );
    }
    #[test]
    fn per_device_settings_are_atomic_private_and_refuse_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let directory = fixture(root.path());
        let path = root.path().join("candidate.json");
        fs::write(&path,json!({"docker_socket":"/var/run/docker.sock","image":format!("sha256:{}","b".repeat(64)),"model_url":"http://127.0.0.1:11434","model":"owned-model","model_digest":"a".repeat(64)}).to_string()).unwrap();
        let settings = Settings::load(&path).unwrap();
        let first = save_settings(&directory, &settings).unwrap();
        assert_eq!(
            fs::metadata(&first).unwrap().permissions().mode() & 0o777,
            0o600
        );
        save_settings(&directory, &settings).unwrap();
        assert!(fs::read_dir(&directory).unwrap().any(|p| {
            p.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("agent-settings.before-")
        }));
        let other = fixture(&root.path().join("other"));
        std::os::unix::fs::symlink(&path, other.join("agent-settings.json")).unwrap();
        assert!(save_settings(&other, &settings).is_err());
    }

    #[test]
    fn a_model_change_creates_a_paused_unpaired_identity_and_keeps_the_old_key() {
        let root = tempfile::tempdir().unwrap();
        let directory = fixture(root.path());
        let mut config = read_config(&directory).unwrap();
        config.paused = true;
        let old_key = fs::read(directory.join("device.key")).unwrap();
        let old_config = fs::read(directory.join("relay.json")).unwrap();
        let candidate = root.path().join("candidate.json");
        fs::write(&candidate,json!({"docker_socket":"/var/run/docker.sock","image":format!("sha256:{}","b".repeat(64)),"model_url":"http://127.0.0.1:11434","model":"new-owned-model","model_digest":"a".repeat(64)}).to_string()).unwrap();
        let settings = Settings::load(&candidate).unwrap();
        let next = root.path().join("new-model");
        new_model_state(&next, &config, &settings, "0.22.5").unwrap();
        let created = read_config(&next).unwrap();
        assert!(created.paused && created.device_id.is_none() && created.pairing_id.is_none());
        assert_eq!(
            created.introduction.declared_model.as_deref(),
            Some("new-owned-model")
        );
        assert_eq!(
            created.introduction.compute_group,
            config.introduction.compute_group
        );
        assert_ne!(fs::read(next.join("device.key")).unwrap(), old_key);
        assert_eq!(fs::read(directory.join("device.key")).unwrap(), old_key);
        assert_eq!(fs::read(directory.join("relay.json")).unwrap(), old_config);
        assert!(new_model_state(&next, &config, &settings, "0.22.5").is_err());
    }

    #[test]
    fn self_heal_keeps_an_outbox_when_delivery_is_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let directory = fixture(root.path());
        let mut config = read_config(&directory).unwrap();
        config.paused = true;
        config.device_id = Some(Uuid::nil());
        config.pending_result = Some(CompleteWork {
            lease_id: Uuid::nil(),
            result: WorkResult::Fixture(patchriot_protocol::FixtureResult { runs: Vec::new() }),
        });
        write_config(&directory, &config).unwrap();
        let before = fs::read(directory.join("relay.json")).unwrap();
        assert!(
            execute(&[
                "self-heal".into(),
                "--state-dir".into(),
                directory.to_str().unwrap().into(),
                "--agent-config".into(),
                "never-read.json".into()
            ])
            .is_err()
        );
        assert_eq!(before, fs::read(directory.join("relay.json")).unwrap());
    }
}
