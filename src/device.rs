//! Persistent device identity, presence and optional owned-example assignments.
//! No remote shell is exposed. Private keys stay in the operator's state directory.

use patchriot_protocol::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

type Error = Box<dyn std::error::Error>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u8,
    dispatcher: String,
    audience: String,
    introduction: DeviceIntroduction,
    pairing_id: Option<Uuid>,
    device_id: Option<Uuid>,
    sequence: u64,
    paused: bool,
    #[serde(default)]
    work_sequence: u64,
    #[serde(default)]
    active_assignment: Option<WorkAssignment>,
    #[serde(default)]
    pending_result: Option<CompleteWork>,
    #[serde(default)]
    renewal_sequence: u64,
}

fn private_open(path: &Path, create: bool) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(
            "state files must be regular files readable only by their owner (chmod 600)".into(),
        );
    }
    Ok(file)
}

fn state_lock(directory: &Path) -> Result<File, Error> {
    let file = private_open(&directory.join("state.lock"), true)?;
    file.lock()?;
    Ok(file)
}

fn read_config(directory: &Path) -> Result<Config, Error> {
    let file = private_open(&directory.join("relay.json"), false)?;
    if file.metadata()?.len() > 16 * 1024 {
        return Err("state file too large".into());
    }
    let config: Config = serde_json::from_reader(file)?;
    if config.schema_version != 1 {
        return Err("unsupported state version".into());
    }
    validate_url(&config.dispatcher)?;
    config.introduction.validate()?;
    Ok(config)
}

fn write_config(directory: &Path, config: &Config) -> Result<(), Error> {
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(&mut temporary, config)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(directory.join("relay.json"))?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn write_agent_report(directory: &Path, report: &serde_json::Value) -> Result<(), Error> {
    let bytes = serde_json::to_vec(report)?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("local agent report exceeded its limit".into());
    }
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(directory.join("last-agent-check.json"))?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn read_key(directory: &Path) -> Result<DeviceKey, Error> {
    let file = private_open(&directory.join("device.key"), false)?;
    if file.metadata()?.len() != 32 {
        return Err("invalid local device key".into());
    }
    let mut seed = Zeroizing::new([0; 32]);
    file.take(32).read_exact(seed.as_mut())?;
    Ok(DeviceKey::from_bytes(&seed))
}

fn validate_url(value: &str) -> Result<url::Url, Error> {
    let url = url::Url::parse(value).map_err(|_| "invalid dispatcher URL")?;
    let loopback = match url.host() {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("dispatcher needs HTTPS (HTTP only on loopback), with no credentials, path, query or fragment".into());
    }
    Ok(url)
}

fn client() -> Result<reqwest::blocking::Client, Error> {
    Ok(reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("patchriot-relay/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

#[derive(Debug)]
struct RemoteError {
    status: u16,
}
impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dispatcher returned HTTP {}", self.status)
    }
}
impl std::error::Error for RemoteError {}

fn post<T: Serialize, R: DeserializeOwned>(
    client: &reqwest::blocking::Client,
    config: &Config,
    key: &DeviceKey,
    path: &str,
    payload: T,
) -> Result<R, Error> {
    let signed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?;
    let request = sign(key, &config.audience, path, signed_at, payload)?;
    let url = validate_url(&config.dispatcher)?.join(path)?;
    let response = client
        .post(url)
        .json(&request)
        .send()
        .map_err(|_| "dispatcher request failed; check connectivity and TLS")?;
    if !response.status().is_success() {
        return Err(Box::new(RemoteError {
            status: response.status().as_u16(),
        }));
    }
    // Treat even a configured server's output as bounded input; redirects are disabled.
    let mut bytes = Vec::new();
    response.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 16 * 1024 {
        return Err("dispatcher response exceeded limit".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn initialize(directory: &Path, options: &HashMap<&str, &str>) -> Result<(), Error> {
    let required = |name| {
        options
            .get(name)
            .copied()
            .ok_or("missing init option; see --help")
    };
    let dispatcher = validate_url(required("--dispatcher")?)?.to_string();
    let audience = required("--audience")?.to_owned();
    if audience.is_empty() || audience.len() > 200 || audience.chars().any(char::is_control) {
        return Err("invalid audience".into());
    }
    let introduction = DeviceIntroduction {
        label: required("--label")?.into(),
        runtime: match options.get("--runtime").copied().unwrap_or("owned_fixture") {
            "owned_fixture" => RuntimeKind::OwnedFixture,
            "hermes" => RuntimeKind::Hermes,
            _ => return Err("supported runtimes: owned_fixture or hermes".into()),
        },
        runtime_version: options
            .get("--runtime-version")
            .copied()
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .into(),
        declared_model: options.get("--model").map(|value| (*value).to_owned()),
        compute_group: required("--compute-group")?.into(),
        slots: 1,
    };
    match introduction.runtime {
        RuntimeKind::Hermes
            if !options.contains_key("--runtime-version")
                || introduction
                    .declared_model
                    .as_ref()
                    .is_none_or(|m| m.trim().is_empty()) =>
        {
            return Err("Hermes pairing requires --runtime-version and --model; these are operator declarations".into());
        }
        RuntimeKind::OwnedFixture
            if options.contains_key("--runtime-version") || options.contains_key("--model") =>
        {
            return Err(
                "owned fixtures use the built-in runtime version and do not declare a model".into(),
            );
        }
        _ => {}
    }
    introduction.validate()?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("state directory must be private (chmod 700), not a symlink".into());
    }
    let _lock = state_lock(directory)?;
    if directory.join("relay.json").exists() || directory.join("device.key").exists() {
        return Err("state already exists; choose a different directory".into());
    }
    let mut seed = Zeroizing::new([0; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| "OS random source unavailable")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("device.key"))?;
    file.write_all(seed.as_ref())?;
    file.sync_all()?;
    write_config(
        directory,
        &Config {
            schema_version: 1,
            dispatcher,
            audience,
            introduction,
            pairing_id: None,
            device_id: None,
            sequence: 0,
            paused: false,
            work_sequence: 0,
            active_assignment: None,
            pending_result: None,
            renewal_sequence: 0,
        },
    )?;
    println!(
        "{}",
        serde_json::json!({"state":"initialized", "public_key":hex::encode(DeviceKey::from_bytes(&seed).verifying_key().as_bytes())})
    );
    Ok(())
}

fn pair(directory: &Path) -> Result<(), Error> {
    let _lock = state_lock(directory)?;
    let mut config = read_config(directory)?;
    let key = read_key(directory)?;
    let pair: PairingStarted = post(
        &client()?,
        &config,
        &key,
        PAIRING_START_PATH,
        &config.introduction,
    )?;
    config.pairing_id = Some(pair.pairing_id);
    write_config(directory, &config)?;
    println!("{}", serde_json::to_string(&pair)?);
    eprintln!(
        "Claim this code in your Patchriot account. Device approval is a separate admin action."
    );
    Ok(())
}

fn tick(directory: &Path, client: &reqwest::blocking::Client) -> Result<Option<String>, Error> {
    let _lock = state_lock(directory)?;
    let mut config = read_config(directory)?;
    let key = read_key(directory)?;
    if config.device_id.is_none() {
        let pairing_id = config.pairing_id.ok_or("run pair first")?;
        let reply: PairingStatus = post(
            client,
            &config,
            &key,
            PAIRING_STATUS_PATH,
            PairingStatusInput { pairing_id },
        )?;
        config.device_id = reply.device_id;
        write_config(directory, &config)?;
        if config.device_id.is_none() {
            println!("{}", serde_json::to_string(&reply)?);
            if reply.state == "expired" {
                return Err("pairing expired; run pair again".into());
            }
            return Ok(None);
        }
    }
    let id = config.device_id.ok_or("missing device identity")?;
    config.sequence = config
        .sequence
        .checked_add(1)
        .filter(|s| *s <= i64::MAX as u64)
        .ok_or("heartbeat sequence exhausted")?;
    // Reserve the sequence durably before sending. A lost response or restart
    // skips a number instead of accidentally reusing it for different content.
    write_config(directory, &config)?;
    // Do not hold the local state lock during a potentially slow network call;
    // pause/status must remain available while the dispatcher is unreachable.
    drop(_lock);
    let reply: HeartbeatReply = post(
        client,
        &config,
        &key,
        &format!("/v1/devices/{id}/heartbeat"),
        Heartbeat {
            sequence: config.sequence,
            paused: config.paused,
            running: u16::from(config.active_assignment.as_ref().is_some_and(|a| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .is_ok_and(|now| (now.as_secs() as i64) < a.expires_at)
            })),
        },
    )?;
    println!(
        "{}",
        serde_json::json!({"device_id":id,"state":reply.state,"sequence":reply.sequence})
    );
    Ok(Some(reply.state))
}

fn clear_assignment(directory: &Path) -> Result<(), Error> {
    let _lock = state_lock(directory)?;
    let mut config = read_config(directory)?;
    config.active_assignment = None;
    config.pending_result = None;
    write_config(directory, &config)
}

fn send_result(directory: &Path, client: &reqwest::blocking::Client) -> Result<(), Error> {
    let (config, key) = {
        let _lock = state_lock(directory)?;
        (read_config(directory)?, read_key(directory)?)
    };
    let Some(result) = &config.pending_result else {
        return Ok(());
    };
    let id = config.device_id.ok_or("missing device identity")?;
    let reply = post::<_, WorkAccepted>(
        client,
        &config,
        &key,
        &format!("/v1/devices/{id}/work/complete"),
        result,
    );
    match reply {
        Ok(accepted) => {
            if !accepted.accepted {
                return Err("dispatcher did not accept the saved result".into());
            }
            println!(
                "{}",
                serde_json::json!({"event":if result.result.mode().is_fixture() { "fixture_result_accepted" } else { "agent_result_accepted" },"mode":result.result.mode(),"lease_id":result.lease_id,"fixture_matches":accepted.fixture_matches,"replayed":accepted.replayed})
            );
            clear_assignment(directory)?;
        }
        Err(error)
            if error
                .downcast_ref::<RemoteError>()
                .is_some_and(|e| [404, 409].contains(&e.status)) =>
        {
            // A cancelled, superseded or expired lease cannot be resurrected by
            // an outbox retry. Discard only this saved result, never reinterpret it.
            clear_assignment(directory)?;
            eprintln!("saved result no longer has an active lease");
        }
        Err(error) => return Err(error), // Keep the outbox for a network retry.
    }
    Ok(())
}

fn work_tick(
    directory: &Path,
    client: &reqwest::blocking::Client,
    stop: &Arc<AtomicBool>,
    agent: Option<&crate::agent::Settings>,
) -> Result<(), Error> {
    send_result(directory, client)?;
    let (config, key) = {
        let _lock = state_lock(directory)?;
        let mut config = read_config(directory)?;
        if config.paused || stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        config.work_sequence = config
            .work_sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("work sequence exhausted")?;
        write_config(directory, &config)?;
        (config, read_key(directory)?)
    };
    let id = config.device_id.ok_or("missing device identity")?;
    let reply: WorkReply = post(
        client,
        &config,
        &key,
        &format!("/v1/devices/{id}/work/poll"),
        WorkPoll {
            sequence: config.work_sequence,
        },
    )?;
    let Some(assignment) = reply.assignment else {
        clear_assignment(directory)?;
        return Ok(());
    };
    if (assignment.mode == ReviewMode::OwnedAgent) != agent.is_some() {
        return Err("assignment mode does not match the opted-in local runtime".into());
    }
    {
        let _lock = state_lock(directory)?;
        let mut latest = read_config(directory)?;
        latest.active_assignment = Some(assignment.clone());
        write_config(directory, &latest)?;
    }
    if let Some(settings) = agent {
        return agent_work(directory, client, stop, settings, &assignment);
    }
    let ready = || {
        let Ok(_lock) = state_lock(directory) else {
            return false;
        };
        read_config(directory).is_ok_and(|config| !config.paused)
    };
    println!(
        "{}",
        serde_json::json!({"event":"fixture_started","review_id":assignment.review_id,"role":assignment.role,"lease_id":assignment.lease_id})
    );
    if let Some(result) = crate::work::execute(&assignment, stop, ready)? {
        {
            let _lock = state_lock(directory)?;
            let mut latest = read_config(directory)?;
            // Save before POST: losing a response must not require fabricating a
            // new result or rerunning an already completed assignment.
            latest.pending_result = Some(result);
            write_config(directory, &latest)?;
        }
        send_result(directory, client)?;
    }
    Ok(())
}

fn renew(
    directory: &Path,
    client: &reqwest::blocking::Client,
    lease_id: Uuid,
) -> Result<(Instant, WorkRenewed), Error> {
    let (config, key) = {
        let _lock = state_lock(directory)?;
        let mut config = read_config(directory)?;
        if config.paused || config.active_assignment.as_ref().map(|a| a.lease_id) != Some(lease_id)
        {
            return Err("assignment is no longer locally active".into());
        }
        config.renewal_sequence = config
            .renewal_sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or("renewal sequence exhausted")?;
        write_config(directory, &config)?;
        (config, read_key(directory)?)
    };
    let id = config.device_id.ok_or("missing device identity")?;
    let started = Instant::now();
    let reply: WorkRenewed = post(
        client,
        &config,
        &key,
        &format!("/v1/devices/{id}/work/renew"),
        RenewWork {
            lease_id,
            sequence: config.renewal_sequence,
        },
    )?;
    if reply.lease_id != lease_id
        || reply.sequence != config.renewal_sequence
        || reply.valid_for_seconds > 60
        || reply.expires_at > reply.deadline_at
    {
        return Err("invalid lease renewal reply".into());
    }
    {
        let _lock = state_lock(directory)?;
        let mut latest = read_config(directory)?;
        if let Some(active) = &mut latest.active_assignment
            && active.lease_id == lease_id
        {
            active.expires_at = reply.expires_at;
            write_config(directory, &latest)?;
        }
    }
    Ok((started, reply))
}

/// All work uses this monotonic deadline. A response delayed in transit cannot
/// grant another minute, and expiry latches even if a late renewal arrives.
struct LeaseWindow(Mutex<(Instant, bool)>);
impl LeaseWindow {
    fn new(started: Instant, valid_seconds: u64) -> Self {
        Self(Mutex::new((
            started + Duration::from_secs(valid_seconds.saturating_sub(5)),
            false,
        )))
    }
    fn stopped_at(&self, now: Instant) -> bool {
        let Ok(mut state) = self.0.lock() else {
            return true;
        };
        state.1 |= now >= state.0;
        state.1
    }
    fn stop(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.1 = true;
        }
    }
    fn extend_at(&self, started: Instant, valid_seconds: u64, now: Instant) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        let until = started + Duration::from_secs(valid_seconds.saturating_sub(5));
        state.1 |= now >= state.0 || now >= until;
        if !state.1 {
            state.0 = until;
        }
    }
}

fn locally_ready(directory: &Path, lease_id: Uuid) -> bool {
    let Ok(_lock) = state_lock(directory) else {
        return false;
    };
    read_config(directory).is_ok_and(|c| {
        !c.paused && c.active_assignment.as_ref().map(|a| a.lease_id) == Some(lease_id)
    })
}

fn agent_work(
    directory: &Path,
    client: &reqwest::blocking::Client,
    stop: &Arc<AtomicBool>,
    settings: &crate::agent::Settings,
    assignment: &WorkAssignment,
) -> Result<(), Error> {
    // Renew before spawning even when a cached poll reply contains an assignment.
    // The server must confirm that it is still this device's active lease.
    let (started, renewed) = renew(directory, client, assignment.lease_id)?;
    let window = LeaseWindow::new(started, renewed.valid_for_seconds);
    let config = read_config(directory)?;
    let device_id = config.device_id.ok_or("missing device identity")?;
    let declared_model = config
        .introduction
        .declared_model
        .as_deref()
        .ok_or("missing model declaration")?;
    let done = AtomicBool::new(false);
    struct StopMonitor<'a>(&'a AtomicBool);
    impl Drop for StopMonitor<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    println!(
        "{}",
        serde_json::json!({"event":"agent_started","review_id":assignment.review_id,"role":assignment.role,"lease_id":assignment.lease_id})
    );
    std::thread::scope(|scope| {
        let monitor = scope.spawn(|| {
            struct StopWindow<'a>(&'a LeaseWindow);
            impl Drop for StopWindow<'_> {
                fn drop(&mut self) {
                    self.0.stop();
                }
            }
            let _stop_window = StopWindow(&window);
            let mut heartbeat_at = Instant::now() + Duration::from_secs(10);
            let mut renew_at = Instant::now() + Duration::from_secs(20);
            while !done.load(Ordering::Relaxed) {
                if stop.load(Ordering::Relaxed)
                    || window.stopped_at(Instant::now())
                    || !locally_ready(directory, assignment.lease_id)
                {
                    window.stop();
                    break;
                }
                if Instant::now() >= heartbeat_at {
                    match tick(directory, client) {
                        Ok(Some(state)) if ["online", "busy"].contains(&state.as_str()) => {}
                        Err(error) if !terminal_remote_error(&error) => {
                            eprintln!("heartbeat retry pending")
                        }
                        _ => {
                            window.stop();
                            break;
                        }
                    }
                    heartbeat_at = Instant::now() + Duration::from_secs(10);
                }
                if Instant::now() >= renew_at {
                    match renew(directory, client, assignment.lease_id) {
                        Ok((started, reply)) => {
                            window.extend_at(started, reply.valid_for_seconds, Instant::now())
                        }
                        Err(error) if !terminal_remote_error(&error) => {
                            eprintln!("lease renewal retry pending")
                        }
                        _ => {
                            window.stop();
                            break;
                        }
                    }
                    renew_at = Instant::now() + Duration::from_secs(10);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let stop_monitor = StopMonitor(&done);
        let result = (|| {
            let check = crate::agent::run(
                settings,
                Some(crate::agent::Assignment {
                    device_id,
                    lease_id: assignment.lease_id,
                    declared_model,
                }),
                &|| stop.load(Ordering::Relaxed) || window.stopped_at(Instant::now()),
            )?;
            // Keep one bounded private trace for operator diagnosis. It is never
            // printed or sent to the website; only typed observations are sent.
            write_agent_report(directory, &check.report)?;
            if stop.load(Ordering::Relaxed)
                || window.stopped_at(Instant::now())
                || !locally_ready(directory, assignment.lease_id)
            {
                clear_assignment(directory)?;
                eprintln!("agent stopped; lease ended or work was cancelled");
                return Ok(());
            }
            {
                let _lock = state_lock(directory)?;
                let mut latest = read_config(directory)?;
                latest.pending_result = Some(CompleteWork {
                    lease_id: assignment.lease_id,
                    result: WorkResult::Agent(check.result),
                });
                write_config(directory, &latest)?;
            }
            send_result(directory, client)
        })();
        drop(stop_monitor);
        if monitor.join().is_err() {
            return Err("lease monitor stopped unexpectedly".into());
        }
        result
    })
}

fn terminal_remote_error(error: &Error) -> bool {
    error
        .downcast_ref::<RemoteError>()
        .is_some_and(|e| [400, 401, 403, 404, 409, 422].contains(&e.status))
}

pub fn execute(args: &[String]) -> Result<u8, Error> {
    let action = args[0].as_str();
    let mut options = HashMap::new();
    let mut once = false;
    let mut fixtures = false;
    let mut agents = false;
    let mut args = args[1..].iter();
    while let Some(name) = args.next() {
        if name == "--once" && action == "connect" && !once {
            once = true;
            continue;
        }
        if name == "--fixtures" && action == "connect" && !fixtures {
            fixtures = true;
            continue;
        }
        if name == "--agents" && action == "connect" && !agents {
            agents = true;
            continue;
        }
        let allowed = name == "--state-dir"
            || action == "connect" && name == "--agent-config"
            || action == "init"
                && [
                    "--dispatcher",
                    "--audience",
                    "--label",
                    "--compute-group",
                    "--runtime",
                    "--runtime-version",
                    "--model",
                ]
                .contains(&name.as_str());
        if !allowed {
            return Err("unknown option; see --help".into());
        }
        let value = args.next().ok_or("missing option value")?;
        if options.insert(name.as_str(), value.as_str()).is_some() {
            return Err("duplicate option".into());
        }
    }
    let directory = PathBuf::from(
        options
            .get("--state-dir")
            .ok_or("--state-dir is required")?,
    );
    if action == "init" {
        initialize(&directory, &options)?;
        return Ok(0);
    }
    // Other operations never create a missing state directory or follow a symlink.
    let metadata = fs::symlink_metadata(&directory)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("state directory must be private (chmod 700), not a symlink".into());
    }
    match action {
        "pair" => pair(&directory)?,
        "status" | "pause" | "resume" => {
            let _lock = state_lock(&directory)?;
            let mut config = read_config(&directory)?;
            if action != "status" {
                config.paused = action == "pause";
                write_config(&directory, &config)?;
            }
            println!(
                "{}",
                serde_json::json!({"device_id":config.device_id,"pairing_id":config.pairing_id,"label":config.introduction.label,"runtime":config.introduction.runtime,"runtime_version":config.introduction.runtime_version,"declared_model":config.introduction.declared_model,"paused":config.paused,"sequence":config.sequence})
            );
        }
        "connect" => {
            if fixtures && agents || agents != options.contains_key("--agent-config") {
                return Err(
                    "choose --fixtures or --agents --agent-config PATH; each is explicit opt-in"
                        .into(),
                );
            }
            if fixtures
                && read_config(&directory)?.introduction.runtime != RuntimeKind::OwnedFixture
            {
                return Err("--fixtures is only for owned_fixture devices; without --agents a Hermes relay reports presence only".into());
            }
            if agents && read_config(&directory)?.introduction.runtime != RuntimeKind::Hermes {
                return Err("--agents requires a paired Hermes runtime declaration".into());
            }
            let settings = options
                .get("--agent-config")
                .map(|path| crate::agent::Settings::load(Path::new(path)))
                .transpose()?;
            let daemon_lock = private_open(&directory.join("daemon.lock"), true)?;
            daemon_lock
                .try_lock()
                .map_err(|_| "another relay is already using this state directory")?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))?;
            let client = client()?;
            let mut failures = 0;
            let mut recovered = false;
            loop {
                let result = tick(&directory, &client).and_then(|state| {
                    if (fixtures || agents)
                        && state
                            .as_deref()
                            .is_some_and(|s| ["online", "busy"].contains(&s))
                    {
                        if let Some(settings) = &settings
                            && !recovered
                        {
                            let id = read_config(&directory)?
                                .device_id
                                .ok_or("missing device identity")?;
                            crate::agent::recover(settings, id)?;
                            recovered = true;
                        }
                        work_tick(&directory, &client, &stop, settings.as_ref())?;
                    }
                    Ok(())
                });
                match result {
                    Ok(()) => failures = 0,
                    Err(error) => {
                        // Never print response bodies, private keys or signed requests.
                        eprintln!("{error}");
                        if once
                            || agents
                            || error.is::<crate::work::CleanupUnconfirmed>()
                            || error
                                .downcast_ref::<RemoteError>()
                                .is_some_and(|e| [401, 403, 409].contains(&e.status))
                        {
                            return Ok(1);
                        }
                        failures = (failures + 1).min(3);
                    }
                }
                if once {
                    break;
                }
                let delay = 10 * (1 + failures);
                for _ in 0..delay * 10 {
                    if stop.load(Ordering::Relaxed) {
                        return Ok(0);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
        _ => return Err("unknown device command".into()),
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_time_excludes_transit_and_late_replies_cannot_revive_expired_work() {
        let start = Instant::now();
        let lease = LeaseWindow::new(start, 60);
        assert!(!lease.stopped_at(start + Duration::from_secs(54)));
        lease.extend_at(
            start + Duration::from_secs(40),
            60,
            start + Duration::from_secs(45),
        );
        assert!(!lease.stopped_at(start + Duration::from_secs(94)));
        assert!(lease.stopped_at(start + Duration::from_secs(95)));
        lease.extend_at(
            start + Duration::from_secs(94),
            60,
            start + Duration::from_secs(96),
        );
        assert!(lease.stopped_at(start + Duration::from_secs(96)));

        let delayed = LeaseWindow::new(start, 10);
        assert!(delayed.stopped_at(start + Duration::from_secs(8)));
        let late = LeaseWindow::new(start, 60);
        late.extend_at(
            start + Duration::from_secs(50),
            60,
            start + Duration::from_secs(56),
        );
        assert!(late.stopped_at(start + Duration::from_secs(56)));
        let cancelled = LeaseWindow::new(start, 60);
        cancelled.stop();
        cancelled.extend_at(start, 60, start);
        assert!(cancelled.stopped_at(start));
        assert!(LeaseWindow::new(start, 4).stopped_at(start));
    }

    #[test]
    fn local_agent_trace_is_private_bounded_and_keeps_only_the_last_run() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("last-agent-check.json");
        write_agent_report(directory.path(), &serde_json::json!({"run":1})).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let before = fs::read(&path).unwrap();
        assert!(
            write_agent_report(
                directory.path(),
                &serde_json::json!({"output":"x".repeat(2 * 1024 * 1024)})
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        write_agent_report(directory.path(), &serde_json::json!({"run":2})).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&fs::read(path).unwrap()).unwrap()["run"],
            2
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn endpoints_require_tls_except_explicit_loopback() {
        for good in [
            "https://dispatcher.example",
            "http://127.0.0.1:7411",
            "http://[::1]:7411",
            "http://localhost:7411",
        ] {
            assert!(validate_url(good).is_ok(), "{good}");
        }
        for bad in [
            "http://example.com",
            "http://192.168.1.1",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com?secret=value",
            "https://example.com#fragment",
            "file:///tmp/server",
        ] {
            assert!(validate_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refuses_permissive_or_symlinked_private_files() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("device.key");
        fs::write(&file, [1; 32]).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_key(directory.path()).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_key(directory.path()).is_ok());
        let link = directory.path().join("linked.key");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(private_open(&link, false).is_err());
    }
}
