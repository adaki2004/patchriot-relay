//! Persistent device identity, presence and optional owned-example assignments.
//! No remote shell is exposed. Private keys stay in the operator's state directory.

use patchriot_protocol::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
// One protocol-sized result plus the device identity and assignment. Keeping
// this below the accepted result size loses completed work before delivery.
// Compact JSON makes this bound independent of pretty-print indentation.
const MAX_STATE: u64 = patchriot_protocol::pentests::MAX_RESULT_BYTES as u64 + 128 * 1024;

// Read data rather than sourcing this file as a shell script. Only OS name and
// version leave the machine; hostname, kernel details and IDs are not collected.
fn os_release(text: &str) -> Option<(String, Option<String>)> {
    if text.len() > 16 * 1024 {
        return None;
    }
    let field = |key: &str| {
        text.lines()
            .filter_map(|line| line.split_once('='))
            .find_map(|(name, value)| {
                if name != key {
                    return None;
                }
                let value = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                    .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                    .unwrap_or(value);
                (!value.trim().is_empty()
                    && value.len() <= 80
                    && value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || " ._-/()+".contains(c)))
                .then(|| value.to_owned())
            })
    };
    Some((field("NAME")?, field("VERSION_ID")))
}

fn reported_system() -> AgentSystem {
    let release = if cfg!(target_os = "linux") {
        ["/etc/os-release", "/usr/lib/os-release"]
            .into_iter()
            .find_map(|path| {
                let mut text = String::new();
                File::open(path)
                    .ok()?
                    .take(16 * 1024 + 1)
                    .read_to_string(&mut text)
                    .ok()?;
                os_release(&text)
            })
    } else {
        None
    };
    let (os_name, os_version) = release.unwrap_or_else(|| (std::env::consts::OS.into(), None));
    AgentSystem {
        os_name,
        os_version,
        architecture: std::env::consts::ARCH.into(),
        relay_version: env!("CARGO_PKG_VERSION").into(),
    }
}

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

pub(crate) mod maintenance;

fn require_state_owner(metadata: &fs::Metadata) -> Result<(), Error> {
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err("state belongs to another Unix user; run the relay as the account that owns its state directory and files".into());
    }
    Ok(())
}

fn check_state_directory(directory: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("state directory must be private (chmod 700), not a symlink".into());
    }
    // An accidental sudo invocation must not replace another user's state files.
    require_state_owner(&metadata)
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
    require_state_owner(&metadata)?;
    Ok(file)
}

fn state_lock(directory: &Path) -> Result<File, Error> {
    let file = private_open(&directory.join("state.lock"), true)?;
    file.lock()?;
    Ok(file)
}

fn read_config(directory: &Path) -> Result<Config, Error> {
    let file = private_open(&directory.join("relay.json"), false)?;
    if file.metadata()?.len() > MAX_STATE {
        return Err("state file too large".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_STATE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE {
        return Err("state file too large".into());
    }
    let config: Config = serde_json::from_slice(&bytes)?;
    if config.schema_version != 1 {
        return Err("unsupported state version".into());
    }
    validate_url(&config.dispatcher)?;
    config.introduction.validate()?;
    Ok(config)
}

fn write_config(directory: &Path, config: &Config) -> Result<(), Error> {
    let bytes = serde_json::to_vec(config)?;
    if bytes.len() as u64 + 1 > MAX_STATE {
        return Err("state file too large".into());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(&bytes)?;
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

// Keep one bounded, private recovery artifact per device. This is diagnostic
// evidence from interrupted work, and never an outbox that can revive a lease.
fn preserve_interrupted_result(directory: &Path, result: &CompleteWork) -> Result<(), Error> {
    let bytes = serde_json::to_vec(result)?;
    if bytes.len() as u64 > MAX_STATE {
        return Err("interrupted result exceeded its limit".into());
    }
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(directory.join("last-interrupted-work.json"))?;
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
        // TLS through the operator's gateway may take several seconds. Leave
        // room for that handshake without extending the whole request or lease.
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(10))
        .user_agent(concat!("patchriot-relay/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

#[derive(Debug)]
struct RemoteError {
    status: u16,
    code: Option<&'static str>,
}
impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dispatcher returned HTTP {}", self.status)?;
        if let Some(code) = self.code {
            write!(f, " ({code})")?;
        }
        Ok(())
    }
}
impl std::error::Error for RemoteError {}

#[derive(Debug)]
struct DispatcherConnectionError(&'static str);
impl std::fmt::Display for DispatcherConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dispatcher {}", self.0)
    }
}
impl std::error::Error for DispatcherConnectionError {}

fn retryable_dispatcher_error(error: &Error) -> bool {
    error.is::<DispatcherConnectionError>()
        || error
            .downcast_ref::<RemoteError>()
            .is_some_and(|e| e.status == 429 || e.status >= 500)
}

fn post<T: Serialize, R: DeserializeOwned>(
    client: &reqwest::blocking::Client,
    config: &Config,
    key: &DeviceKey,
    path: &str,
    payload: T,
) -> Result<R, Error> {
    post_with_limit(client, config, key, path, payload, 16 * 1024)
}

fn post_with_limit<T: Serialize, R: DeserializeOwned>(
    client: &reqwest::blocking::Client,
    config: &Config,
    key: &DeviceKey,
    path: &str,
    payload: T,
    maximum: u64,
) -> Result<R, Error> {
    let completion = path.ends_with("/work/complete");
    let evidence = path.ends_with("/work/pentest-evidence");
    // Negotiate via a distinct endpoint: old servers return 404 before seeing
    // any result. Only that response enables the original signed JSON transport.
    // A lost response is retried from the durable outbox with the same payload.
    let compressed_path = format!("{path}-gzip");
    let mut compressed = completion || evidence;
    let response = loop {
        let request_path = if compressed { &compressed_path } else { path };
        let signed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .try_into()?;
        let request = sign(key, &config.audience, request_path, signed_at, &payload)?;
        let url = validate_url(&config.dispatcher)?.join(request_path)?;
        let outgoing = if compressed && completion {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            serde_json::to_writer(&mut encoder, &request)?;
            encoder.flush()?;
            client
                .post(url)
                .header(reqwest::header::CONTENT_TYPE, "application/gzip")
                .body(encoder.finish()?)
        } else {
            client.post(url).json(&request)
        };
        // Reports can reach 32 MiB. Allow slow links without extending heartbeat
        // deadlines or the server's 120-second signature freshness window.
        let outgoing = if completion || evidence {
            outgoing.timeout(Duration::from_secs(90))
        } else {
            outgoing
        };
        let response = outgoing.send().map_err(|error| {
            DispatcherConnectionError(if error.is_timeout() {
                "request timed out"
            } else if error.is_connect() {
                "connection failed"
            } else {
                "request failed"
            })
        })?;
        if compressed && response.status() == reqwest::StatusCode::NOT_FOUND {
            compressed = false;
            continue;
        }
        break response;
    };
    if !response.status().is_success() {
        let status = response.status().as_u16();
        // Log only known protocol codes. Server bodies can contain private
        // content and must never be forwarded to the operator's journal.
        let mut bytes = Vec::new();
        let _ = response.take(4096).read_to_end(&mut bytes);
        let value = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
        let code = [
            "device_not_ready",
            "lease_no_longer_active",
            "invalid_live_progress",
            "stale_renewal",
            "private_work_not_allowed",
            "selected_tool_unavailable",
        ]
        .into_iter()
        .find(|code| value.as_ref().and_then(|v| v["error"].as_str()) == Some(*code));
        return Err(Box::new(RemoteError { status, code }));
    }
    let gzip = match response.headers().get(reqwest::header::CONTENT_ENCODING) {
        None => false,
        Some(value) if value == "gzip" && evidence => true,
        _ => return Err("dispatcher returned unsupported response encoding".into()),
    };
    // Bound both wire bytes and expanded JSON. A highly compressible response
    // cannot bypass the normal evidence limit. Redirects remain disabled.
    let mut bytes = Vec::new();
    response
        .take(maximum + if gzip { 8193 } else { 1 })
        .read_to_end(&mut bytes)
        .map_err(|_| DispatcherConnectionError("response read failed"))?;
    if gzip {
        if bytes.len() as u64 > maximum + 8192 {
            return Err("dispatcher response exceeded limit".into());
        }
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .take(maximum + 1)
            .read_to_end(&mut decoded)
            .map_err(|_| "dispatcher returned invalid compressed evidence")?;
        bytes = decoded;
    }
    if bytes.len() as u64 > maximum {
        return Err("dispatcher response exceeded limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "dispatcher returned an invalid reply".into())
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
        reported_os: Some(std::env::consts::OS.into()),
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
    check_state_directory(directory)?;
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
        )
        .map_err(|error| -> Error {
            if error
                .downcast_ref::<RemoteError>()
                .is_some_and(|reply| reply.status == 404)
            {
                // Starting another pairing removes expired, unclaimed records.
                "pairing not found (HTTP 404); check the dispatcher address, then run pair again with the same --state-dir".into()
            } else {
                error
            }
        })?;
        config.device_id = reply.device_id;
        write_config(directory, &config)?;
        if config.device_id.is_none() {
            println!("{}", serde_json::to_string(&reply)?);
            if reply.state == "expired" {
                return Err("pairing expired; run pair again with the same --state-dir to keep the device key".into());
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
            system: Some(reported_system()),
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
    let funding_blocked = config.pending_result.as_ref().is_some_and(|saved| {
        matches!(&saved.result, WorkResult::Pentest(result)
            if result.execution.state == patchriot_protocol::website_reviews::WebsiteRunState::Failed
                && result.execution.failure_reason.as_deref() == Some("provider_payment_required"))
    });
    // Only after delivery acknowledgement (or preserving a fenced outbox) can
    // we pause: doing it earlier would stop the result's own lease renewals.
    // Keep the pause durable so restart cannot consume the rest of the queue.
    if funding_blocked {
        config.paused = true;
    }
    config.active_assignment = None;
    config.pending_result = None;
    write_config(directory, &config)?;
    if funding_blocked {
        eprintln!("worker paused: provider_payment_required; restore funding before resume");
    }
    Ok(())
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
                serde_json::json!({"event":if result.result.mode().is_fixture() { "fixture_result_accepted" } else { "agent_result_accepted" },"mode":result.result.mode(),"lease_id":result.lease_id,"fixture_matches":accepted.fixture_matches,"evidence_complete":accepted.evidence_complete,"replayed":accepted.replayed})
            );
            clear_assignment(directory)?;
        }
        Err(error)
            if error
                .downcast_ref::<RemoteError>()
                .is_some_and(|e| [404, 409].contains(&e.status)) =>
        {
            // A cancelled, superseded or expired lease cannot be resurrected by
            // an outbox retry. Preserve its evidence before removing the outbox.
            preserve_interrupted_result(directory, result)?;
            clear_assignment(directory)?;
            eprintln!("saved result no longer has an active lease");
        }
        Err(error) => return Err(error), // Keep the outbox for a network retry.
    }
    Ok(())
}

fn send_result_while_active(
    directory: &Path,
    client: &reqwest::blocking::Client,
    active: impl Fn() -> bool,
) -> Result<(), Error> {
    loop {
        match send_result(directory, client) {
            Err(error) if retryable_dispatcher_error(&error) && active() => {
                // Stay inside agent_work's lease-monitor scope. Returning to
                // connect's outer backoff used to stop renewal and lose an
                // already completed report when the upload failed briefly.
                eprintln!("saved result delivery retry pending: {error}");
                for _ in 0..20 {
                    if !active() {
                        return Err(error);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            result => return result,
        }
    }
}

fn work_tick(
    directory: &Path,
    client: &reqwest::blocking::Client,
    stop: &Arc<AtomicBool>,
    agent: Option<&crate::agent::Settings>,
    website_reviews: bool,
    source_reviews: bool,
    live_tests: bool,
) -> Result<(), Error> {
    // Outbox delivery after restart needs the same renewable lease as live
    // execution: the upload deadline can exceed a single 60-second lease.
    let saved = read_config(directory)?;
    let renewal = if let Some(result) = &saved.pending_result
        && !saved.paused
        && saved.active_assignment.as_ref().map(|a| a.lease_id) == Some(result.lease_id)
    {
        match renew(directory, client, result.lease_id, None) {
            Ok((started, renewed)) => Some((result.lease_id, started, renewed)),
            // An already accepted result still needs its idempotent ack.
            Err(error)
                if error
                    .downcast_ref::<RemoteError>()
                    .is_some_and(|e| [404, 409].contains(&e.status)) =>
            {
                None
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    if let Some((lease_id, started, renewed)) = renewal {
        let window = LeaseWindow::new(started, renewed.valid_for_seconds);
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let monitor = scope.spawn(|| {
                monitor_lease(directory, client, stop, &window, &done, lease_id, || None)
            });
            let guard = StopMonitor(&done);
            let result = send_result(directory, client);
            drop(guard);
            if monitor.join().is_err() {
                return Err("saved delivery lease monitor stopped unexpectedly".into());
            }
            result
        })?;
    } else {
        send_result(directory, client)?;
    }
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
            website_reviews,
            source_reviews,
            live_tests,
            live_tools: if live_tests {
                agent
                    .ok_or("live tools require agent settings")?
                    .live_tools()?
            } else {
                vec![]
            },
        },
    )?;
    let Some(assignment) = reply.assignment else {
        clear_assignment(directory)?;
        return Ok(());
    };
    let allowed = match assignment.mode {
        ReviewMode::PentestAgent => {
            agent.is_some()
                && live_tests
                && assignment.scenario == FixtureScenario::LiveHttpV1
                && assignment.pentest.is_some()
                && assignment.source.is_none()
                && assignment.website.is_none()
        }
        ReviewMode::OwnedFixture => {
            agent.is_none()
                && assignment.scenario == FixtureScenario::AccessControlV1
                && assignment.website.is_none()
                && assignment.source.is_none()
        }
        ReviewMode::OwnedAgent => {
            agent.is_some()
                && assignment.scenario == FixtureScenario::AccessControlV1
                && assignment.website.is_none()
                && assignment.source.is_none()
        }
        ReviewMode::WebsiteAgent => {
            agent.is_some()
                && website_reviews
                && assignment.scenario == FixtureScenario::WebsiteSnapshotV1
                && assignment.website.is_some()
                && assignment.source.is_none()
        }
        ReviewMode::SourceAgent => {
            agent.is_some()
                && source_reviews
                && assignment.scenario == FixtureScenario::SourceBundleV1
                && assignment.source.is_some()
                && assignment.website.is_none()
        }
    };
    if !allowed || (assignment.mode != ReviewMode::PentestAgent && assignment.pentest.is_some()) {
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
    progress: Option<patchriot_protocol::pentests::LiveProgress>,
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
            progress,
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

/// The renewable lease controls permission to keep working; this earlier deadline
/// leaves one minute for container cleanup and saving the result. Use the server's
/// remaining duration anchored before the request, not this machine's wall clock.
fn agent_execution_deadline(
    started: Instant,
    renewed: &WorkRenewed,
    operator_limit: u64,
) -> Result<Instant, Error> {
    if !(patchriot_protocol::DEFAULT_AGENT_ATTEMPT_SECONDS
        ..=patchriot_protocol::MAX_AGENT_ATTEMPT_SECONDS)
        .contains(&operator_limit)
    {
        return Err("invalid operator attempt limit".into());
    }
    let after_expiry = renewed
        .deadline_at
        .checked_sub(renewed.expires_at)
        .filter(|difference| *difference >= 0)
        .ok_or("invalid lease deadline")? as u64;
    let remaining = after_expiry
        .saturating_add(renewed.valid_for_seconds)
        .min(operator_limit);
    Ok(started
        + Duration::from_secs(remaining.saturating_sub(patchriot_protocol::AGENT_CLEANUP_SECONDS)))
}

fn monitor_lease(
    directory: &Path,
    client: &reqwest::blocking::Client,
    stop: &AtomicBool,
    window: &LeaseWindow,
    done: &AtomicBool,
    lease_id: Uuid,
    snapshot: impl Fn() -> Option<patchriot_protocol::pentests::LiveProgress>,
) {
    struct StopWindow<'a>(&'a LeaseWindow);
    impl Drop for StopWindow<'_> {
        fn drop(&mut self) {
            self.0.stop();
        }
    }
    let _stop_window = StopWindow(window);
    let mut heartbeat_at = Instant::now() + Duration::from_secs(10);
    let mut renew_at = Instant::now() + Duration::from_secs(20);
    while !done.load(Ordering::Relaxed) {
        let reason = if stop.load(Ordering::Relaxed) {
            Some("operator_stop")
        } else if window.stopped_at(Instant::now()) {
            Some("lease_window_expired")
        } else if !locally_ready(directory, lease_id) {
            Some("local_assignment_unavailable")
        } else {
            None
        };
        if let Some(reason) = reason {
            eprintln!("lease monitor stopped: {reason}");
            window.stop();
            break;
        }
        if Instant::now() >= heartbeat_at {
            match tick(directory, client) {
                Ok(Some(state)) if ["online", "busy"].contains(&state.as_str()) => {}
                Err(error) if !terminal_remote_error(&error) => {
                    eprintln!("heartbeat retry pending")
                }
                Ok(_) => {
                    eprintln!("lease monitor stopped: heartbeat_device_unavailable");
                    window.stop();
                    break;
                }
                Err(error) => {
                    eprintln!("lease monitor stopped: heartbeat_rejected: {error}");
                    window.stop();
                    break;
                }
            }
            heartbeat_at = Instant::now() + Duration::from_secs(10);
        }
        if Instant::now() >= renew_at {
            let renewal_started = Instant::now();
            match renew(directory, client, lease_id, snapshot()) {
                Ok((started, reply)) => {
                    window.extend_at(started, reply.valid_for_seconds, Instant::now());
                    if window.stopped_at(Instant::now()) {
                        eprintln!("lease monitor stopped: renewal_arrived_after_local_expiry");
                        break;
                    }
                }
                Err(error) if !terminal_remote_error(&error) => {
                    eprintln!("lease renewal retry pending")
                }
                Err(error) => {
                    eprintln!("lease monitor stopped: renewal_rejected: {error}");
                    window.stop();
                    break;
                }
            }
            if renewal_started.elapsed() >= Duration::from_secs(2) {
                eprintln!(
                    "lease renewal delayed: duration_ms={}",
                    renewal_started.elapsed().as_millis()
                );
            }
            renew_at = Instant::now() + Duration::from_secs(10);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct StopMonitor<'a>(&'a AtomicBool);
impl Drop for StopMonitor<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn agent_work(
    directory: &Path,
    client: &reqwest::blocking::Client,
    stop: &Arc<AtomicBool>,
    settings: &crate::agent::Settings,
    assignment: &WorkAssignment,
) -> Result<(), Error> {
    if assignment.pentest.is_some()
        && directory
            .join(format!("live-{}.started", assignment.lease_id))
            .try_exists()?
    {
        // Leave the original lease to expire without resetting its progress,
        // purchasing inference again or crashing the device's service.
        eprintln!("live role already started; waiting for its lease to close");
        return Ok(());
    }
    let progress = assignment
        .pentest
        .as_ref()
        .map(|_| crate::agent::live::Progress::default());
    let snapshot = || {
        progress
            .as_ref()
            .and_then(|p| p.try_lock().ok().map(|p| p.clone()))
    };
    // Renew before spawning even when a cached poll reply contains an assignment.
    // The server must confirm that it is still this device's active lease.
    let (started, renewed) = renew(directory, client, assignment.lease_id, snapshot())?;
    let window = LeaseWindow::new(started, renewed.valid_for_seconds);
    let execution_deadline =
        agent_execution_deadline(started, &renewed, settings.max_attempt_seconds())?;
    let config = read_config(directory)?;
    let device_id = config.device_id.ok_or("missing device identity")?;
    let declared_model = config
        .introduction
        .declared_model
        .as_deref()
        .ok_or("missing model declaration")?;
    let done = AtomicBool::new(false);
    println!(
        "{}",
        serde_json::json!({"event":"agent_started","review_id":assignment.review_id,"role":assignment.role,"lease_id":assignment.lease_id})
    );
    std::thread::scope(|scope| {
        let monitor = scope.spawn(|| {
            monitor_lease(
                directory,
                client,
                stop,
                &window,
                &done,
                assignment.lease_id,
                snapshot,
            );
        });
        let stop_monitor = StopMonitor(&done);
        let result = (|| {
            let website = if let Some(website) = &assignment.website {
                let saved = post_with_limit(
                    client,
                    &config,
                    &read_key(directory)?,
                    &format!("/v1/devices/{device_id}/work/evidence"),
                    patchriot_protocol::website_reviews::ReadWorkEvidence {
                        lease_id: assignment.lease_id,
                    },
                    5 * 1024 * 1024,
                )?;
                Some(crate::agent::website::Task {
                    role: assignment.role,
                    snapshot_sha256: website.snapshot_sha256.clone(),
                    evidence: saved,
                })
            } else {
                None
            };
            let source = if let Some(source) = &assignment.source {
                let saved = post_with_limit(
                    client,
                    &config,
                    &read_key(directory)?,
                    &format!("/v1/devices/{device_id}/work/source-evidence"),
                    patchriot_protocol::website_reviews::ReadWorkEvidence {
                        lease_id: assignment.lease_id,
                    },
                    512 * 1024,
                )?;
                Some(crate::agent::source::Task {
                    role: assignment.role,
                    snapshot_sha256: source.snapshot_sha256.clone(),
                    evidence: saved,
                })
            } else {
                None
            };
            let live = if let Some(live) = &assignment.pentest {
                let saved: patchriot_protocol::pentests::PentestEvidence = post_with_limit(
                    client,
                    &config,
                    &read_key(directory)?,
                    &format!("/v1/devices/{device_id}/work/pentest-evidence"),
                    patchriot_protocol::website_reviews::ReadWorkEvidence {
                        lease_id: assignment.lease_id,
                    },
                    patchriot_protocol::pentests::MAX_EVIDENCE_BYTES as u64,
                )?;
                if saved.context.pentest_id != live.pentest_id {
                    return Err("wrong live scope".into());
                }
                Some(crate::agent::live::Task {
                    role: assignment.role,
                    scope_sha256: live.scope_sha256.clone(),
                    evidence: saved,
                })
            } else {
                None
            };
            if live.is_some() {
                // A process restart must not purchase the same role twice. The
                // existing result outbox handles delivery retries separately.
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
                    .open(directory.join(format!("live-{}.started",assignment.lease_id)))
                    .map_err(|_|"live role already started or marker could not be saved; do not rerun paid inference")?
                    .sync_all()?;
            }
            let check = crate::agent::run(
                settings,
                Some(crate::agent::Assignment {
                    device_id,
                    lease_id: assignment.lease_id,
                    declared_model,
                    execution_deadline,
                    progress: progress.as_ref(),
                }),
                website.as_ref(),
                source.as_ref(),
                live.as_ref(),
                &|| stop.load(Ordering::Relaxed) || window.stopped_at(Instant::now()),
            )?;
            if stop.load(Ordering::Relaxed)
                || window.stopped_at(Instant::now())
                || !locally_ready(directory, assignment.lease_id)
            {
                preserve_interrupted_result(
                    directory,
                    &CompleteWork {
                        lease_id: assignment.lease_id,
                        result: check.result,
                    },
                )?;
                clear_assignment(directory)?;
                eprintln!("agent stopped; lease ended or work was cancelled");
                return Ok(());
            }
            {
                let _lock = state_lock(directory)?;
                let mut latest = read_config(directory)?;
                latest.pending_result = Some(CompleteWork {
                    lease_id: assignment.lease_id,
                    result: check.result,
                });
                write_config(directory, &latest)?;
            }
            // The result outbox is durable before optional diagnostic output.
            // A trace failure must not lose evidence or trigger new inference.
            if let Some(report) = &check.report
                && write_agent_report(directory, report).is_err()
            {
                eprintln!(
                    "diagnostic trace could not be saved; result remains queued for delivery"
                );
            }
            send_result_while_active(directory, client, || {
                !stop.load(Ordering::Relaxed)
                    && !window.stopped_at(Instant::now())
                    && locally_ready(directory, assignment.lease_id)
            })
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
    let mut website_reviews = false;
    let mut source_reviews = false;
    let mut live_tests = false;
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
        if name == "--website-reviews" && action == "connect" && !website_reviews {
            website_reviews = true;
            continue;
        }
        if name == "--source-reviews" && action == "connect" && !source_reviews {
            source_reviews = true;
            continue;
        }
        if name == "--live-tests" && action == "connect" && !live_tests {
            live_tests = true;
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
    check_state_directory(&directory)?;
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
                serde_json::json!({"device_id":config.device_id,"pairing_id":config.pairing_id,"label":config.introduction.label,"runtime":config.introduction.runtime,"runtime_version":config.introduction.runtime_version,"declared_model":config.introduction.declared_model,"reported_os":config.introduction.reported_os,"paused":config.paused,"sequence":config.sequence})
            );
        }
        "connect" => {
            if fixtures && agents
                || agents != options.contains_key("--agent-config")
                || (website_reviews || source_reviews || live_tests) && !agents
                || live_tests && (website_reviews || source_reviews)
            {
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
            // Lock before reading agent settings so maintenance cannot race a
            // connection that has already cached the old image/model.
            let daemon_lock = private_open(&directory.join("daemon.lock"), true)?;
            daemon_lock
                .try_lock()
                .map_err(|_| "another relay is already using this state directory")?;
            let settings = options
                .get("--agent-config")
                .map(|path| crate::agent::Settings::load(Path::new(path)))
                .transpose()?;
            if let Some(settings) = &settings
                && read_config(&directory)?
                    .introduction
                    .declared_model
                    .as_deref()
                    != Some(settings.model_name())
            {
                return Err("agent model differs from the paired declaration; use update-model and obtain fresh approval".into());
            }
            if live_tests {
                settings
                    .as_ref()
                    .ok_or("live tests require agent settings")?
                    .require_live_adapter()?;
            }
            if website_reviews {
                settings
                    .as_ref()
                    .ok_or("website reviews require an agent configuration")?
                    .require_website_adapter()?;
            }
            if source_reviews {
                settings
                    .as_ref()
                    .ok_or("source reviews require an agent configuration")?
                    .require_source_adapter()?;
            }
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
                        work_tick(
                            &directory,
                            &client,
                            &stop,
                            settings.as_ref(),
                            website_reviews,
                            source_reviews,
                            live_tests,
                        )?;
                    }
                    Ok(())
                });
                match result {
                    Ok(()) => failures = 0,
                    Err(error) => {
                        // Never print response bodies, private keys or signed requests.
                        eprintln!("{error}");
                        if once
                            || agents && !retryable_dispatcher_error(&error)
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
    #[test]
    fn reports_os_release_without_sourcing_commands_or_machine_details() {
        assert_eq!(
            super::os_release(
                "NAME=\"Kali GNU/Linux\"\nVERSION_ID=\"2026.3\"\nHOSTNAME=private-host\n"
            ),
            Some(("Kali GNU/Linux".into(), Some("2026.3".into())))
        );
        assert_eq!(
            super::os_release("NAME='Debian GNU/Linux'\n"),
            Some(("Debian GNU/Linux".into(), None))
        );
        assert_eq!(super::os_release("NAME=$(id)\n"), None);
        assert_eq!(
            super::os_release("NAME=\"Linux\"\nVERSION_ID=\"$(id)\"\n"),
            Some(("Linux".into(), None))
        );
        assert_eq!(
            super::os_release(&format!("NAME=Linux\n{}", "x".repeat(16 * 1024))),
            None
        );
        assert_eq!(super::os_release("NAME=\"broken\n"), None);
        super::reported_system().validate().unwrap();
    }
    use super::*;

    #[test]
    fn interrupted_paid_lease_waits_without_renewing_or_restarting_inference() {
        let directory = tempfile::tempdir().unwrap();
        let lease_id = Uuid::new_v4();
        let marker = directory.path().join(format!("live-{lease_id}.started"));
        fs::write(&marker, b"").unwrap();
        let assignment = WorkAssignment {
            lease_id,
            review_id: Uuid::new_v4(),
            role: ReviewRole::Investigator,
            scenario: FixtureScenario::LiveHttpV1,
            expires_at: i64::MAX,
            mode: ReviewMode::PentestAgent,
            website: None,
            source: None,
            pentest: Some(pentests::PentestAssignment {
                pentest_id: Uuid::new_v4(),
                scope_sha256: "a".repeat(64),
            }),
        };
        let settings = serde_json::from_value(serde_json::json!({
            "docker_socket":"/unavailable", "image":"unavailable",
            "model_url":"http://127.0.0.1:1", "model":"fixture", "model_digest":"fixture"
        }))
        .unwrap();
        // No config, device key, model or Docker exists. Repeated ordinary
        // agent_work entry must return before touching any of them.
        for _ in 0..2 {
            agent_work(
                directory.path(),
                &client().unwrap(),
                &Arc::new(AtomicBool::new(false)),
                &settings,
                &assignment,
            )
            .unwrap();
        }
        assert!(marker.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn transport_errors_can_retry_but_invalid_replies_cannot_restart_agent_work() {
        use std::net::TcpListener;
        let directory = tempfile::tempdir().unwrap();
        let options = HashMap::from([
            ("--dispatcher", "http://127.0.0.1:1"),
            ("--audience", "test"),
            ("--label", "owned fixture"),
            ("--compute-group", "owned"),
        ]);
        let state = directory.path().join("relay");
        initialize(&state, &options).unwrap();
        let mut config = read_config(&state).unwrap();
        let key = read_key(&state).unwrap();
        let client = client().unwrap();
        for (status, body, declared_length, retryable) in [
            (503, "{}", 2, true),
            (429, "{}", 2, true),
            (403, "{}", 2, false),
            (409, "{\"error\":\"device_not_ready\"}", 28, false),
            (400, "{\"error\":\"private_response\"}", 28, false),
            (200, "{\"partial\":", 50, true),
            (200, "not json", 8, false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            config.dispatcher = format!("http://{}/", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buffer = [0; 4096];
                let mut request = Vec::new();
                loop {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0 && request.len() + count <= 16 * 1024);
                    request.extend_from_slice(&buffer[..count]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                write!(stream,"HTTP/1.1 {status} Test\r\nContent-Length: {declared_length}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}").unwrap();
            });
            let error = post::<_, WorkReply>(
                &client,
                &config,
                &key,
                "/work/poll",
                WorkPoll {
                    sequence: 1,
                    website_reviews: false,
                    source_reviews: false,
                    live_tests: false,
                    live_tools: vec![],
                },
            )
            .unwrap_err();
            assert_eq!(
                retryable_dispatcher_error(&error),
                retryable,
                "status {status}"
            );
            if status == 409 {
                assert!(error.to_string().contains("device_not_ready"));
            }
            assert!(!error.to_string().contains("private_response"));
            server.join().unwrap();
        }
        assert!(!retryable_dispatcher_error(&"model profile changed".into()));
    }

    #[test]
    fn restarted_outbox_keeps_renewing_during_delivery_without_starting_work() {
        use std::net::TcpListener;
        use std::sync::atomic::AtomicUsize;
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("relay");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        initialize(
            &state,
            &HashMap::from([
                ("--dispatcher", url.as_str()),
                ("--audience", "test"),
                ("--label", "Owned fixture"),
                ("--compute-group", "owned"),
            ]),
        )
        .unwrap();
        let lease_id = Uuid::new_v4();
        let mut config = read_config(&state).unwrap();
        config.device_id = Some(Uuid::new_v4());
        config.active_assignment = Some(WorkAssignment {
            lease_id,
            review_id: Uuid::new_v4(),
            role: ReviewRole::Investigator,
            scenario: FixtureScenario::AccessControlV1,
            expires_at: i64::MAX,
            mode: ReviewMode::OwnedFixture,
            website: None,
            source: None,
            pentest: None,
        });
        config.pending_result = Some(CompleteWork {
            lease_id,
            result: WorkResult::Fixture(FixtureResult { runs: vec![] }),
        });
        write_config(&state, &config).unwrap();
        let renewals = Arc::new(AtomicUsize::new(0));
        let observed = renewals.clone();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(35);
            let mut handlers = Vec::new();
            let polled = Arc::new(AtomicBool::new(false));
            while !polled.load(Ordering::Relaxed) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                let renewals = renewals.clone();
                let polled = polled.clone();
                handlers.push(std::thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let mut bytes = Vec::new();
                    let (end, length) = loop {
                        let mut buffer = [0; 8192];
                        let n = stream.read(&mut buffer).unwrap();
                        assert!(n > 0 && bytes.len() < 16384);
                        bytes.extend_from_slice(&buffer[..n]);
                        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            let length: usize = std::str::from_utf8(&bytes[..end]).unwrap().lines().find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                            }).unwrap();
                            if bytes.len() >= end + 4 + length { break (end + 4, length); }
                        }
                    };
                    let path = std::str::from_utf8(&bytes[..end]).unwrap().lines().next().unwrap().split_whitespace().nth(1).unwrap();
                    let body = if path.ends_with("/complete-gzip") {
                        // Hold the completion open until a concurrent renewal arrives.
                        while renewals.load(Ordering::Relaxed) < 2 && Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        assert!(renewals.load(Ordering::Relaxed) >= 2);
                        serde_json::json!({"accepted":true,"fixture_matches":true,"evidence_complete":null,"replayed":false})
                    } else {
                        let request: serde_json::Value = serde_json::from_slice(&bytes[end..end+length]).unwrap();
                        if path.ends_with("/renew") {
                            renewals.fetch_add(1, Ordering::Relaxed);
                            serde_json::json!({"lease_id":lease_id,"sequence":request["payload"]["sequence"],"expires_at":100,"deadline_at":1000,"valid_for_seconds":60,"replayed":false})
                        } else if path.ends_with("/heartbeat") {
                            serde_json::json!({"state":"busy","sequence":request["payload"]["sequence"],"replayed":false})
                        } else {
                            assert!(path.ends_with("/poll"));
                            polled.store(true, Ordering::Relaxed);
                            serde_json::json!({"assignment":null})
                        }
                    }.to_string();
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}",body.len()).unwrap();
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
            assert!(polled.load(Ordering::Relaxed));
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        work_tick(
            &state,
            &client,
            &Arc::new(AtomicBool::new(false)),
            None,
            false,
            false,
            false,
        )
        .unwrap();
        server.join().unwrap();
        assert!(observed.load(Ordering::Relaxed) >= 2);
        assert!(read_config(&state).unwrap().pending_result.is_none());
        assert!(read_config(&state).unwrap().active_assignment.is_none());
    }

    #[test]
    fn evidence_download_negotiates_signed_routes_and_bounds_gzip() {
        use std::net::TcpListener;
        fn gzip(bytes: &[u8]) -> Vec<u8> {
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder.write_all(bytes).unwrap();
            encoder.finish().unwrap()
        }
        for (fallback, encoding, body, expected_error) in [
            (false, "gzip", gzip(br#"{"evidence":"saved"}"#), None),
            (true, "", br#"{"evidence":"saved"}"#.to_vec(), None),
            (
                false,
                "gzip",
                gzip(&vec![b' '; 1025]),
                Some("dispatcher response exceeded limit"),
            ),
            (
                false,
                "gzip",
                vec![0; 1024 + 8193],
                Some("dispatcher response exceeded limit"),
            ),
            (
                false,
                "gzip",
                b"invalid compressed body".to_vec(),
                Some("dispatcher returned invalid compressed evidence"),
            ),
            (
                false,
                "br",
                vec![],
                Some("dispatcher returned unsupported response encoding"),
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let state = directory.path().join("relay");
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/", listener.local_addr().unwrap());
            initialize(
                &state,
                &HashMap::from([
                    ("--dispatcher", url.as_str()),
                    ("--audience", "test"),
                    ("--label", "Owned fixture"),
                    ("--compute-group", "owned"),
                ]),
            )
            .unwrap();
            let config = read_config(&state).unwrap();
            let key = read_key(&state).unwrap();
            let server = std::thread::spawn(move || {
                for attempt in 0..if fallback { 2 } else { 1 } {
                    let path = if attempt == 0 {
                        "/work/pentest-evidence-gzip"
                    } else {
                        "/work/pentest-evidence"
                    };
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let (end, length) = loop {
                        let mut buffer = [0; 8192];
                        let n = stream.read(&mut buffer).unwrap();
                        assert!(n > 0 && bytes.len() < 16384);
                        bytes.extend_from_slice(&buffer[..n]);
                        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                            assert!(headers.starts_with(&format!("POST {path} ")));
                            let length: usize = headers
                                .lines()
                                .find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse().unwrap())
                                })
                                .unwrap();
                            if bytes.len() >= end + 4 + length {
                                break (end + 4, length);
                            }
                        }
                    };
                    let signed: SignedRequest<serde_json::Value> =
                        serde_json::from_slice(&bytes[end..end + length]).unwrap();
                    patchriot_protocol::verify(&signed, "test", path, signed.signed_at).unwrap();
                    assert_eq!(signed.payload, serde_json::json!({"lease":"same"}));
                    let old_endpoint = fallback && attempt == 0;
                    let status = if old_endpoint { 404 } else { 200 };
                    let data = if old_endpoint {
                        b"{}".as_slice()
                    } else {
                        body.as_slice()
                    };
                    let header = if encoding.is_empty() || old_endpoint {
                        String::new()
                    } else {
                        format!("Content-Encoding: {encoding}\r\n")
                    };
                    // A caller may reject unsupported headers before reading the body.
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{header}\r\n",
                        data.len()
                    );
                    let _ = stream.write_all(data);
                }
            });
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .build()
                .unwrap();
            let result = post_with_limit::<_, serde_json::Value>(
                &client,
                &config,
                &key,
                "/work/pentest-evidence",
                serde_json::json!({"lease":"same"}),
                1024,
            );
            if let Some(expected) = expected_error {
                assert_eq!(result.unwrap_err().to_string(), expected);
            } else {
                assert_eq!(result.unwrap(), serde_json::json!({"evidence":"saved"}));
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn completion_falls_back_only_for_an_old_endpoint_and_resigns_the_path() {
        use std::net::TcpListener;
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("relay");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        initialize(
            &state,
            &HashMap::from([
                ("--dispatcher", url.as_str()),
                ("--audience", "test"),
                ("--label", "Owned fixture"),
                ("--compute-group", "owned"),
            ]),
        )
        .unwrap();
        let config = read_config(&state).unwrap();
        let key = read_key(&state).unwrap();
        let server = std::thread::spawn(move || {
            for (path, status) in [("/work/complete-gzip", 404), ("/work/complete", 200)] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let (end, length) = loop {
                    let mut buffer = [0; 8192];
                    let n = stream.read(&mut buffer).unwrap();
                    assert!(n > 0 && bytes.len() < 16384);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        assert!(headers.starts_with(&format!("POST {path} ")));
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= end + 4 + length {
                            break (end + 4, length);
                        }
                    }
                };
                let decoded = if status == 404 {
                    let mut decoded = Vec::new();
                    flate2::read::GzDecoder::new(&bytes[end..end + length])
                        .read_to_end(&mut decoded)
                        .unwrap();
                    decoded
                } else {
                    bytes[end..end + length].to_vec()
                };
                let signed: SignedRequest<serde_json::Value> =
                    serde_json::from_slice(&decoded).unwrap();
                patchriot_protocol::verify(&signed, "test", path, signed.signed_at).unwrap();
                assert_eq!(signed.payload, serde_json::json!({"saved":"unchanged"}));
                let body = "{}";
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        post::<_, serde_json::Value>(
            &client,
            &config,
            &key,
            "/work/complete",
            serde_json::json!({"saved":"unchanged"}),
        )
        .unwrap();
        server.join().unwrap();
    }

    #[test]
    fn structured_website_outbox_survives_restart_and_oversized_writes_are_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let finding = serde_json::json!({"title":"Observed fixture", "support":"needs_live_test", "explanation":"x".repeat(1200), "suggested_action":"x".repeat(800), "citations":[{"resource_sha256":"a".repeat(64),"quote":"x".repeat(300)}]});
        let result = serde_json::json!({"kind":"website_agent_v1", "execution":{"state":"completed", "declared_model":"local", "model":"local", "model_digest":"a".repeat(64), "image_digest":format!("sha256:{}","b".repeat(64)), "duration_ms":1000,"inference_calls":2,"terminal_calls":1,"cleanup_confirmed":true},"snapshot_sha256":"c".repeat(64),"inspected_snapshot_sha256":"c".repeat(64),"assessment":{"summary":"x".repeat(1200),"findings":[finding.clone(),finding.clone(),finding],"limitations":["x".repeat(500),"x".repeat(500),"x".repeat(500),"x".repeat(500),"x".repeat(500)]},"raw_summary":"\"".repeat(4000)});
        let mut config: Config = serde_json::from_value(serde_json::json!({"schema_version":1,"dispatcher":"https://dispatcher.invalid/","audience":"test","introduction":{"label":"Owned fixture","runtime":"hermes","runtime_version":"test","declared_model":"local","compute_group":"shared","slots":1},"pairing_id":null,"device_id":Uuid::nil(),"sequence":1,"paused":false,"active_assignment":null,"pending_result":{"lease_id":Uuid::nil(),"result":result}})).unwrap();
        let WorkResult::Website(pending) = &config.pending_result.as_ref().unwrap().result else {
            panic!("wrong result");
        };
        assert!(pending.valid());
        write_config(directory.path(), &config).unwrap();
        let path = directory.path().join("relay.json");
        let before = fs::read(&path).unwrap();
        assert!(before.len() > 16 * 1024);
        assert!(
            read_config(directory.path())
                .unwrap()
                .pending_result
                .is_some()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        config.introduction.label = "x".repeat(MAX_STATE as usize);
        assert!(write_config(directory.path(), &config).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn payment_refusal_pauses_only_after_saved_delivery_and_does_not_poll() {
        use std::net::TcpListener;
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("relay");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        initialize(
            &state,
            &HashMap::from([
                ("--dispatcher", url.as_str()),
                ("--audience", "test"),
                ("--label", "Owned fixture"),
                ("--compute-group", "owned"),
            ]),
        )
        .unwrap();
        let mut config = read_config(&state).unwrap();
        config.device_id = Some(Uuid::new_v4());
        let result = serde_json::from_value(serde_json::json!({
            "kind":"pentest_agent_v1","scope_sha256":"a".repeat(64),
            "execution":{"state":"failed","provider":"venice.ai","model":"fixture",
                "image_digest":"fixture","duration_ms":10,"inference_calls":1,"http_requests":1,
                "cost_upper_microusd":1,"cleanup_confirmed":true,"failure_reason":"provider_payment_required"},
            "assessment":null,"evidence":[],"raw_summary":"saved partial work"
        })).unwrap();
        config.pending_result = Some(CompleteWork {
            lease_id: Uuid::new_v4(),
            result: WorkResult::Pentest(result),
        });
        write_config(&state, &config).unwrap();
        let before = serde_json::to_value(&config.pending_result).unwrap();
        let server = std::thread::spawn(move || {
            for status in [503, 200] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0; 8192];
                    let n = stream.read(&mut buffer).unwrap();
                    assert!(n > 0 && bytes.len() < 16384);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        assert!(
                            headers
                                .lines()
                                .next()
                                .unwrap()
                                .contains("/work/complete-gzip ")
                        );
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let body = if status == 503 {
                    "{}"
                } else {
                    r#"{"accepted":true,"fixture_matches":false,"evidence_complete":false,"replayed":true}"#
                };
                write!(stream,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}",body.len()).unwrap();
            }
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        assert!(send_result(&state, &client).is_err());
        let saved = read_config(&state).unwrap();
        assert!(!saved.paused, "Delivery still needs normal lease renewal");
        assert_eq!(serde_json::to_value(saved.pending_result).unwrap(), before);
        // A later work tick delivers the exact outbox, then stops before polling
        // another assignment. A third request would fail against this server.
        work_tick(
            &state,
            &client,
            &Arc::new(AtomicBool::new(false)),
            None,
            false,
            false,
            false,
        )
        .unwrap();
        server.join().unwrap();
        let resumed = read_config(&state).unwrap();
        assert!(resumed.paused);
        assert!(resumed.pending_result.is_none());
        assert!(resumed.active_assignment.is_none());
        assert_eq!(resumed.device_id, config.device_id);
    }

    #[test]
    fn live_outbox_survives_restart_and_delivery_retries_at_the_protocol_limit() {
        use patchriot_protocol::pentests::{LiveScope, MAX_RESULT_BYTES, PentestResult};
        use std::net::TcpListener;

        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("relay");
        initialize(
            &state,
            &HashMap::from([
                ("--dispatcher", "http://127.0.0.1:1"),
                ("--audience", "test"),
                ("--label", "Owned fixture"),
                ("--compute-group", "owned"),
            ]),
        )
        .unwrap();
        let scope: LiveScope = serde_json::from_value(serde_json::json!({
            "origins":["https://example.com"], "methods":["GET", "HEAD", "OPTIONS"],
            "profile":"web_baseline_v1"
        }))
        .unwrap();
        let scope = scope.normalized().unwrap();
        let mut result: PentestResult = serde_json::from_value(serde_json::json!({
            "kind":"pentest_agent_v1", "scope_sha256":scope.hash().unwrap(),
            "execution":{"state":"completed", "provider":"abliteration.ai",
                "model":"abliterated-model-large-v2", "image_digest":"owned-fixture",
                "duration_ms":100, "inference_calls":1, "http_requests":500,
                "cost_upper_microusd":1, "cleanup_confirmed":true},
            "assessment":null, "evidence":[], "raw_summary":""
        }))
        .unwrap();
        // The inference SDK enables serde_json arbitrary_precision. Fractional
        // observed costs must survive the untagged WorkResult outbox reader.
        result.execution.inference_usage = vec![patchriot_protocol::pentests::InferenceUsage {
            provider: "abliteration.ai".into(),
            model: "abliterated-model-large-v2".into(),
            responses: 1,
            usd_cost_responses: 1,
            diem_cost_responses: 1,
            provider_reported_usd: 0.32495331000000005,
            provider_reported_diem: 0.0,
            ..Default::default()
        }];
        // Escaped characters and many records are realistic HTML/tool output.
        // Fill to the wire limit, not an arbitrary 'large enough' test size.
        for id in 1..=500 {
            result.evidence.push(
                serde_json::from_value(serde_json::json!({
                    "id":id,"method":"GET","url":format!("https://example.com/{id}"),
                    "request_headers":{},"status":200,"headers":{},
                    "body_excerpt":"","truncated":true,"error":null,"observed_at":1
                }))
                .unwrap(),
            );
        }
        let overhead = serde_json::to_vec(&result).unwrap().len();
        let repeated = (MAX_RESULT_BYTES - overhead) / (4 * result.evidence.len());
        for evidence in &mut result.evidence {
            evidence.body_excerpt = "\"\\".repeat(repeated);
        }
        let size = serde_json::to_vec(&result).unwrap().len();
        assert!(size < MAX_RESULT_BYTES && MAX_RESULT_BYTES - size < 24_000);
        result.raw_summary = "x".repeat(MAX_RESULT_BYTES - size);
        assert!(result.valid(&scope));
        assert_eq!(serde_json::to_vec(&result).unwrap().len(), MAX_RESULT_BYTES);
        let mut oversized = result.clone();
        oversized.raw_summary.push('x');
        assert!(!oversized.valid(&scope));
        let lease_id = Uuid::new_v4();
        let expected = CompleteWork {
            lease_id,
            result: WorkResult::Pentest(result),
        };
        preserve_interrupted_result(&state, &expected).unwrap();
        let recovery_path = state.join("last-interrupted-work.json");
        let recovered: CompleteWork =
            serde_json::from_slice(&fs::read(&recovery_path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&recovered).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(
            fs::metadata(&recovery_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(read_config(&state).unwrap().pending_result.is_none());
        let mut config = read_config(&state).unwrap();
        config.device_id = Some(Uuid::new_v4());
        config.pending_result = Some(expected.clone());
        write_config(&state, &config).unwrap();
        let before = fs::read(state.join("relay.json")).unwrap();
        assert!(before.len() > 128 * 1024);
        assert_eq!(
            serde_json::to_value(read_config(&state).unwrap().pending_result).unwrap(),
            serde_json::to_value(Some(&expected)).unwrap()
        );
        assert_eq!(
            fs::metadata(state.join("relay.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // Refuse an oversized replacement without corrupting the saved result.
        config.introduction.label = "x".repeat(MAX_STATE as usize);
        assert!(write_config(&state, &config).is_err());
        assert_eq!(fs::read(state.join("relay.json")).unwrap(), before);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = read_config(&state).unwrap();
        config.dispatcher = format!("http://{}/", listener.local_addr().unwrap());
        write_config(&state, &config).unwrap();
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for status in [503, 503, 503, 200] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let (end, length) = loop {
                    let mut buffer = [0; 8192];
                    let n = stream.read(&mut buffer).unwrap();
                    assert!(n > 0 && bytes.len() < MAX_RESULT_BYTES + 8192);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if bytes.len() >= end + 4 + length {
                            break (end + 4, length);
                        }
                    }
                };
                assert!(
                    std::str::from_utf8(&bytes[..end])
                        .unwrap()
                        .contains("/work/complete-gzip ")
                );
                assert!(
                    length < MAX_RESULT_BYTES / 20,
                    "repeated evidence should compress"
                );
                let mut decoded = Vec::new();
                flate2::read::GzDecoder::new(&bytes[end..end + length])
                    .read_to_end(&mut decoded)
                    .unwrap();
                let signed: SignedRequest<CompleteWork> = serde_json::from_slice(&decoded).unwrap();
                let path = std::str::from_utf8(&bytes[..end])
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                patchriot_protocol::verify(&signed, "test", path, signed.signed_at).unwrap();
                requests.push(serde_json::to_value(signed.payload).unwrap());
                let body = if status == 503 {
                    "{}"
                } else {
                    // Completion uploads override a short heartbeat timeout.
                    std::thread::sleep(Duration::from_millis(300));
                    "{\"accepted\":true,\"fixture_matches\":false,\"evidence_complete\":false,\"replayed\":true}"
                };
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap();
        assert!(retryable_dispatcher_error(
            &send_result(&state, &client).unwrap_err()
        ));
        assert!(read_config(&state).unwrap().pending_result.is_some());
        // A stopped lease must not keep retrying. The unchanged outbox remains
        // available for authoritative replay/cancellation handling.
        assert!(send_result_while_active(&state, &client, || false).is_err());
        assert!(read_config(&state).unwrap().pending_result.is_some());
        let active_checks = std::sync::atomic::AtomicUsize::new(0);
        send_result_while_active(&state, &client, || {
            active_checks.fetch_add(1, Ordering::Relaxed);
            true
        })
        .unwrap();
        assert!(active_checks.load(Ordering::Relaxed) > 1);
        assert!(read_config(&state).unwrap().pending_result.is_none());
        let requests = server.join().unwrap();
        assert_eq!(requests, vec![serde_json::to_value(&expected).unwrap(); 4]);
    }

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
    fn agent_deadline_reserves_cleanup_and_reporting_without_extending_short_leases() {
        let start = Instant::now();
        let mut renewal = WorkRenewed {
            lease_id: Uuid::nil(),
            sequence: 1,
            expires_at: 1060,
            deadline_at: 1600,
            valid_for_seconds: 59,
            replayed: false,
        };
        let deadline = agent_execution_deadline(start, &renewal, 600).unwrap();
        assert_eq!(deadline.duration_since(start), Duration::from_secs(539));
        // Transit, snapshot delivery and preflight consume the same budget.
        assert_eq!(
            deadline.saturating_duration_since(start + Duration::from_secs(40)),
            Duration::from_secs(499)
        );
        renewal.deadline_at = 1120;
        assert_eq!(
            agent_execution_deadline(start, &renewal, 600).unwrap(),
            start + Duration::from_secs(59)
        );
        renewal.deadline_at = renewal.expires_at;
        assert_eq!(
            agent_execution_deadline(start, &renewal, 600).unwrap(),
            start
        );
        renewal.deadline_at = i64::MAX;
        assert_eq!(
            agent_execution_deadline(start, &renewal, 600).unwrap(),
            start + Duration::from_secs(540)
        );
        renewal.deadline_at = 0;
        assert!(agent_execution_deadline(start, &renewal, 600).is_err());
        renewal.deadline_at = i64::MAX;
        renewal.expires_at = i64::MIN;
        assert!(agent_execution_deadline(start, &renewal, 600).is_err());
    }

    #[test]
    fn longer_cpu_runs_require_both_server_and_operator_allowance() {
        let start = Instant::now();
        let mut renewal = WorkRenewed {
            lease_id: Uuid::nil(),
            sequence: 1,
            expires_at: 1060,
            deadline_at: 2800,
            valid_for_seconds: 59,
            replayed: false,
        };
        assert_eq!(
            agent_execution_deadline(start, &renewal, 600).unwrap(),
            start + Duration::from_secs(540)
        );
        assert_eq!(
            agent_execution_deadline(start, &renewal, 1800).unwrap(),
            start + Duration::from_secs(1739)
        );
        renewal.deadline_at = 4600;
        assert_eq!(
            agent_execution_deadline(start, &renewal, 3600).unwrap(),
            start + Duration::from_secs(3539)
        );
        renewal.deadline_at = 1600;
        assert_eq!(
            agent_execution_deadline(start, &renewal, 3600).unwrap(),
            start + Duration::from_secs(539)
        );
        for invalid in [0, 599, 10801, u64::MAX] {
            assert!(agent_execution_deadline(start, &renewal, invalid).is_err());
        }
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
