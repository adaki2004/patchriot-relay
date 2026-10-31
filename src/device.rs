//! Persistent device identity and outbound heartbeat loop. No remote shell or work
//! execution is exposed here. Private keys never leave the operator's state directory.

use patchriot_protocol::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
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
        runtime: RuntimeKind::OwnedFixture,
        runtime_version: env!("CARGO_PKG_VERSION").into(),
        declared_model: None,
        compute_group: required("--compute-group")?.into(),
        slots: 1,
    };
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

fn tick(directory: &Path, client: &reqwest::blocking::Client) -> Result<(), Error> {
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
            return Ok(());
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
    let reply: HeartbeatReply = post(
        client,
        &config,
        &key,
        &format!("/v1/devices/{id}/heartbeat"),
        Heartbeat {
            sequence: config.sequence,
            paused: config.paused,
            running: 0,
        },
    )?;
    println!(
        "{}",
        serde_json::json!({"device_id":id,"state":reply.state,"sequence":reply.sequence})
    );
    Ok(())
}

pub fn execute(args: &[String]) -> Result<u8, Error> {
    let action = args[0].as_str();
    let mut options = HashMap::new();
    let mut once = false;
    let mut args = args[1..].iter();
    while let Some(name) = args.next() {
        if name == "--once" && action == "connect" && !once {
            once = true;
            continue;
        }
        let allowed = name == "--state-dir"
            || action == "init"
                && ["--dispatcher", "--audience", "--label", "--compute-group"]
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
                serde_json::json!({"device_id":config.device_id,"pairing_id":config.pairing_id,"label":config.introduction.label,"paused":config.paused,"sequence":config.sequence})
            );
        }
        "connect" => {
            let daemon_lock = private_open(&directory.join("daemon.lock"), true)?;
            daemon_lock
                .try_lock()
                .map_err(|_| "another relay is already using this state directory")?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            ctrlc::set_handler(move || flag.store(true, Ordering::Relaxed))?;
            let client = client()?;
            let mut failures = 0;
            loop {
                match tick(&directory, &client) {
                    Ok(()) => failures = 0,
                    Err(error) => {
                        // Never print response bodies, private keys or signed requests.
                        eprintln!("{error}");
                        if once
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
