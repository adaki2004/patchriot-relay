//! Owned, finite Linux probes. No models, customer input, shell or credentials.
//! Built separately so the scratch image contains only this static executable.
#![forbid(unsafe_code)]

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    net::{SocketAddr, TcpStream},
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

fn read(path: &str) -> String {
    fs::read_to_string(path)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn status(field: &str) -> String {
    read("/proc/self/status")
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == field).then(|| value.trim().to_owned())
        })
        .unwrap_or_default()
}

fn evidence(checks: &[(&str, bool)]) -> bool {
    print!("{{\"schema_version\":1,\"checks\":[");
    for (index, (name, passed)) in checks.iter().enumerate() {
        if index != 0 {
            print!(",");
        }
        // Names are fixed literals in this source, never task-supplied text.
        print!("{{\"name\":\"{name}\",\"passed\":{passed}}}");
    }
    println!("]}}");
    checks.iter().all(|(_, passed)| *passed)
}

fn policy(canary: &str) -> bool {
    let cpu = read("/sys/fs/cgroup/cpu.max");
    let values: Vec<_> = cpu
        .split_whitespace()
        .filter_map(|v| v.parse::<u64>().ok())
        .collect();
    let cpu_limited = values.len() == 2 && values[0].checked_mul(2) == Some(values[1]);
    // Some kernels create inactive tunnel devices in every network namespace.
    // They are harmless here: no interface other than loopback may be UP, and
    // the unprivileged probe cannot configure interfaces or routes.
    let net: Option<Vec<_>> = fs::read_dir("/sys/class/net").ok().map(|entries| {
        entries
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .map(|entry| {
                entry.file_name() == "lo"
                    || fs::read_to_string(entry.path().join("flags"))
                        .ok()
                        .and_then(|s| {
                            u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok()
                        })
                        .is_some_and(|flags| flags & 1 == 0)
            })
            .collect()
    });
    let no_network = net
        .is_some_and(|interfaces| !interfaces.is_empty() && interfaces.into_iter().all(|v| v))
        && TcpStream::connect_timeout(
            &SocketAddr::from(([203, 0, 113, 1], 9)),
            Duration::from_millis(200),
        )
        .err()
        .is_some_and(|e| e.raw_os_error() == Some(101));
    let root_read_only = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open("/.patchriot-probe")
        .err()
        .is_some_and(|e| e.raw_os_error() == Some(30));
    let workspace = fs::write("/work/write-check", b"owned fixture").is_ok();
    let _ = fs::remove_file("/work/write-check");
    let copied = fs::copy("/probe", "/work/probe-copy").is_ok();
    let cannot_execute_workspace = copied
        && Command::new("/work/probe-copy")
            .arg("quick")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .err()
            .is_some_and(|e| e.kind() == io::ErrorKind::PermissionDenied);
    let _ = fs::remove_file("/work/probe-copy");
    let canary_hidden = fs::metadata(canary).is_err() && fs::read(canary).is_err();
    let symlink = std::os::unix::fs::symlink(canary, "/work/host-link").is_ok();
    let symlink_blocked = symlink && fs::read("/work/host-link").is_err();
    let _ = fs::remove_file("/work/host-link");
    evidence(&[
        (
            "non_root",
            status("Uid").split_whitespace().all(|v| v == "65534") && !status("Uid").is_empty(),
        ),
        ("no_capabilities", status("CapEff") == "0000000000000000"),
        ("no_new_privileges", status("NoNewPrivs") == "1"),
        ("seccomp_filter", status("Seccomp") == "2"),
        ("network_isolated", no_network),
        ("root_read_only", root_read_only),
        ("workspace_writable", workspace),
        ("workspace_noexec", cannot_execute_workspace),
        ("host_canary_hidden", canary_hidden),
        ("symlink_cannot_read_host", symlink_blocked),
        (
            "no_runtime_socket",
            !std::path::Path::new("/var/run/docker.sock").exists(),
        ),
        (
            "no_parent_environment",
            std::env::var_os("PATCHRIOT_TEST_CANARY").is_none()
                && std::env::var("HOME").ok().as_deref() == Some("/work"),
        ),
        (
            "memory_limited",
            read("/sys/fs/cgroup/memory.max") == "67108864",
        ),
        (
            "swap_disabled",
            read("/sys/fs/cgroup/memory.swap.max") == "0",
        ),
        ("cpu_limited", cpu_limited),
        ("tasks_limited", read("/sys/fs/cgroup/pids.max") == "32"),
    ])
}

fn disk() -> bool {
    let result = (|| -> io::Result<bool> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open("/work/bounded-file")?;
        let chunk = [0x5a; 65536];
        for _ in 0..384 {
            if let Err(error) = file.write_all(&chunk) {
                return Ok(error.raw_os_error() == Some(28));
            }
        }
        Ok(false)
    })();
    evidence(&[("workspace_size_enforced", result.unwrap_or(false))])
}

fn tasks() -> bool {
    let done = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    let mut blocked = false;
    // At most 48 threads, even if the runtime ignores its configured limit.
    for _ in 0..48 {
        let stop = done.clone();
        match std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !stop.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }) {
            Ok(thread) => threads.push(thread),
            Err(error) => {
                blocked = error.raw_os_error() == Some(11);
                break;
            }
        }
    }
    done.store(true, Ordering::Relaxed);
    let count = threads.len();
    for thread in threads {
        let _ = thread.join();
    }
    evidence(&[("task_limit_enforced", blocked && (1..32).contains(&count))])
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let passed = match args.first().map(String::as_str) {
        Some("policy") if args.len() == 2 => policy(&args[1]),
        Some("disk") if args.len() == 1 => disk(),
        Some("tasks") if args.len() == 1 => tasks(),
        Some("descendant") if args.len() == 1 => {
            // This child leaves its parent's process group and keeps the output
            // pipes open. Container teardown must still terminate it.
            let child = Command::new("/probe").arg("slow").process_group(0).spawn();
            evidence(&[("separate_process_group_started", child.is_ok())])
        }
        Some("slow") if args.len() == 1 => {
            std::thread::sleep(Duration::from_secs(20));
            true
        }
        Some("noisy") if args.len() == 1 => {
            for _ in 0..512 {
                if io::stdout().write_all(&[b'x'; 8192]).is_err() {
                    break;
                }
            }
            true
        }
        Some("memory") if args.len() == 1 => {
            let mut allocations = Vec::new();
            for _ in 0..24 {
                allocations.push(vec![0x5a_u8; 4 * 1024 * 1024]);
                std::hint::black_box(&allocations);
            }
            evidence(&[("memory_limit_enforced", false)])
        }
        Some("quick") if args.len() == 1 => true,
        _ => return std::process::ExitCode::from(2),
    };
    std::process::ExitCode::from(u8::from(!passed))
}
