//! Bounded supervision of relay-owned helper commands. This is process cleanup,
//! not filesystem or network isolation; callers must provide that boundary.
use rustix::{
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid},
};
use serde::Serialize;
use std::{
    io::{self, Read},
    os::fd::AsFd,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const POLL: Duration = Duration::from_millis(5);
const CLEANUP_LIMIT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Limits {
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_ms: 3_000,
            max_output_bytes: 8_192,
        }
    }
}

impl Limits {
    pub fn validate(self) -> Result<(), &'static str> {
        if !(1..=60_000).contains(&self.timeout_ms) {
            return Err("timeout must be 1..60000 ms");
        }
        if !(1..=1_048_576).contains(&self.max_output_bytes) {
            return Err("output limit must be 1..1048576 bytes");
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    TimedOut,
    Cancelled,
    OutputLimit,
    InvalidOutput,
    ProcessFailed,
    CleanupUnconfirmed,
}

#[derive(Debug, Serialize)]
pub struct ProcessReport {
    pub outcome: Outcome,
    limits: Limits,
    pub duration_ms: u128,
    process_started: bool,
    exit_code: Option<i32>,
    termination_signal: Option<i32>,
    direct_child_reaped: bool,
    output_streams_closed: bool,
    stdout_bytes: usize,
    stderr_bytes: usize,
    output_truncated: bool,
    #[serde(skip)]
    pub stdout: Vec<u8>,
    #[serde(skip)]
    pub stderr: Vec<u8>,
}

/// Keep the leader waitable until after signaling its group. Reaping it first
/// would let the OS reuse its PID before we send the group signal.
struct OwnedChild {
    child: Child,
    pid: Pid,
    reaped: bool,
}

impl OwnedChild {
    fn new(child: Child) -> Self {
        Self {
            pid: Pid::from_child(&child),
            child,
            reaped: false,
        }
    }

    fn exited(&self) -> io::Result<bool> {
        match waitid(
            WaitId::Pid(self.pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn terminate_group(&mut self, _deadline: Instant) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        let result = kill_process_group(self.pid, Signal::KILL);
        // Darwin filters zombies before signaling a group. An exiting task can
        // return EPERM just before waitid observes its exit. Retry while retaining
        // the PID; never treat denial on a live task as confirmed cleanup.
        #[cfg(target_os = "macos")]
        let result = {
            let mut result = result;
            while result == Err(rustix::io::Errno::PERM) {
                if self.exited()? {
                    return Ok(());
                }
                if Instant::now() >= _deadline {
                    break;
                }
                std::thread::sleep(POLL);
                result = kill_process_group(self.pid, Signal::KILL);
            }
            result
        };
        match result {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn reap(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped = status.is_some();
        Ok(status)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let deadline = Instant::now() + CLEANUP_LIMIT;
            let _ = self.terminate_group(deadline);
            while Instant::now() < deadline {
                match self.reap() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => std::thread::sleep(POLL),
                }
            }
        }
    }
}

struct Capture<P> {
    pipe: P,
    bytes: Vec<u8>,
    closed: bool,
}

impl<P: Read + AsFd> Capture<P> {
    fn new(pipe: P) -> io::Result<Self> {
        fcntl_setfl(&pipe, fcntl_getfl(&pipe)? | OFlags::NONBLOCK)?;
        Ok(Self {
            pipe,
            bytes: Vec::new(),
            closed: false,
        })
    }

    // Bounded work per poll: continuous output cannot starve cancellation/deadlines.
    // Read one extra byte to distinguish exactly-at-limit from over-limit output.
    fn drain(&mut self, mut room: usize) -> io::Result<bool> {
        let mut overflow = false;
        for _ in 0..4 {
            let mut buffer = [0; 4096];
            let wanted = if room == 0 {
                buffer.len()
            } else {
                buffer.len().min(room.saturating_add(1))
            };
            match self.pipe.read(&mut buffer[..wanted]) {
                Ok(0) => {
                    self.closed = true;
                    break;
                }
                Ok(n) => {
                    let kept = n.min(room);
                    self.bytes.extend_from_slice(&buffer[..kept]);
                    room -= kept;
                    overflow |= kept < n;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(overflow)
    }
}

/// Supervise a command assembled by trusted relay code. No shell string or
/// caller-supplied command reaches this helper from the dispatcher or CLI.
pub fn run(
    mut command: Command,
    limits: Limits,
    cancelled: &AtomicBool,
    cancel_after: Option<Duration>,
    on_started: impl FnOnce(),
) -> io::Result<ProcessReport> {
    limits.validate().map_err(io::Error::other)?;
    let started = Instant::now();
    let is_cancelled = || {
        cancelled.load(Ordering::Relaxed) || cancel_after.is_some_and(|d| started.elapsed() >= d)
    };
    let mut report = ProcessReport {
        outcome: Outcome::Cancelled,
        limits,
        duration_ms: 0,
        process_started: false,
        exit_code: None,
        termination_signal: None,
        direct_child_reaped: false,
        output_streams_closed: false,
        stdout_bytes: 0,
        stderr_bytes: 0,
        output_truncated: false,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    if is_cancelled() {
        return Ok(report);
    }
    let mut child = OwnedChild::new(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?,
    );
    report.process_started = true;
    on_started();
    let mut stdout = Capture::new(
        child
            .child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing stdout pipe"))?,
    )?;
    let mut stderr = Capture::new(
        child
            .child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing stderr pipe"))?,
    )?;
    let mut drain = |report: &mut ProcessReport| -> io::Result<bool> {
        let over_out =
            stdout.drain(limits.max_output_bytes - stdout.bytes.len() - stderr.bytes.len())?;
        let over_err =
            stderr.drain(limits.max_output_bytes - stdout.bytes.len() - stderr.bytes.len())?;
        report.output_truncated |= over_out || over_err;
        report.output_streams_closed = stdout.closed && stderr.closed;
        Ok(over_out || over_err)
    };
    report.outcome = loop {
        if is_cancelled() {
            break Outcome::Cancelled;
        }
        if started.elapsed() >= Duration::from_millis(limits.timeout_ms) {
            break Outcome::TimedOut;
        }
        if drain(&mut report)? {
            break Outcome::OutputLimit;
        }
        if child.exited()? {
            break Outcome::Completed;
        }
        std::thread::sleep(POLL);
    };

    // Also clean up pipe-holding descendants after a normal leader exit. This
    // covers our fixtures; hostile programs can escape groups, so need a sandbox.
    let cleanup_started = Instant::now();
    child.terminate_group(cleanup_started + CLEANUP_LIMIT)?;
    let mut status = None;
    while cleanup_started.elapsed() < CLEANUP_LIMIT {
        if status.is_none() {
            status = child.reap()?;
        }
        if drain(&mut report)? && report.outcome == Outcome::Completed {
            report.outcome = Outcome::OutputLimit;
        }
        if status.is_some() && report.output_streams_closed {
            break;
        }
        std::thread::sleep(POLL);
    }
    report.direct_child_reaped = status.is_some();
    report.exit_code = status.and_then(|s| s.code());
    report.termination_signal = status.and_then(|s| s.signal());
    report.stdout_bytes = stdout.bytes.len();
    report.stderr_bytes = stderr.bytes.len();
    report.duration_ms = started.elapsed().as_millis();
    if !report.direct_child_reaped || !report.output_streams_closed {
        report.outcome = Outcome::CleanupUnconfirmed;
    } else if report.outcome == Outcome::Completed && !status.is_some_and(|s| s.success()) {
        report.outcome = Outcome::ProcessFailed;
    }
    report.stdout = stdout.bytes;
    report.stderr = stderr.bytes;
    Ok(report)
}
