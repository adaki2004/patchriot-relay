//! Local Docker commands and explicit cleanup, shared by owned diagnostics and agents.
use crate::process::{self, Limits, Outcome, ProcessReport};
use serde_json::Value;
use std::{
    io,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
};

/// The CLI and socket are administrator-owned. A private, empty Docker config
/// and cleared environment exclude registry credentials, proxies and contexts.
pub(crate) struct Docker {
    executable: PathBuf,
    host: String,
    config: tempfile::TempDir,
}

impl Docker {
    pub(crate) fn new(socket: &Path) -> io::Result<Self> {
        if !socket.is_absolute() || !socket.metadata()?.file_type().is_socket() {
            return Err(io::Error::other(
                "expected an absolute local Unix socket path",
            ));
        }
        let socket = socket.canonicalize()?;
        let host = format!(
            "unix://{}",
            socket
                .to_str()
                .ok_or_else(|| io::Error::other("socket path must be UTF-8"))?
        );
        let executable = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|path| path.is_absolute())
            .map(|path| path.join("docker"))
            .find(|path| {
                path.metadata()
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
            .ok_or_else(|| {
                io::Error::other("Docker CLI is not installed on an absolute PATH entry")
            })?;
        Ok(Self {
            executable: executable.canonicalize()?,
            host,
            config: tempfile::Builder::new()
                .prefix("patchriot-docker-")
                .tempdir()?,
        })
    }

    pub(crate) fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.executable);
        command
            .env_clear()
            .current_dir(self.config.path())
            .arg("--host")
            .arg(&self.host)
            .arg("--config")
            .arg(self.config.path())
            .args(args);
        command
    }

    pub(crate) fn control(&self, args: &[&str]) -> io::Result<ProcessReport> {
        // Control/cleanup must still finish after a user cancellation. Each
        // command has its own short deadline; no shell or credentials are used.
        process::run(
            self.command(args),
            Limits {
                timeout_ms: 10_000,
                max_output_bytes: 65_536,
            },
            &AtomicBool::new(false),
            None,
            || {},
        )
    }

    pub(crate) fn inspect(&self, kind: &str, reference: &str) -> io::Result<Value> {
        let result = self.control(&[kind, "inspect", reference])?;
        if result.outcome != Outcome::Completed {
            return Err(io::Error::other(
                "Docker inspection failed; check the local runtime",
            ));
        }
        let mut entries: Vec<Value> = serde_json::from_slice(&result.stdout)
            .map_err(|_| io::Error::other("invalid Docker inspection response"))?;
        if entries.len() != 1 {
            return Err(io::Error::other("expected one Docker inspection result"));
        }
        Ok(entries.remove(0))
    }
}

pub(crate) struct Container<'a> {
    pub(crate) docker: &'a Docker,
    pub(crate) name: String,
    pub(crate) cleaned: bool,
}

impl Container<'_> {
    pub(crate) fn cleanup(&mut self) -> bool {
        let removed = self
            .docker
            .control(&["container", "rm", "--force", "--volumes", &self.name])
            .is_ok_and(|r| r.outcome == Outcome::Completed);
        let filter = format!("name=^/{}$", self.name);
        let absent = self
            .docker
            .control(&["container", "ls", "--all", "--quiet", "--filter", &filter])
            .is_ok_and(|r| r.outcome == Outcome::Completed && r.stdout.is_empty());
        self.cleaned = removed && absent;
        self.cleaned
    }
}

impl Drop for Container<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            // Best effort on an early error. The explicit result above is the
            // only basis for a cleanup claim; a failed create is ambiguous.
            let _ = self
                .docker
                .control(&["container", "rm", "--force", "--volumes", &self.name]);
        }
    }
}

pub(crate) fn immutable_image(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) fn no_entries(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}
