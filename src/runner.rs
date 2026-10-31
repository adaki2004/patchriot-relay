//! Execute only compiled-in fixtures. Process supervision is not a sandbox.

pub use crate::process::{Limits, Outcome};
use crate::{
    fixtures::{Case, Evidence},
    process,
};
use serde::Serialize;
use std::{io, path::Path, process::Command, sync::atomic::AtomicBool, time::Duration};

#[derive(Debug, Serialize)]
pub struct Report {
    schema_version: u8,
    mode: &'static str,
    case: Case,
    #[serde(flatten)]
    pub process: process::ProcessReport,
    pub evidence: Option<Evidence>,
}
/// Run our executable's fixed example in a cleared environment and temporary
/// working directory. No customer source or executable path comes from a job.
pub fn run(
    executable: &Path,
    case: Case,
    limits: Limits,
    cancelled: &AtomicBool,
    cancel_after: Option<Duration>,
) -> io::Result<Report> {
    limits.validate().map_err(io::Error::other)?;
    let workspace = tempfile::Builder::new()
        .prefix("patchriot-fixture-")
        .tempdir()?;
    let mut command = Command::new(executable);
    command
        .args(["__fixture", case.as_str()])
        .env_clear()
        .current_dir(workspace.path());
    let mut result = process::run(command, limits, cancelled, cancel_after, || {
        eprintln!("running owned fixture: {}", case.as_str())
    })?;
    let mut evidence = None;
    if result.outcome == Outcome::Completed {
        match serde_json::from_slice::<Evidence>(&result.stdout) {
            Ok(value) if value.case == case => evidence = Some(value),
            _ => result.outcome = Outcome::InvalidOutput,
        }
    }
    Ok(Report {
        schema_version: 1,
        mode: "owned_fixture",
        case,
        process: result,
        evidence,
    })
}
