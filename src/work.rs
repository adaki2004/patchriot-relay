//! Only the owned access-control example can be dispatched. The server cannot
//! supply executable text, paths, target URLs or a broader resource limit.

use crate::{
    fixtures::Case,
    runner::{self, Limits, Outcome},
};
use patchriot_protocol::{
    CompleteWork, FixtureCheck, FixtureResult, FixtureRun, FixtureVersion, WorkAssignment,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub struct CleanupUnconfirmed;
impl std::fmt::Display for CleanupUnconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fixture process cleanup was not confirmed; stop and inspect the relay"
        )
    }
}
impl std::error::Error for CleanupUnconfirmed {}

pub fn execute(
    assignment: &WorkAssignment,
    cancelled: &Arc<AtomicBool>,
    can_continue: impl Fn() -> bool,
) -> Result<Option<CompleteWork>, Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let mut runs = Vec::new();
    for (case, version) in [
        (Case::Original, FixtureVersion::Original),
        (Case::Patched, FixtureVersion::Patched),
        (Case::Clean, FixtureVersion::Clean),
    ] {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        if cancelled.load(Ordering::Relaxed) || !can_continue() || now + 5 >= assignment.expires_at
        {
            return Ok(None);
        }
        let report = runner::run(&executable, case, Limits::default(), cancelled, None)?;
        if report.process.outcome == Outcome::CleanupUnconfirmed {
            return Err(Box::new(CleanupUnconfirmed));
        }
        let completed = report.process.outcome == Outcome::Completed;
        let checks = report
            .evidence
            .map(|evidence| {
                evidence
                    .checks
                    .into_iter()
                    .map(|check| FixtureCheck {
                        name: check.name,
                        expected: check.expected,
                        actual: check.actual,
                    })
                    .collect()
            })
            .unwrap_or_default();
        runs.push(FixtureRun {
            version,
            completed,
            checks,
            elapsed_ms: report.process.duration_ms.try_into()?,
        });
        if !completed {
            break;
        }
    }
    Ok(Some(CompleteWork {
        lease_id: assignment.lease_id,
        result: patchriot_protocol::WorkResult::Fixture(FixtureResult { runs }),
    }))
}
