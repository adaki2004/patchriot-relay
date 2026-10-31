//! Small, owned programs for exercising execution controls, not AI quality.

use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    Original,
    Patched,
    Clean,
    Slow,
    Noisy,
    SplitOutput,
    Malformed,
    Nonzero,
    Descendant,
    Environment,
}

impl Case {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Patched => "patched",
            Self::Clean => "clean",
            Self::Slow => "slow",
            Self::Noisy => "noisy",
            Self::SplitOutput => "split_output",
            Self::Malformed => "malformed",
            Self::Nonzero => "nonzero",
            Self::Descendant => "descendant",
            Self::Environment => "environment",
        }
    }
}

impl std::str::FromStr for Case {
    type Err = &'static str;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "original" => Ok(Self::Original),
            "patched" => Ok(Self::Patched),
            "clean" => Ok(Self::Clean),
            "slow" => Ok(Self::Slow),
            "noisy" => Ok(Self::Noisy),
            "split_output" => Ok(Self::SplitOutput),
            "malformed" => Ok(Self::Malformed),
            "nonzero" => Ok(Self::Nonzero),
            "descendant" => Ok(Self::Descendant),
            "environment" => Ok(Self::Environment),
            _ => Err("unknown owned fixture; see --help"),
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub name: String,
    pub expected: bool,
    pub actual: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub case: Case,
    pub checks: Vec<Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descendant_pid: Option<u32>,
}

impl Evidence {
    pub fn matches_expected_fixture(&self, case: Case) -> bool {
        self.case == case
            && self.checks.len() == 3
            && self
                .checks
                .iter()
                .zip([
                    ("owner_can_read", true),
                    ("another_user_can_read", false),
                    ("anonymous_can_read", false),
                ])
                .all(|(check, (name, expected))| {
                    check.name == name
                        && check.expected == expected
                        && check.actual
                            == (expected
                                || (case == Case::Original && name == "another_user_can_read"))
                })
    }
}

// A signed-in user must only be able to read their own document.
fn original_can_read(user: Option<u64>, _owner: u64) -> bool {
    user.is_some()
}

fn patched_can_read(user: Option<u64>, owner: u64) -> bool {
    user == Some(owner)
}

// A separate clean implementation guards against calling any successful run a finding.
fn clean_can_read(user: Option<u64>, owner: u64) -> bool {
    match user {
        None => false,
        Some(user) => user == owner,
    }
}

fn access_checks(case: Case) -> Vec<Check> {
    let can_read = match case {
        Case::Original => original_can_read,
        Case::Patched => patched_can_read,
        Case::Clean => clean_can_read,
        _ => unreachable!("access-control fixtures only"),
    };
    [
        ("owner_can_read", Some(10), true),
        ("another_user_can_read", Some(20), false),
        ("anonymous_can_read", None, false),
    ]
    .into_iter()
    .map(|(name, user, expected)| Check {
        name: name.into(),
        expected,
        actual: can_read(user, 10),
    })
    .collect()
}

/// Every probe is finite even if someone invokes the internal command directly.
pub fn execute(case: Case) -> Result<u8, Box<dyn std::error::Error>> {
    let mut evidence = Evidence {
        case,
        checks: vec![],
        descendant_pid: None,
    };
    match case {
        Case::Original | Case::Patched | Case::Clean => evidence.checks = access_checks(case),
        Case::Slow => std::thread::sleep(Duration::from_secs(10)),
        Case::Noisy => {
            let bytes = [b'x'; 4096];
            for _ in 0..512 {
                io::stdout().lock().write_all(&bytes)?;
                io::stderr().lock().write_all(&bytes)?;
            }
            return Ok(0);
        }
        Case::Malformed => {
            println!("not valid JSON");
            return Ok(0);
        }
        Case::SplitOutput => {
            // Each stream fits in 768 bytes; their total does not. JSON permits
            // the whitespace prefix, so a generous limit still completes.
            io::stdout().lock().write_all(&[b' '; 512])?;
            io::stderr().lock().write_all(&[b'x'; 512])?;
        }
        Case::Nonzero => {
            // Even plausible evidence must not turn a crashed process into a success.
            serde_json::to_writer(io::stdout().lock(), &evidence)?;
            return Ok(7);
        }
        Case::Descendant => {
            // Deliberately exit before a pipe-holding descendant. The supervisor must
            // terminate the group without waiting ten seconds for the pipe to close.
            let child = Command::new(std::env::current_exe()?)
                .args(["__fixture", "slow"])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()?;
            evidence.descendant_pid = Some(child.id());
        }
        Case::Environment => evidence.checks.push(Check {
            name: "parent_environment_absent".into(),
            expected: true,
            // Some platforms add runtime variables after exec. Check the explicit
            // parent canaries rather than mistaking those for inherited credentials.
            actual: std::env::var_os("PATCHRIOT_TEST_CANARY").is_none()
                && std::env::var_os("HOME").is_none(),
        }),
    }
    serde_json::to_writer(io::stdout().lock(), &evidence)?;
    io::stdout().lock().flush()?;
    Ok(0)
}
