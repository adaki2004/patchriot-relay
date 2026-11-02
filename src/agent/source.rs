//! A source bundle is delivered through stdin and kept only in container tmpfs. The
//! report validates quoted text against the original dispatcher bundle.

use super::{AgentRun, Settings};
use patchriot_protocol::{ReviewRole, sources::*};
use serde::Serialize;
use serde_json::Value;

pub struct Task {
    pub role: ReviewRole,
    pub snapshot_sha256: String,
    pub evidence: SourceWorkEvidence,
}

impl Task {
    pub fn input(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if !self.evidence.bundle.valid()
            || self.evidence.previous_reports.len() > 2
            || bundle_hash(&self.evidence.bundle)? != self.snapshot_sha256
        {
            return Err("source bundle does not match the assignment".into());
        }
        // Preserve the exact serialized bytes used for the digest. Passing a JSON
        // object through another language could change key order or escaping.
        #[derive(Serialize)]
        struct Input<'a> {
            kind: &'static str,
            role: ReviewRole,
            snapshot_sha256: &'a str,
            source_json: String,
            previous_reports: &'a [PriorSourceReport],
        }
        let mut bytes = serde_json::to_vec(&Input {
            kind: "source_bundle_v1",
            role: self.role,
            snapshot_sha256: &self.snapshot_sha256,
            source_json: serde_json::to_string(&self.evidence.bundle)?,
            previous_reports: &self.evidence.previous_reports,
        })?;
        bytes.push(b'\n');
        if bytes.len() > 512 * 1024 {
            return Err("source assignment input exceeds 512 KiB".into());
        }
        Ok(bytes)
    }
}

fn summary(text: &str) -> String {
    let mut result = String::new();
    for c in text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
    {
        if result.len() + c.len_utf8() > 4000 {
            break;
        }
        result.push(c);
    }
    result
}

pub(super) fn evidence(
    report: &AgentRun,
    settings: &Settings,
    declared: Option<&str>,
    task: &Task,
    completed: bool,
    cleanup: bool,
) -> SourceAgentResult {
    let mut inspected_snapshot_sha256 = None;
    let mut terminal_calls = 0;
    for event in &report.events {
        if event["event"] != "tool_complete" || event["data"]["args"][1] != "terminal" {
            continue;
        }
        terminal_calls += 1;
        let args = &event["data"]["args"];
        if args[2]["command"] != "python /patchriot/inspect_source.py" {
            continue;
        }
        let Some(tool) = args[3]
            .as_str()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
        else {
            continue;
        };
        if tool["exit_code"] != 0 || !tool["error"].is_null() {
            continue;
        }
        let Some(output) = tool["output"]
            .as_str()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
        else {
            continue;
        };
        if output["snapshot_sha256"] == task.snapshot_sha256 {
            inspected_snapshot_sha256 = Some(task.snapshot_sha256.clone());
        }
    }
    let response = report
        .events
        .iter()
        .find(|e| e["event"] == "result")
        .and_then(|e| e["data"]["final_response"].as_str())
        .unwrap_or("");
    let json = response
        .trim()
        .strip_prefix("```json\n")
        .and_then(|s| s.strip_suffix("```"))
        .or_else(|| {
            response
                .trim()
                .strip_prefix("```\n")
                .and_then(|s| s.strip_suffix("```"))
        })
        .unwrap_or(response)
        .trim();
    let assessment =
        serde_json::from_str::<patchriot_protocol::website_reviews::WebsiteAssessment>(json)
            .ok()
            .filter(patchriot_protocol::website_reviews::WebsiteAssessment::valid);
    let raw_summary = if assessment.is_some() {
        String::new()
    } else {
        summary(response)
    };
    SourceAgentResult {
        kind: SourceResultKind::SourceAgentV1,
        execution: patchriot_protocol::website_reviews::WebsiteExecution {
            state: match report.outcome {
                "completed" if completed => {
                    patchriot_protocol::website_reviews::WebsiteRunState::Completed
                }
                "timed_out" => patchriot_protocol::website_reviews::WebsiteRunState::TimedOut,
                "cancelled" => patchriot_protocol::website_reviews::WebsiteRunState::Cancelled,
                _ => patchriot_protocol::website_reviews::WebsiteRunState::Failed,
            },
            declared_model: declared.unwrap_or(&settings.model).into(),
            model: settings.model.clone(),
            model_digest: settings.model_digest.clone(),
            image_digest: settings.image.clone(),
            duration_ms: report.duration_ms.try_into().unwrap_or(u64::MAX),
            inference_calls: report.inference_calls.try_into().unwrap_or(u16::MAX),
            terminal_calls,
            cleanup_confirmed: cleanup,
        },
        snapshot_sha256: task.snapshot_sha256.clone(),
        inspected_snapshot_sha256,
        assessment,
        raw_summary,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn task() -> Task {
        let input: CreateSourceUpload = serde_json::from_value(json!({"request_id":uuid::Uuid::new_v4(),"title":"Owned example","objective":"Check record access rules.","permission_note":"I wrote this owned synthetic example.","accepts_private_storage":true,"files":[{"path":"access.py","text":"def read(user, owner, data):\n    return data\n"}]})).unwrap();
        let bundle = input.bundle().unwrap();
        Task {
            role: ReviewRole::Investigator,
            snapshot_sha256: bundle_hash(&bundle).unwrap(),
            evidence: SourceWorkEvidence {
                bundle,
                previous_reports: vec![],
            },
        }
    }

    #[test]
    fn source_frames_preserve_bytes_and_reject_corruption_and_unsafe_paths() {
        let mut task = task();
        let frame: Value = serde_json::from_slice(&task.input().unwrap()).unwrap();
        assert_eq!(frame["kind"], "source_bundle_v1");
        assert_eq!(
            frame["source_json"],
            serde_json::to_string(&task.evidence.bundle).unwrap()
        );
        task.evidence.bundle.files[0].text.push('!');
        task.snapshot_sha256 = bundle_hash(&task.evidence.bundle).unwrap();
        assert!(
            task.input().is_err(),
            "a correct bundle hash cannot repair a wrong file hash"
        );
        let mut task = self::task();
        task.evidence.bundle.files[0].path = "../outside.py".into();
        task.snapshot_sha256 = bundle_hash(&task.evidence.bundle).unwrap();
        assert!(task.input().is_err());
    }

    #[test]
    fn source_report_requires_the_fixed_reader_real_quotes_and_cleanup() {
        let task = task();
        let settings = super::super::tests::settings();
        let assessment = json!({"summary":"Unchecked return.","findings":[{"title":"Missing ownership check","support":"observed_in_snapshot","explanation":"The supplied function returns data without checking its caller.","suggested_action":"Check ownership before returning the record.","citations":[{"resource_sha256":task.evidence.bundle.files[0].sha256,"quote":"return data"}]}],"limitations":["Static text only; no execution."]});
        let tool = json!({"exit_code":0,"error":null,"output":json!({"snapshot_sha256":task.snapshot_sha256}).to_string()});
        let mut run = AgentRun {
            outcome: "completed",
            inference_calls: 1,
            events: vec![
                json!({"event":"tool_complete","data":{"args":["fixed-read","terminal",{"command":"python /patchriot/inspect_source.py"},tool.to_string()]}}),
                json!({"event":"result","data":{"final_response":assessment.to_string()}}),
            ],
            ..AgentRun::default()
        };
        assert!(
            evidence(&run, &settings, None, &task, true, true)
                .evidence_complete(&task.evidence.bundle)
        );
        assert!(
            !evidence(&run, &settings, None, &task, true, false)
                .evidence_complete(&task.evidence.bundle)
        );
        run.events[0]["data"]["args"][2]["command"] = json!("python /patchriot/inspect_site.py");
        assert!(
            !evidence(&run, &settings, None, &task, true, true)
                .evidence_complete(&task.evidence.bundle)
        );
        run.events[0]["data"]["args"][2]["command"] = json!("python /patchriot/inspect_source.py");
        let mut invented = assessment;
        invented["findings"][0]["citations"][0]["quote"] = json!("invented ownership check");
        run.events[1]["data"]["final_response"] = json!(invented.to_string());
        assert!(
            !evidence(&run, &settings, None, &task, true, true)
                .evidence_complete(&task.evidence.bundle)
        );
    }
}
