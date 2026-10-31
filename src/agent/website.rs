//! A snapshot is delivered through stdin and kept only in container tmpfs. The
//! report validates quoted text against the original dispatcher snapshot.

use super::{AgentRun, Settings};
use patchriot_protocol::{ReviewRole, website_reviews::*};
use serde::Serialize;
use serde_json::Value;

pub struct Task {
    pub role: ReviewRole,
    pub snapshot_sha256: String,
    pub evidence: WebsiteWorkEvidence,
}

impl Task {
    pub fn input(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if snapshot_hash(&self.evidence.snapshot)? != self.snapshot_sha256 {
            return Err("website snapshot does not match the assignment".into());
        }
        // Preserve the exact serialized bytes used for the digest. Passing a JSON
        // object through another language could change key order or escaping.
        #[derive(Serialize)]
        struct Input<'a> {
            kind: &'static str,
            role: ReviewRole,
            snapshot_sha256: &'a str,
            snapshot_json: String,
            previous_reports: &'a [PriorWebsiteReport],
        }
        let mut bytes = serde_json::to_vec(&Input {
            kind: "website_snapshot_v1",
            role: self.role,
            snapshot_sha256: &self.snapshot_sha256,
            snapshot_json: serde_json::to_string(&self.evidence.snapshot)?,
            previous_reports: &self.evidence.previous_reports,
        })?;
        bytes.push(b'\n');
        if bytes.len() > 6 * 1024 * 1024 {
            return Err("website assignment input exceeds 6 MiB".into());
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
) -> WebsiteAgentResult {
    let mut inspected_snapshot_sha256 = None;
    let mut terminal_calls = 0;
    for event in &report.events {
        if event["event"] != "tool_complete" || event["data"]["args"][1] != "terminal" {
            continue;
        }
        terminal_calls += 1;
        let args = &event["data"]["args"];
        if args[2]["command"] != "python /patchriot/inspect_site.py" {
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
    let assessment = serde_json::from_str::<WebsiteAssessment>(json)
        .ok()
        .filter(WebsiteAssessment::valid);
    let raw_summary = if assessment.is_some() {
        String::new()
    } else {
        summary(response)
    };
    WebsiteAgentResult {
        kind: WebsiteResultKind::WebsiteAgentV1,
        execution: WebsiteExecution {
            state: match report.outcome {
                "completed" if completed => WebsiteRunState::Completed,
                "timed_out" => WebsiteRunState::TimedOut,
                "cancelled" => WebsiteRunState::Cancelled,
                _ => WebsiteRunState::Failed,
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
mod tests {
    use super::*;
    use serde_json::json;

    fn task() -> Task {
        let snapshot = serde_json::from_value(json!({"schema_version":1,"scope":{"homepage":"https://example.com/","script_origins":[]},"homepage":{"kind":"homepage","url":"https://example.com/","sha256":"d".repeat(64),"bytes":8,"content_type":"text/html","headers":{},"text":"owned é","collected_at":1,"connected_ip":null},"resources":[],"scripts":[],"script_limit_reached":false,"requests_made":1,"captured_response_bytes":8,"started_at":1,"finished_at":2})).unwrap();
        Task {
            role: ReviewRole::Investigator,
            snapshot_sha256: snapshot_hash(&snapshot).unwrap(),
            evidence: WebsiteWorkEvidence {
                snapshot,
                previous_reports: vec![],
            },
        }
    }

    #[test]
    fn snapshot_digest_and_exact_bytes_survive_the_initial_frame() {
        let mut task = task();
        let bytes = task.input().unwrap();
        assert!(bytes.ends_with(b"\n"));
        let frame: Value = serde_json::from_slice(&bytes).unwrap();
        let decoded = serde_json::from_str(frame["snapshot_json"].as_str().unwrap()).unwrap();
        assert_eq!(snapshot_hash(&decoded).unwrap(), task.snapshot_sha256);
        task.evidence.snapshot.homepage.text.push('!');
        assert!(task.input().is_err());
    }

    #[test]
    fn prose_alone_wrong_commands_and_fabricated_quotes_do_not_complete_evidence() {
        let task = task();
        let settings = super::super::tests::settings();
        let assessment = json!({"summary":"Observed saved page text.","findings":[{"title":"Page content", "support":"observed_in_snapshot", "explanation":"Text appears in the snapshot.", "suggested_action":"Inspect runtime behavior separately.", "citations":[{"resource_sha256":"d".repeat(64),"quote":"owned é"}]}],"limitations":["No browser execution or exploit reproduction."]});
        let mut run = AgentRun {
            outcome: "completed",
            inference_calls: 2,
            events: vec![
                json!({"event":"result","data":{"final_response":assessment.to_string()}}),
            ],
            ..AgentRun::default()
        };
        assert!(
            !evidence(&run, &settings, None, &task, true, true)
                .evidence_complete(&task.evidence.snapshot)
        );
        let observed = json!({"snapshot_sha256":task.snapshot_sha256});
        let tool = json!({"exit_code":0,"error":null,"output":observed.to_string()});
        run.events.insert(0, json!({"event":"tool_complete", "data":{"args":["call-1","terminal",{"command":"python /patchriot/inspect_site.py"},tool.to_string()]}}));
        assert!(
            evidence(&run, &settings, None, &task, true, true)
                .evidence_complete(&task.evidence.snapshot)
        );
        assert!(
            !evidence(&run, &settings, None, &task, true, false)
                .evidence_complete(&task.evidence.snapshot)
        );
        run.events[0]["data"]["args"][2]["command"] = json!("echo invented");
        assert!(
            !evidence(&run, &settings, None, &task, true, true)
                .evidence_complete(&task.evidence.snapshot)
        );
        run.events[0]["data"]["args"][2]["command"] = json!("python /patchriot/inspect_site.py");
        let mut fake = assessment;
        fake["findings"][0]["citations"][0]["quote"] = json!("invented");
        run.events[1]["data"]["final_response"] = json!(fake.to_string());
        assert!(
            !evidence(&run, &settings, None, &task, true, true)
                .evidence_complete(&task.evidence.snapshot)
        );
        run.events[1]["data"]["final_response"] = json!("Model ignored the output schema.");
        let result = evidence(&run, &settings, None, &task, true, true);
        assert!(result.assessment.is_none());
        assert_eq!(result.raw_summary, "Model ignored the output schema.");
        assert!(!result.evidence_complete(&task.evidence.snapshot));
    }
}
