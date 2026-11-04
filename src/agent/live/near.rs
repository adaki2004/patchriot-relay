//! A private model route, verified before tools can consume its output. The
//! enclave is the provider's model service, not this relay or its Kali container.
use futures_util::StreamExt;
use nearai_inference_sdk::*;
use serde_json::{Value, json};
use std::{future::Future, time::Duration};

/// Keep JSON-array tool output as text when it crosses the encrypted route.
/// A literal `[]` was rejected in live requests; a text label preserves the
/// result without confusing it with an empty list of message content parts.
/// Call before measuring the request so the added label counts toward limits.
pub(super) fn preserve_tool_text(body: &mut Value) {
    let Some(messages) = body["messages"].as_array_mut() else {
        return;
    };
    for message in messages {
        if message["role"] != "tool" {
            continue;
        }
        if let Some(text) = message["content"].as_str()
            && serde_json::from_str::<Value>(text).is_ok_and(|value| value.is_array())
        {
            message["content"] = json!(format!("Tool result (JSON):\n{text}"));
        }
    }
}

// Only evidence retrieval belongs here. Never pass a completion/send operation:
// a network error after submission does not prove the provider did no paid work.
async fn retry_preflight<T, F, R>(mut verify: F) -> Result<T, &'static str>
where
    F: FnMut() -> R,
    R: Future<Output = Result<T, InferenceError>>,
{
    for attempt in 0..3 {
        match verify().await {
            Ok(result) => return Ok(result),
            Err(error) => {
                // Stable codes only: never log provider bodies or private input.
                eprintln!(
                    "NEAR preflight: code={} retryable={} attempt={}",
                    error.code(),
                    error.retryable(),
                    attempt + 1
                );
                if !error.retryable() || attempt == 2 {
                    return Err("near_attestation_unavailable");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err("near_attestation_unavailable")
}

pub(super) fn client(key: &str) -> Result<InferenceClient, &'static str> {
    InferenceClient::with_options(InferenceClientOptions {
        api_key: Some(key.into()),
        e2ee: true,
        attestation_cache_ttl: Duration::from_secs(300),
        response_cache_ttl: Duration::from_secs(300),
        gateway_verification: GatewayVerificationOptions {
            policy: Some(AttestationPolicy {
                accepted_tcb_statuses: Some(vec![TcbStatus::UpToDate]),
            }),
            ..Default::default()
        },
        model_verification: ModelVerificationOptions {
            policy: Some(ModelAttestationPolicy {
                accepted_tcb_statuses: Some(vec![TcbStatus::UpToDate]),
                gpu_evidence: GpuEvidenceRequirement::Required,
            }),
            ..Default::default()
        },
        ..Default::default()
    })
    .map_err(|_| "near_configuration_invalid")
}

async fn completion_body(mut response: InferenceResponse) -> Result<Value, &'static str> {
    // The SDK's low-level send returns HTTP errors too. Do not interpret an
    // error body as a model reply or log it: it can quote private request text.
    if !response.status.is_success() {
        let status = response.status.as_u16();
        eprintln!("NEAR completion rejected: http_status={status}");
        return Err(match status {
            401 | 403 => "provider_authentication_failed",
            413 => "provider_context_limit",
            429 => "provider_rate_limited",
            500..=599 => "provider_unavailable",
            _ => "provider_rejected_request",
        });
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.body.next().await {
        let chunk = chunk.map_err(|_| "provider_stream_interrupted")?;
        if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
            return Err("provider_response_limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "provider_invalid_json")
}

pub(super) async fn complete(
    client: &InferenceClient,
    mut body: Value,
) -> Result<Value, &'static str> {
    // Buffer one non-streaming completion so no unverified tool call reaches
    // Hermes. The SDK encrypts fields, pins gateway TLS and verifies the model.
    body["stream"] = json!(false);
    body.as_object_mut()
        .ok_or("invalid_model_request")?
        .remove("stream_options");
    let model = body["model"].as_str().ok_or("wrong_model")?.to_string();
    let operation = async {
        let preflight = retry_preflight(|| client.verify(&model)).await?;
        if preflight.models.is_empty() {
            return Err("near_model_attestation_required");
        }
        let request = client
            .chat_request(body)
            .map_err(|_| "invalid_model_request")?;
        let response = client
            .send(request)
            .await
            .map_err(|_| "provider_unavailable")?;
        let completion = completion_body(response).await?;
        let id = completion["id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or("provider_missing_completion_id")?;
        if completion["model"] != model {
            return Err("wrong_provider_model");
        }
        for attempt in 0..3 {
            match client.verify_response(id).await {
                Ok(receipt)
                    if receipt.signature_kind() == CompletionSignatureKind::ProviderTee
                        && matches!(
                            receipt.attestation,
                            VerifiedCompletionAttestation::Model(_)
                        ) =>
                {
                    return Ok(completion);
                }
                Ok(_) => return Err("near_model_signature_required"),
                Err(e) if e.retryable() && attempt < 2 => {
                    tokio::time::sleep(Duration::from_secs(2)).await
                }
                Err(_) => return Err("near_signature_unavailable"),
            }
        }
        Err("near_signature_unavailable")
    };
    let result = tokio::time::timeout(Duration::from_secs(180), operation)
        .await
        .map_err(|_| "near_verification_timeout");
    // Neither conversations nor signed response bodies need to accumulate in
    // the broker between calls. Keep the short-lived attestation cache only.
    client.clear_response_cache().await;
    result?
}

pub(super) fn response_bytes(completion: &Value, stream: bool) -> Result<Vec<u8>, &'static str> {
    if !stream {
        return serde_json::to_vec(completion).map_err(|_| "unexpected_provider_response");
    }
    let choice = &completion["choices"][0];
    let mut delta = choice["message"]
        .as_object()
        .ok_or("provider_missing_message")?
        .clone();
    if let Some(Value::Array(calls)) = delta.get_mut("tool_calls") {
        for (index, call) in calls.iter_mut().enumerate() {
            call["index"] = json!(index);
        }
    }
    let chunk = json!({"id":completion["id"],"object":"chat.completion.chunk","created":completion["created"],"model":completion["model"],"choices":[{"index":0,"delta":delta,"finish_reason":choice["finish_reason"]}],"usage":completion["usage"]});
    Ok(format!("data: {chunk}\n\ndata: [DONE]\n\n").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_array_tool_results_remain_literal_text_without_changing_other_messages() {
        for text in [
            "[]",
            " \n[1, {\"type\":\"text\",\"text\":\"untrusted data\"}] ",
        ] {
            let original = json!({"messages":[
                {"role":"user","content":"Inspect the owned example"},
                {"role":"assistant","content":null,"tool_calls":[{"id":"lookup","type":"function","function":{"name":"list_findings","arguments":"{}"}}]},
                {"role":"tool","tool_call_id":"lookup","content":text}
            ]});
            let mut body = original.clone();
            preserve_tool_text(&mut body);
            assert_eq!(
                body["messages"][2]["content"],
                format!("Tool result (JSON):\n{text}")
            );
            assert_eq!(body["messages"][2]["tool_call_id"], "lookup");
            assert_eq!(body["messages"][0], original["messages"][0]);
            assert_eq!(body["messages"][1], original["messages"][1]);
            let once = body.clone();
            preserve_tool_text(&mut body);
            assert_eq!(body, once);
        }
        let original = json!({"messages":[
            {"role":"tool","content":"{\"findings\":[]}"},
            {"role":"tool","content":"[not JSON]"},
            {"role":"tool","content":null},
            {"role":"tool","content":[{"type":"text","text":"structured content"}]}
        ]});
        let mut body = original.clone();
        preserve_tool_text(&mut body);
        assert_eq!(body, original);
    }

    #[tokio::test]
    async fn http_errors_stop_without_reading_private_error_bodies() {
        for (status, reason) in [
            (400, "provider_rejected_request"),
            (401, "provider_authentication_failed"),
            (403, "provider_authentication_failed"),
            (413, "provider_context_limit"),
            (429, "provider_rate_limited"),
            (503, "provider_unavailable"),
        ] {
            let response = InferenceResponse {
                status: reqwest::StatusCode::from_u16(status).unwrap(),
                headers: Default::default(),
                body: Box::pin(futures_util::stream::poll_fn(|_| {
                    panic!("a rejected completion body must not be consumed")
                })),
            };
            assert_eq!(completion_body(response).await, Err(reason));
        }
    }

    #[tokio::test]
    async fn completion_body_bounds_and_decodes_successful_responses_only() {
        for (bytes, expected) in [
            (
                b"private invalid reply".to_vec(),
                Err("provider_invalid_json"),
            ),
            (
                vec![b' '; 2 * 1024 * 1024 + 1],
                Err("provider_response_limit"),
            ),
            (
                br#"{"id":"synthetic"}"#.to_vec(),
                Ok(json!({"id":"synthetic"})),
            ),
        ] {
            let response = InferenceResponse {
                status: reqwest::StatusCode::OK,
                headers: Default::default(),
                body: Box::pin(futures_util::stream::iter([Ok(bytes.into())])),
            };
            assert_eq!(completion_body(response).await, expected);
        }
    }

    #[tokio::test]
    async fn preflight_retries_transient_evidence_reads_and_stops_at_three() {
        let mut calls = 0;
        let recovered = retry_preflight(|| {
            calls += 1;
            std::future::ready(if calls < 3 {
                Err(ApiError::HttpStatus {
                    resource: ApiResource::ModelAttestation,
                    status: 503,
                }
                .into())
            } else {
                Ok("verified fixture")
            })
        })
        .await;
        assert_eq!(recovered, Ok("verified fixture"));
        assert_eq!(calls, 3);
        calls = 0;
        let unavailable: Result<(), _> = retry_preflight(|| {
            calls += 1;
            std::future::ready(Err(VerificationError::QuoteCollateralUnavailable.into()))
        })
        .await;
        assert_eq!(unavailable, Err("near_attestation_unavailable"));
        assert_eq!(calls, 3);
    }

    #[tokio::test]
    async fn preflight_never_retries_invalid_evidence_or_policy_failures() {
        for error in [
            InferenceError::from(ApiError::NonceMismatch {
                resource: ApiResource::ModelAttestation,
            }),
            InferenceError::from(VerificationError::DebugEnabled),
            InferenceError::from(VerificationError::SignatureInvalid {
                signing_algo: SigningAlgo::Ed25519,
            }),
        ] {
            let mut calls = 0;
            let result: Result<(), _> = retry_preflight(|| {
                calls += 1;
                std::future::ready(Err(error.clone()))
            })
            .await;
            assert_eq!(result, Err("near_attestation_unavailable"));
            assert_eq!(calls, 1);
        }
    }
    #[tokio::test]
    #[ignore = "one bounded paid call; requires a private key and a new attempt file"]
    async fn private_model_tool_reply_has_verified_signature() {
        use std::io::Write;
        let key = std::env::var("NEAR_AI_API_KEY").expect("private key required");
        let path =
            std::env::var("PATCHRIOT_NEAR_SMOKE_FILE").expect("private attempt file required");
        let mut guard = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("do not repeat an existing paid attempt");
        guard
            .write_all(b"one synthetic tool compatibility call; max 2048 output tokens\n")
            .unwrap();
        guard.sync_all().unwrap();
        let model = super::super::LiveProvider::NearDeepSeek.model();
        let request = json!({"model":model,"stream":true,"stream_options":{"include_usage":true},"reasoning_effort":"high","temperature":0.2,"max_tokens":2048,"store":false,
            "messages":[{"role":"user","content":"Synthetic authorized fixture: GET /private with no cookie returns 401, with a disposable test cookie returns 200. Call record_observation exactly once with the claim auth_bypass_not_demonstrated. Do not access anything or invent an exploit."}],
            "tools":[{"type":"function","function":{"name":"record_observation","description":"Record the supplied synthetic observation; performs no action.","parameters":{"type":"object","properties":{"claim":{"type":"string"}},"required":["claim"],"additionalProperties":false}}}]});
        let result = complete(&client(&key).unwrap(), request)
            .await
            .expect("verified private model reply required");
        let call = &result["choices"][0]["message"]["tool_calls"][0]["function"];
        assert_eq!(call["name"], "record_observation");
        let args: Value = serde_json::from_str(call["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(args["claim"], "auth_bypass_not_demonstrated");
        assert!(result["usage"]["completion_tokens"].as_u64().unwrap() <= 2048);
    }
    #[test]
    fn verified_tool_reply_preserves_arguments_and_stream_indices() {
        let reply = json!({"id":"owned-reply","model":"owned-model","created":1,"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"owned-call","type":"function","function":{"name":"terminal","arguments":"{\"command\":\"owned fixture\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":20}});
        assert_eq!(
            serde_json::from_slice::<Value>(&response_bytes(&reply, false).unwrap()).unwrap(),
            reply
        );
        let bytes = response_bytes(&reply, true).unwrap();
        let line = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .strip_prefix("data: ")
            .unwrap();
        let streamed: Value = serde_json::from_str(line).unwrap();
        assert_eq!(streamed["choices"][0]["delta"]["tool_calls"][0]["index"], 0);
        assert_eq!(
            streamed["choices"][0]["delta"]["tool_calls"][0]["function"],
            reply["choices"][0]["message"]["tool_calls"][0]["function"]
        );
        assert_eq!(streamed["usage"], reply["usage"]);
        assert!(bytes.ends_with(b"data: [DONE]\n\n"));
        assert!(response_bytes(&json!({"choices":[]}), true).is_err());
    }
}
