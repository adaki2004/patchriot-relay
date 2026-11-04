//! One consented recovery route. A logical agent call can try NEAR then Venice;
//! both attempts reserve money, but consume just one call from the work allowance.
use super::*;
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Near,
    Venice,
}

fn fallback_body(mut body: Value) -> Value {
    body["model"] = json!(VENICE_FALLBACK_MODEL);
    body["stream"] = json!(false);
    body.as_object_mut()
        .expect("validated chat object")
        .remove("stream_options");
    body["store"] = json!(false);
    body["fallbacks"] = json!([]);
    body["venice_parameters"] = json!({
        "include_venice_system_prompt": false, "enable_web_search": "off",
        "enable_web_scraping": false, "enable_x_search": false
    });
    body
}

/// Published uncached Venice rates for the fixed DeepSeek fallback, 2026-11-04.
/// Failed/ambiguous attempts keep their full reservation; no guessed refunds.
fn fallback_cost(input: u64, output: u64) -> Option<u64> {
    Some(
        input
            .checked_mul(330_000)?
            .checked_add(output.checked_mul(1_320_000)?)?
            .div_ceil(1_000_000),
    )
}

impl LiveBroker {
    async fn venice_completion(&self, body: Value) -> Result<Value, &'static str> {
        let mut response = self
            .client
            .post("https://api.venice.ai/api/v1/chat/completions")
            .bearer_auth(
                self.fallback_key
                    .as_ref()
                    .ok_or("fallback_not_configured")?
                    .as_str(),
            )
            .json(&body)
            .send()
            .await
            .map_err(|_| "provider_unavailable")?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 | 403 => "provider_authentication_failed",
                429 => "provider_rate_limited",
                500..=599 => "provider_unavailable",
                _ => "provider_rejected_request",
            });
        }
        if response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| v.split(';').next() != Some("application/json"))
        {
            return Err("unexpected_provider_response");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "provider_stream_interrupted")?
        {
            if bytes.len() + chunk.len() > 2 * 1024 * 1024 {
                return Err("provider_response_limit");
            }
            bytes.extend_from_slice(&chunk);
        }
        let completion: Value =
            serde_json::from_slice(&bytes).map_err(|_| "provider_invalid_json")?;
        if completion["model"] != VENICE_FALLBACK_MODEL {
            return Err("wrong_provider_model");
        }
        if !completion["choices"][0]["message"].is_object() {
            return Err("provider_missing_message");
        }
        Ok(completion)
    }

    fn reserve_route(
        &self,
        route: Route,
        body: &Value,
        engine: bool,
        new_call: bool,
        reason: Option<&'static str>,
    ) -> Result<u64, &'static str> {
        if Instant::now() >= self.deadline {
            return Err("attempt_deadline_reached");
        }
        let length = serde_json::to_vec(body)
            .map_err(|_| "invalid_model_request")?
            .len();
        if length > MAX_FRAME {
            return Err("model_request_too_large");
        }
        let reservation = match route {
            Route::Near => token_cost(LiveProvider::NearDeepSeek, length as u64 + 4096, 8192),
            Route::Venice => fallback_cost(length as u64 + 4096, 8192),
        }
        .ok_or("provider_budget_reached")?;
        let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
        // A recovery for the last allowed logical call is still allowed. Money,
        // engine reserve and wall time remain bounded for each physical attempt.
        if engine
            && ((new_call && count.calls >= ENGINE_CALL_LIMIT)
                || count.reserved.saturating_add(reservation) > MAX_SPEND - REVIEWER_RESERVE
                || self.deadline.saturating_duration_since(Instant::now())
                    <= Duration::from_secs(240))
        {
            return Err("engine_budget_reached");
        }
        if (new_call && count.calls >= MAX_LIVE_INFERENCE_CALLS)
            || count.reserved.saturating_add(reservation) > MAX_SPEND
        {
            return Err("provider_budget_reached");
        }
        if new_call {
            count.calls += 1;
        }
        count.reserved += reservation;
        match route {
            Route::Near => count.primary_attempts += 1,
            Route::Venice => {
                let primary_attempts = count.primary_attempts;
                let receipt = count.fallback.get_or_insert_with(|| VeniceFallbackReceipt {
                    model: VENICE_FALLBACK_MODEL.into(),
                    reason: reason.unwrap_or("provider_unavailable").into(),
                    primary_attempts,
                    fallback_attempts: 0,
                    fallback_completed: 0,
                });
                receipt.fallback_attempts += 1;
            }
        }
        Ok(reservation)
    }

    fn finish_route(
        &self,
        route: Route,
        reservation: u64,
        completion: &Value,
    ) -> Result<(), &'static str> {
        let usage = &completion["usage"];
        let cost = usage["prompt_tokens"]
            .as_u64()
            .zip(usage["completion_tokens"].as_u64())
            .filter(|(input, output)| *input > 0 && *input <= 10_000_000 && *output <= 1_000_000)
            .and_then(|(input, output)| match route {
                Route::Near => token_cost(LiveProvider::NearDeepSeek, input, output),
                Route::Venice => fallback_cost(input, output),
            });
        let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
        if let Some(cost) = cost {
            count.reserved = count
                .reserved
                .saturating_sub(reservation)
                .saturating_add(cost);
        }
        if route == Route::Venice {
            count
                .fallback
                .as_mut()
                .ok_or("counter_unavailable")?
                .fallback_completed += 1;
        }
        Ok(())
    }

    async fn route_completion<F, R>(
        &self,
        body: Value,
        engine: bool,
        mut send: F,
    ) -> Result<Value, &'static str>
    where
        F: FnMut(Route, Value) -> R,
        R: Future<Output = Result<Value, &'static str>>,
    {
        let already_fell_back = self
            .counters
            .lock()
            .map_err(|_| "counter_unavailable")?
            .fallback
            .is_some();
        if already_fell_back {
            let body = fallback_body(body);
            let reserved = self.reserve_route(Route::Venice, &body, engine, true, None)?;
            let completion = send(Route::Venice, body).await?;
            self.finish_route(Route::Venice, reserved, &completion)?;
            return Ok(completion);
        }
        let reserved = self.reserve_route(Route::Near, &body, engine, true, None)?;
        match send(Route::Near, body.clone()).await {
            Ok(completion) => {
                self.finish_route(Route::Near, reserved, &completion)?;
                Ok(completion)
            }
            Err(reason) if fallback_available_for(reason) && self.fallback_key.is_some() => {
                // Nothing has reached the agent. Keep NEAR's uncertain charge,
                // reserve Venice separately and stay on Venice for this role.
                let body = fallback_body(body);
                let reserved =
                    self.reserve_route(Route::Venice, &body, engine, false, Some(reason))?;
                eprintln!("model recovery: near.ai -> venice.ai reason={reason}");
                let completion = send(Route::Venice, body).await?;
                self.finish_route(Route::Venice, reserved, &completion)?;
                Ok(completion)
            }
            Err(reason) => Err(reason),
        }
    }

    pub(super) async fn routed_model(
        &self,
        body: Value,
        engine: bool,
        id: u64,
        output: &mpsc::Sender<Frame>,
    ) -> Result<(), &'static str> {
        let stream = body["stream"] == true;
        let completion = self
            .route_completion(body, engine, |route, body| async move {
                match route {
                    Route::Near => {
                        near::complete(
                            self.near.as_ref().ok_or("near_configuration_invalid")?,
                            body,
                        )
                        .await
                    }
                    Route::Venice => self.venice_completion(body).await,
                }
            })
            .await?;
        // Buffer both routes fully. Never mix partial responses or execute a
        // tool from NEAR and then issue a replacement completion to Venice.
        let bytes = near::response_bytes(&completion, stream)?;
        output
            .send(Frame::Start {
                id,
                status: 200,
                content_type: if stream {
                    "text/event-stream"
                } else {
                    "application/json"
                },
            })
            .await
            .map_err(|_| "agent_disconnected")?;
        for chunk in bytes.chunks(4096) {
            output
                .send(Frame::Chunk {
                    id,
                    hex: hex::encode(chunk),
                })
                .await
                .map_err(|_| "agent_disconnected")?;
        }
        output
            .send(Frame::End { id })
            .await
            .map_err(|_| "agent_disconnected")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn broker() -> Arc<LiveBroker> {
        let mut broker = super::super::tests::broker();
        let value = Arc::get_mut(&mut broker).unwrap();
        value.provider = LiveProvider::NearDeepSeek;
        value.fallback_key = Some(zeroize::Zeroizing::new("fixture-only-key".into()));
        broker
    }
    fn request() -> Value {
        json!({"model":LiveProvider::NearDeepSeek.model(), "messages":[{"role":"user","content":"Owned synthetic fixture"}], "stream":true, "stream_options":{"include_usage":true}, "max_tokens":8192})
    }
    fn reply() -> Value {
        json!({"model":VENICE_FALLBACK_MODEL,"choices":[{"message":{"role":"assistant","content":"fixture"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":100}})
    }
    #[tokio::test]
    async fn recovery_is_one_logical_call_and_sticks_to_venice_for_this_role() {
        let broker = broker();
        let mut routes = Vec::new();
        let result = broker
            .route_completion(request(), false, |route, body| {
                routes.push(route);
                std::future::ready(match route {
                    Route::Near => Err("provider_rate_limited"),
                    Route::Venice => {
                        assert_eq!(body["model"], VENICE_FALLBACK_MODEL);
                        assert_eq!(body["messages"], request()["messages"]);
                        assert_eq!(body["venice_parameters"]["enable_web_search"], "off");
                        assert_eq!(body["fallbacks"], json!([]));
                        assert_eq!(body["store"], false);
                        assert_eq!(body["stream"], false);
                        Ok(reply())
                    }
                })
            })
            .await
            .unwrap();
        assert_eq!(result, reply());
        assert_eq!(routes, vec![Route::Near, Route::Venice]);
        let uncertain_primary_cost = token_cost(
            LiveProvider::NearDeepSeek,
            serde_json::to_vec(&request()).unwrap().len() as u64 + 4096,
            8192,
        )
        .unwrap();
        {
            let count = broker.counters.lock().unwrap();
            assert_eq!(count.calls, 1);
            assert_eq!(
                count.reserved,
                uncertain_primary_cost + fallback_cost(1000, 100).unwrap()
            );
            let receipt = count.fallback.as_ref().unwrap();
            assert!(receipt.valid(1));
            assert_eq!(receipt.fallback_completed, 1);
        }
        broker
            .route_completion(request(), false, |route, _| {
                assert_eq!(route, Route::Venice);
                std::future::ready(Ok(reply()))
            })
            .await
            .unwrap();
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 2);
        let receipt = count.fallback.as_ref().unwrap();
        assert!(receipt.valid(2));
        assert_eq!(receipt.primary_attempts, 1);
        assert_eq!(receipt.fallback_completed, 2);
    }
    #[tokio::test]
    async fn invalid_evidence_credentials_and_bad_input_never_send_to_backup() {
        for reason in [
            "near_attestation_invalid",
            "near_signature_invalid",
            "near_model_signature_required",
            "wrong_provider_model",
            "provider_authentication_failed",
            "provider_rejected_request",
            "provider_context_limit",
            "provider_budget_reached",
            "provider_invalid_json",
        ] {
            let broker = broker();
            let mut calls = 0;
            assert_eq!(
                broker
                    .route_completion(request(), false, |route, _| {
                        calls += 1;
                        assert_eq!(route, Route::Near);
                        std::future::ready(Err(reason))
                    })
                    .await,
                Err(reason)
            );
            assert_eq!(calls, 1);
            assert!(broker.counters.lock().unwrap().fallback.is_none());
        }
    }
    #[tokio::test]
    async fn old_consent_or_no_key_has_no_fallback_and_primary_success_is_unchanged() {
        let mut broker = broker();
        Arc::get_mut(&mut broker).unwrap().fallback_key = None;
        let mut calls = 0;
        assert_eq!(
            broker
                .route_completion(request(), false, |route, _| {
                    calls += 1;
                    assert_eq!(route, Route::Near);
                    std::future::ready(Err("provider_unavailable"))
                })
                .await,
            Err("provider_unavailable")
        );
        assert_eq!(calls, 1);
        broker
            .route_completion(request(), false, |route, _| {
                assert_eq!(route, Route::Near);
                std::future::ready(Ok(reply()))
            })
            .await
            .unwrap();
        assert!(broker.counters.lock().unwrap().fallback.is_none());
    }
    #[tokio::test]
    async fn no_loop_when_both_providers_fail_and_cost_is_not_refunded() {
        let broker = broker();
        let mut routes = Vec::new();
        assert_eq!(
            broker
                .route_completion(request(), false, |route, _| {
                    routes.push(route);
                    std::future::ready(Err("provider_unavailable"))
                })
                .await,
            Err("provider_unavailable")
        );
        assert_eq!(routes, vec![Route::Near, Route::Venice]);
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 1);
        assert!(count.reserved > 10_000);
        let receipt = count.fallback.as_ref().unwrap();
        assert!(receipt.valid(1));
        assert_eq!(receipt.fallback_completed, 0);
    }
    #[tokio::test]
    async fn money_deadline_and_engine_reserve_still_bound_recovery() {
        for engine in [false, true] {
            let broker = broker();
            let body = request();
            let reserve = token_cost(
                LiveProvider::NearDeepSeek,
                serde_json::to_vec(&body).unwrap().len() as u64 + 4096,
                8192,
            )
            .unwrap();
            broker.counters.lock().unwrap().reserved =
                MAX_SPEND - if engine { REVIEWER_RESERVE } else { 0 } - reserve;
            let mut calls = 0;
            let result = broker
                .route_completion(body, engine, |route, _| {
                    calls += 1;
                    assert_eq!(route, Route::Near);
                    std::future::ready(Err("provider_unavailable"))
                })
                .await;
            assert_eq!(
                result,
                Err(if engine {
                    "engine_budget_reached"
                } else {
                    "provider_budget_reached"
                })
            );
            assert_eq!(calls, 1);
            assert!(broker.counters.lock().unwrap().fallback.is_none());
        }
        let mut broker = broker();
        Arc::get_mut(&mut broker).unwrap().deadline = Instant::now();
        assert_eq!(
            broker
                .route_completion(request(), false, |_, _| {
                    panic!("expired work must not contact a model");
                    #[allow(unreachable_code)]
                    std::future::ready(Ok(reply()))
                })
                .await,
            Err("attempt_deadline_reached")
        );
    }
    #[tokio::test]
    async fn last_engine_call_can_recover_without_stealing_another_call() {
        let broker = broker();
        broker.counters.lock().unwrap().calls = ENGINE_CALL_LIMIT - 1;
        broker.counters.lock().unwrap().primary_attempts = ENGINE_CALL_LIMIT - 1;
        broker
            .route_completion(request(), true, |route, _| {
                std::future::ready(match route {
                    Route::Near => Err("provider_unavailable"),
                    Route::Venice => Ok(reply()),
                })
            })
            .await
            .unwrap();
        assert_eq!(broker.counters.lock().unwrap().calls, ENGINE_CALL_LIMIT);
        assert_eq!(
            broker
                .route_completion(request(), true, |_, _| {
                    panic!("engine allowance must still stop");
                    #[allow(unreachable_code)]
                    std::future::ready(Ok(reply()))
                })
                .await,
            Err("engine_budget_reached")
        );
    }

    #[tokio::test]
    #[ignore = "one bounded Venice call after a synthetic NEAR failure; private key and new attempt file required"]
    async fn paid_venice_recovery_smoke() {
        use std::io::Write;
        let path = std::env::var("PATCHRIOT_VENICE_SMOKE_FILE")
            .expect("new private attempt file required");
        let mut guard = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("do not replay a paid smoke call");
        guard
            .write_all(b"Synthetic NEAR 429; one Venice response; 256 output tokens maximum\n")
            .unwrap();
        guard.sync_all().unwrap();
        let key_file =
            std::env::var("PATCHRIOT_VENICE_KEY_FILE").expect("private key file required");
        let mut broker = broker();
        Arc::get_mut(&mut broker).unwrap().fallback_key =
            Some(read_provider_key(Path::new(&key_file)).unwrap());
        let mut body = request();
        body["max_tokens"] = json!(256);
        body["reasoning_effort"] = json!("none");
        body["messages"] = json!([{"role":"user","content":"Synthetic connectivity test. Reply with the single word OK. Do not call any tools."}]);
        let completion = broker
            .route_completion(body, false, |route, body| {
                let broker = &broker;
                async move {
                    match route {
                        Route::Near => Err("provider_rate_limited"),
                        Route::Venice => broker.venice_completion(body).await,
                    }
                }
            })
            .await
            .expect("a complete Venice response is required");
        assert!(
            completion["choices"][0]["message"]["content"]
                .as_str()
                .is_some_and(|s| s.trim() == "OK")
        );
        assert!(completion["usage"]["completion_tokens"].as_u64().unwrap() <= 256);
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 1);
        assert_eq!(count.fallback.as_ref().unwrap().fallback_completed, 1);
        println!(
            "one logical call; synthetic NEAR 429; one real Venice reply; content and credentials omitted"
        );
    }
}
