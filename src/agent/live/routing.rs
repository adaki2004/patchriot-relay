//! One consented recovery route. Deployment settings select either provider first;
//! both attempts reserve money, but consume just one call from the work allowance.
use super::*;
use std::future::Future;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Near,
    Venice,
}
impl Route {
    fn provider(self) -> LiveProvider {
        match self {
            Self::Near => LiveProvider::NearDeepSeek,
            Self::Venice => LiveProvider::VeniceDeepSeek,
        }
    }
    fn from_provider(provider: LiveProvider) -> Result<Self, &'static str> {
        match provider {
            LiveProvider::NearDeepSeek => Ok(Self::Near),
            LiveProvider::VeniceDeepSeek => Ok(Self::Venice),
            _ => Err("unsupported_routed_model"),
        }
    }
}

/// Check the complete, still-buffered response before Hermes receives it. Its
/// stream guard stops long repetition loops; detecting that here lets the
/// consented backup recover the same call without rerunning any target tools.
/// Short repeats and distinct table/code rows are deliberately left alone.
pub(super) fn check_repetition(completion: &Value) -> Result<(), &'static str> {
    let message = &completion["choices"][0]["message"];
    for field in ["content", "reasoning_content", "reasoning"] {
        let Some(text) = message[field].as_str() else {
            continue;
        };
        if repetition_dominates(text) {
            return Err("provider_repetition");
        }
    }
    Ok(())
}

fn repetition_dominates(text: &str) -> bool {
    use std::collections::{HashMap, HashSet};
    // The deployed Hermes guard starts at 16,000 characters and examines a
    // 64,000-character tail. Bound work independently of provider output size.
    let mut chars: Vec<_> = text.chars().rev().take(64_000).collect();
    if chars.len() < 16_000 {
        return false;
    }
    chars.reverse();
    let tail: String = chars.iter().collect();
    let lines: Vec<_> = tail
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if lines.len() >= 5 && lines.iter().collect::<HashSet<_>>().len() * 2 > lines.len() {
        return false;
    }
    let n = chars.len();
    let needed = n.div_ceil(120).max(5);
    let mut windows = HashMap::new();
    for window in chars.windows(60) {
        let count = windows.entry(window).or_insert(0_usize);
        *count += 1;
        if *count >= needed {
            return true;
        }
    }
    // Long repeated paragraphs need their whole period counted, not just a
    // short repeated window. Sample a fixed number of candidate anchors.
    let step = (n - 60).div_ceil(31).max(1);
    for start in (0..=n - 60).step_by(step) {
        let mut matches = 0;
        for end in start + 1..=n - 60 {
            if chars[start..start + 60] != chars[end..end + 60] {
                continue;
            }
            matches += 1;
            let period = end - start;
            let mut left = start;
            let mut right = start + 60;
            while left > 0 && chars[left - 1] == chars[left - 1 + period] {
                left -= 1;
            }
            while right + period < n && chars[right] == chars[right + period] {
                right += 1;
            }
            let covered = right + period - left;
            if covered >= period * 5 && covered * 2 >= n {
                return true;
            }
            if matches == 8 {
                break;
            }
        }
    }
    false
}

fn route_body(route: Route, mut body: Value) -> Value {
    if route == Route::Near {
        body["model"] = json!(LiveProvider::NearDeepSeek.model());
        let object = body.as_object_mut().expect("validated chat object");
        for field in ["venice_parameters", "fallbacks", "response_format"] {
            object.remove(field);
        }
        near::preserve_tool_text(&mut body);
        return body;
    }
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
#[cfg(test)]
fn fallback_cost(input: u64, output: u64) -> Option<u64> {
    token_cost(LiveProvider::VeniceDeepSeek, input, output)
}

impl LiveBroker {
    async fn venice_completion(&self, body: Value) -> Result<Value, &'static str> {
        let mut response = self
            .client
            .post("https://api.venice.ai/api/v1/chat/completions")
            .bearer_auth(if self.provider == LiveProvider::VeniceDeepSeek {
                self.key.as_str()
            } else {
                self.fallback_key
                    .as_ref()
                    .ok_or("fallback_not_configured")?
                    .as_str()
            })
            .json(&body)
            .send()
            .await
            .map_err(|_| "provider_unavailable")?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            eprintln!("Provider completion rejected: http_status={status}");
            return Err(provider_http_error(status));
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
        check_repetition(&completion)?;
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
        let reservation = token_cost(route.provider(), length as u64 + 4096, 8192)
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
        if route.provider() == self.provider {
            count.primary_attempts += 1;
            let attempts = count.primary_attempts;
            if let Some(receipt) = count.fallback.as_mut() {
                receipt.primary_attempts = attempts;
            }
        } else {
            let primary_attempts = count.primary_attempts;
            let receipt = count
                .fallback
                .get_or_insert_with(|| ProviderFallbackReceipt {
                    model: route.provider().model().into(),
                    reason: reason.unwrap_or("provider_unavailable").into(),
                    primary_attempts,
                    fallback_attempts: 0,
                    fallback_completed: 0,
                });
            receipt.fallback_attempts += 1;
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
            .and_then(|(input, output)| token_cost(route.provider(), input, output));
        let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
        usage::observe(&mut count.inference_usage, route.provider(), completion);
        if let Some(cost) = cost {
            count.reserved = count
                .reserved
                .saturating_sub(reservation)
                .saturating_add(cost);
        }
        if route.provider() != self.provider {
            count
                .fallback
                .as_mut()
                .ok_or("counter_unavailable")?
                .fallback_completed += 1;
        }
        Ok(())
    }

    async fn complete_route<F, R>(
        &self,
        route: Route,
        mut body: Value,
        engine: bool,
        reason: Option<&'static str>,
        send: &mut F,
    ) -> Result<Value, &'static str>
    where
        F: FnMut(Route, Value) -> R,
        R: Future<Output = Result<Value, &'static str>>,
    {
        let mut reserved = self.reserve_route(route, &body, engine, reason.is_none(), reason)?;
        let mut completion = send(route, body.clone()).await;
        if completion.as_ref().err() == Some(&"provider_repetition") {
            // No output or tool call from the rejected generation reached the
            // agent. One fresh generation consumes another call slot and keeps
            // the failed attempt's reservation. All ordinary limits still apply.
            body["messages"].as_array_mut().ok_or("invalid_model_request")?.insert(0, json!({
                "role":"system", "content":"The previous generation was rejected for a repeated-output loop. Continue from the existing observations. Produce one concise next action or the requested final answer. Avoid repeating plans or earlier output. All original scope and permission restrictions still apply."
            }));
            body["reasoning_effort"] = json!("low");
            reserved = self.reserve_route(route, &body, engine, true, None)?;
            eprintln!(
                "model repetition recovery: provider={} fresh_attempt=1",
                route.provider().name()
            );
            completion = send(route, body).await;
        }
        let completion = completion?;
        self.finish_route(route, reserved, &completion)?;
        Ok(completion)
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
        let (already_fell_back, returned_to_primary) = {
            let count = self.counters.lock().map_err(|_| "counter_unavailable")?;
            (count.fallback.is_some(), count.returned_to_primary)
        };
        let primary = Route::from_provider(self.provider)?;
        let secondary = self
            .fallback_provider
            .map(Route::from_provider)
            .transpose()?;
        if returned_to_primary {
            return self
                .complete_route(primary, route_body(primary, body), engine, None, &mut send)
                .await;
        }
        if already_fell_back {
            let secondary = secondary.ok_or("fallback_not_configured")?;
            let result = self
                .complete_route(
                    secondary,
                    route_body(secondary, body.clone()),
                    engine,
                    None,
                    &mut send,
                )
                .await;
            if let Err(reason) = result {
                // A backup that worked for earlier calls may later degrade.
                // Return to the already-consented primary at most once per
                // role, only before any output/tool call reached the agent.
                // Do not ping-pong when both providers fail at first failover.
                let recover = {
                    let mut count = self.counters.lock().map_err(|_| "counter_unavailable")?;
                    if fallback_available_for(reason)
                        && !count.returned_to_primary
                        && count
                            .fallback
                            .as_ref()
                            .is_some_and(|r| r.fallback_completed > 0)
                    {
                        count.returned_to_primary = true;
                        true
                    } else {
                        false
                    }
                };
                if recover {
                    eprintln!(
                        "model recovery return: {} -> {} reason={reason}",
                        secondary.provider().name(),
                        primary.provider().name()
                    );
                    // Count this generation as another call and reserve its
                    // full allowance. Keep the ambiguous failed charge.
                    return self
                        .complete_route(primary, route_body(primary, body), engine, None, &mut send)
                        .await;
                }
            }
            return result;
        }
        let primary_body = route_body(primary, body.clone());
        match self
            .complete_route(primary, primary_body, engine, None, &mut send)
            .await
        {
            Ok(completion) => Ok(completion),
            Err(reason)
                if fallback_available_for(reason)
                    && self.fallback_key.is_some()
                    && secondary.is_some() =>
            {
                // Nothing has reached the agent. Keep the primary's uncertain
                // charge and reserve the backup separately. Later calls prefer it.
                let secondary = secondary.ok_or("fallback_not_configured")?;
                let body = route_body(secondary, body);
                eprintln!(
                    "model recovery: {} -> {} reason={reason}",
                    primary.provider().name(),
                    secondary.provider().name()
                );
                self.complete_route(secondary, body, engine, Some(reason), &mut send)
                    .await
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
        value.fallback_provider = Some(LiveProvider::VeniceDeepSeek);
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
    async fn either_order_preserves_one_call_one_failover_and_costs_of_both_attempts() {
        for primary in [Route::Near, Route::Venice] {
            let secondary = if primary == Route::Near {
                Route::Venice
            } else {
                Route::Near
            };
            for fail_first in [false, true] {
                let mut broker = broker();
                let config = Arc::get_mut(&mut broker).unwrap();
                config.provider = primary.provider();
                config.fallback_provider = Some(secondary.provider());
                let mut body = request();
                body["model"] = json!(primary.provider().model());
                body["messages"] = json!([{"role":"tool", "tool_call_id":"owned", "content":"[]"}]);
                let mut routes = Vec::new();
                for call in 0..2 {
                    broker
                        .route_completion(body.clone(), false, |route, sent| {
                            routes.push(route);
                            assert_eq!(sent["model"], route.provider().model());
                            if route == Route::Near {
                                assert!(sent.get("venice_parameters").is_none());
                                assert!(sent.get("response_format").is_none());
                                assert_eq!(
                                    sent["messages"][0]["content"],
                                    "Tool result (JSON):\n[]"
                                );
                            } else {
                                assert_eq!(sent["store"], false);
                                assert_eq!(sent["fallbacks"], json!([]));
                                assert_eq!(sent["venice_parameters"]["enable_web_search"], "off");
                            }
                            let mut response = reply();
                            response["model"] = json!(route.provider().model());
                            std::future::ready(if fail_first && call == 0 && route == primary {
                                Err("provider_rate_limited")
                            } else {
                                Ok(response)
                            })
                        })
                        .await
                        .unwrap();
                }
                let count = broker.counters.lock().unwrap();
                assert_eq!(count.calls, 2);
                if fail_first {
                    assert_eq!(routes, [primary, secondary, secondary]);
                    let receipt = count.fallback.as_ref().unwrap();
                    assert!(receipt.valid_for(primary.provider().model(), count.calls));
                    assert_eq!(receipt.fallback_completed, 2);
                    let reserved = token_cost(
                        primary.provider(),
                        serde_json::to_vec(&route_body(primary, body))
                            .unwrap()
                            .len() as u64
                            + 4096,
                        8192,
                    )
                    .unwrap();
                    assert_eq!(
                        count.reserved,
                        reserved + 2 * token_cost(secondary.provider(), 1000, 100).unwrap()
                    );
                } else {
                    assert_eq!(routes, [primary, primary]);
                    assert!(count.fallback.is_none());
                    assert_eq!(
                        count.reserved,
                        2 * token_cost(primary.provider(), 1000, 100).unwrap()
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn venice_primary_can_disable_backup_and_near_backup_verification_cannot_be_bypassed() {
        for secondary in [None, Some(LiveProvider::NearDeepSeek)] {
            let mut broker = broker();
            let config = Arc::get_mut(&mut broker).unwrap();
            config.provider = LiveProvider::VeniceDeepSeek;
            config.fallback_provider = secondary;
            if secondary.is_none() {
                config.fallback_key = None;
            }
            let mut routes = Vec::new();
            let error = broker
                .route_completion(request(), false, |route, _| {
                    routes.push(route);
                    std::future::ready(Err(if route == Route::Venice {
                        "provider_unavailable"
                    } else {
                        "near_signature_invalid"
                    }))
                })
                .await
                .unwrap_err();
            let count = broker.counters.lock().unwrap();
            assert_eq!(count.calls, 1);
            assert!(count.reserved > 0);
            if secondary.is_some() {
                assert_eq!(routes, [Route::Venice, Route::Near]);
                assert_eq!(error, "near_signature_invalid");
                assert_eq!(count.fallback.as_ref().unwrap().fallback_completed, 0);
            } else {
                assert_eq!(routes, [Route::Venice]);
                assert_eq!(error, "provider_unavailable");
                assert!(count.fallback.is_none());
            }
        }
    }
    #[tokio::test]
    async fn stalled_primary_is_dropped_before_one_backup_with_no_budget_refund() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let broker = broker();
        let dropped = Arc::new(AtomicBool::new(false));
        let mut routes = Vec::new();
        let result = broker
            .route_completion(request(), true, |route, _| {
                routes.push(route);
                let dropped = dropped.clone();
                async move {
                    if route == Route::Venice {
                        assert!(dropped.load(Ordering::SeqCst));
                        return Ok(reply());
                    }
                    await_model_reply(
                        async move {
                            let _guard = Dropped(dropped);
                            std::future::pending::<Result<Value, &'static str>>().await
                        },
                        Duration::from_millis(1),
                        "near_verification_timeout",
                    )
                    .await
                }
            })
            .await
            .unwrap();
        assert_eq!(result, reply());
        assert_eq!(routes, vec![Route::Near, Route::Venice]);
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 1);
        let reservation = token_cost(
            LiveProvider::NearDeepSeek,
            serde_json::to_vec(&request()).unwrap().len() as u64 + 4096,
            8192,
        )
        .unwrap();
        assert_eq!(
            count.reserved,
            reservation + fallback_cost(1000, 100).unwrap()
        );
        assert_eq!(
            count.fallback.as_ref().unwrap().reason,
            "near_verification_timeout"
        );
    }

    #[tokio::test]
    async fn a_later_backup_failure_returns_to_consented_primary_once() {
        for primary in [Route::Near, Route::Venice] {
            let secondary = if primary == Route::Near {
                Route::Venice
            } else {
                Route::Near
            };
            let mut broker = broker();
            let config = Arc::get_mut(&mut broker).unwrap();
            config.provider = primary.provider();
            config.fallback_provider = Some(secondary.provider());
            broker
                .route_completion(request(), true, |route, _| {
                    std::future::ready(if route == primary {
                        Err("provider_unavailable")
                    } else {
                        Ok(reply())
                    })
                })
                .await
                .unwrap();
            let before = broker.counters.lock().unwrap().reserved;
            let mut routes = Vec::new();
            broker
                .route_completion(request(), true, |route, body| {
                    routes.push(route);
                    assert_eq!(body["model"], route.provider().model());
                    std::future::ready(if route == secondary {
                        Err("near_verification_timeout")
                    } else {
                        Ok(reply())
                    })
                })
                .await
                .unwrap();
            assert_eq!(routes, vec![secondary, primary]);
            {
                let count = broker.counters.lock().unwrap();
                let receipt = count.fallback.as_ref().unwrap();
                assert!(count.returned_to_primary);
                assert_eq!(count.calls, 3); // The return generation consumes its own call slot.
                assert_eq!(receipt.primary_attempts, 2);
                assert_eq!(receipt.fallback_attempts, 2);
                assert_eq!(receipt.fallback_completed, 1);
                assert!(receipt.valid(count.calls));
                assert!(count.reserved > before); // No guessed refund of the failed backup.
            }
            routes.clear();
            let error = broker
                .route_completion(request(), true, |route, _| {
                    routes.push(route);
                    std::future::ready(Err("provider_unavailable"))
                })
                .await
                .unwrap_err();
            assert_eq!(error, "provider_unavailable");
            assert_eq!(routes, vec![primary], "No further provider ping-pong");
        }
    }

    #[tokio::test]
    async fn backup_payment_or_verification_denial_never_returns_to_primary() {
        for reason in [
            "provider_payment_required",
            "provider_authentication_failed",
            "near_signature_invalid",
            "engine_budget_reached",
        ] {
            let broker = broker();
            broker
                .route_completion(request(), true, |route, _| {
                    std::future::ready(if route == Route::Near {
                        Err("provider_unavailable")
                    } else {
                        Ok(reply())
                    })
                })
                .await
                .unwrap();
            let mut routes = Vec::new();
            let error = broker
                .route_completion(request(), true, |route, _| {
                    routes.push(route);
                    std::future::ready(Err(reason))
                })
                .await
                .unwrap_err();
            assert_eq!(error, reason);
            assert_eq!(routes, vec![Route::Venice]);
            assert!(!broker.counters.lock().unwrap().returned_to_primary);
        }
    }

    #[tokio::test]
    async fn return_to_primary_cannot_exceed_the_engine_call_allowance() {
        let broker = broker();
        broker
            .route_completion(request(), true, |route, _| {
                std::future::ready(if route == Route::Near {
                    Err("provider_unavailable")
                } else {
                    Ok(reply())
                })
            })
            .await
            .unwrap();
        broker.counters.lock().unwrap().calls = ENGINE_CALL_LIMIT - 1;
        let mut routes = Vec::new();
        let error = broker
            .route_completion(request(), true, |route, _| {
                routes.push(route);
                std::future::ready(Err("provider_unavailable"))
            })
            .await
            .unwrap_err();
        assert_eq!(error, "engine_budget_reached");
        assert_eq!(routes, vec![Route::Venice]);
        assert_eq!(broker.counters.lock().unwrap().calls, ENGINE_CALL_LIMIT);
    }

    #[tokio::test]
    async fn two_stalled_providers_stop_discovery_without_a_retry_loop() {
        let broker = broker();
        let mut routes = Vec::new();
        let error = broker
            .route_completion(request(), true, |route, _| {
                routes.push(route);
                await_model_reply(
                    std::future::pending::<Result<Value, &'static str>>(),
                    Duration::from_millis(1),
                    if route == Route::Near {
                        "near_verification_timeout"
                    } else {
                        "provider_unavailable"
                    },
                )
            })
            .await
            .unwrap_err();
        assert_eq!(routes, vec![Route::Near, Route::Venice]);
        let request = Request {
            id: 1,
            method: "POST".into(),
            path: ENGINE_CHAT.into(),
            body: None,
        };
        assert!(recoverable_engine_error(&request, error));
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 1);
        assert!(count.reserved > 0);
        assert_eq!(count.fallback.as_ref().unwrap().fallback_completed, 0);
    }
    #[test]
    fn repetition_guard_covers_reasoning_and_preserves_short_or_distinct_output() {
        let looped = "Reconsidering the same finding without any new evidence. ".repeat(400);
        assert!(repetition_dominates(&looped));
        assert!(!repetition_dominates(&"Repeated citation. ".repeat(30)));
        let rows = (0..700)
            .map(|i| format!("Finding row {i}: the same column headings with distinct evidence.\n"))
            .collect::<String>();
        assert!(!repetition_dominates(&rows));
        let paragraph = (0..100)
            .map(|i| format!("Distinct section {i}: {}\n", i * 13))
            .collect::<String>();
        assert!(repetition_dominates(&paragraph.repeat(12)));
        let mut completion = reply();
        completion["choices"][0]["message"]["reasoning_content"] = json!(looped);
        assert_eq!(check_repetition(&completion), Err("provider_repetition"));
        assert!(check_repetition(&reply()).is_ok());
    }
    #[tokio::test]
    async fn a_repetitive_primary_reply_recovers_before_the_agent_sees_it() {
        let broker = broker();
        let mut routes = Vec::new();
        let completion = broker
            .route_completion(request(), false, |route, _| {
                routes.push(route);
                let mut result = reply();
                if route == Route::Near {
                    result["choices"][0]["message"]["content"] = json!(
                        "I should check the same thing again without new evidence. ".repeat(400)
                    );
                }
                std::future::ready(check_repetition(&result).map(|()| result))
            })
            .await
            .unwrap();
        assert_eq!(completion, reply());
        assert_eq!(routes, vec![Route::Near, Route::Near, Route::Venice]);
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 2);
        let receipt = count.fallback.as_ref().unwrap();
        assert_eq!(receipt.reason, "provider_repetition");
        assert!(receipt.valid(2));
    }
    #[tokio::test]
    async fn repetition_has_one_fresh_attempt_per_route_and_preserves_report_capacity() {
        let broker = broker();
        let mut bodies = Vec::new();
        let error = broker
            .route_completion(request(), true, |route, body| {
                bodies.push((route, body));
                std::future::ready(Err("provider_repetition"))
            })
            .await
            .unwrap_err();
        assert_eq!(error, "provider_repetition");
        assert_eq!(
            bodies.iter().map(|(route, _)| *route).collect::<Vec<_>>(),
            vec![Route::Near, Route::Near, Route::Venice, Route::Venice]
        );
        for index in [1, 3] {
            assert_eq!(bodies[index].1["reasoning_effort"], "low");
            assert_eq!(bodies[index].1["messages"].as_array().unwrap().len(), 2);
        }
        let engine_request = Request {
            id: 1,
            method: "POST".into(),
            path: ENGINE_CHAT.into(),
            body: None,
        };
        assert!(recoverable_engine_error(&engine_request, error));
        let retained = broker.counters.lock().unwrap().reserved;
        assert!(retained > 0);
        broker
            .route_completion(request(), false, |route, _| {
                assert_eq!(route, Route::Venice);
                std::future::ready(Ok(reply()))
            })
            .await
            .unwrap();
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 4);
        assert!(count.reserved > retained);
        assert!(count.fallback.as_ref().unwrap().valid(count.calls));
    }

    #[tokio::test]
    async fn a_fresh_generation_can_recover_without_switching_provider() {
        let broker = broker();
        let mut attempts = 0;
        broker
            .route_completion(request(), false, |route, _| {
                assert_eq!(route, Route::Near);
                attempts += 1;
                std::future::ready(if attempts == 1 {
                    Err("provider_repetition")
                } else {
                    Ok(reply())
                })
            })
            .await
            .unwrap();
        assert_eq!(attempts, 2);
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 2);
        assert!(count.fallback.is_none());
        assert!(count.reserved > token_cost(LiveProvider::NearDeepSeek, 1000, 100).unwrap());
    }

    #[tokio::test]
    async fn rate_limited_discovery_preserves_attempts_and_allows_a_later_review() {
        let broker = broker();
        let mut routes = Vec::new();
        let error = broker
            .route_completion(request(), true, |route, _| {
                routes.push(route);
                std::future::ready(Err("provider_rate_limited"))
            })
            .await
            .unwrap_err();
        assert_eq!(routes, vec![Route::Near, Route::Venice]);
        let mut engine_request = Request {
            id: 1,
            method: "POST".into(),
            path: ENGINE_CHAT.into(),
            body: Some(request()),
        };
        assert!(recoverable_engine_error(&engine_request, error));
        engine_request.path = "/v1/chat/completions".into();
        assert!(!recoverable_engine_error(&engine_request, error));
        let failed_reservation = {
            let count = broker.counters.lock().unwrap();
            assert_eq!(count.calls, 1);
            let receipt = count.fallback.as_ref().unwrap();
            assert!(receipt.valid(1));
            assert_eq!(receipt.fallback_completed, 0);
            assert!(count.reserved > 0);
            count.reserved
        };
        // This is the later reviewer, not an automatic replay of discovery.
        broker
            .route_completion(request(), false, |route, _| {
                routes.push(route);
                std::future::ready(Ok(reply()))
            })
            .await
            .unwrap();
        assert_eq!(routes, vec![Route::Near, Route::Venice, Route::Venice]);
        let count = broker.counters.lock().unwrap();
        assert_eq!(count.calls, 2);
        assert_eq!(
            count.reserved,
            failed_reservation + fallback_cost(1000, 100).unwrap()
        );
        assert!(count.fallback.as_ref().unwrap().valid(2));
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
            "provider_payment_required",
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
