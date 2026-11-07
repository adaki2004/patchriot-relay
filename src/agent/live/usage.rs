//! Retain provider observations without changing conservative spend admission.
use super::*;

pub(super) fn observe(records: &mut Vec<InferenceUsage>, provider: LiveProvider, reply: &Value) {
    let index = records
        .iter()
        .position(|r| r.model == provider.model())
        .unwrap_or_else(|| {
            records.push(InferenceUsage {
                provider: provider.name().into(),
                model: provider.model().into(),
                ..Default::default()
            });
            records.len() - 1
        });
    let row = &mut records[index];
    row.responses += 1;
    let usage = &reply["usage"];
    if let Some((input, output)) = usage["prompt_tokens"]
        .as_u64()
        .zip(usage["completion_tokens"].as_u64())
        .filter(|(p, c)| *p <= 10_000_000 && *c <= 1_000_000)
    {
        row.token_usage_responses += 1;
        row.prompt_tokens += input;
        row.completion_tokens += output;
        if let Some(cached) = usage["prompt_tokens_details"]["cached_tokens"]
            .as_u64()
            .or_else(|| usage["prompt_cache_hit_tokens"].as_u64())
            .filter(|c| *c <= input)
        {
            row.cache_usage_responses += 1;
            row.cached_prompt_tokens += cached;
        }
    }
    // Venice documents separate USD and DIEM charges. Absent fields are unknown.
    if matches!(
        provider,
        LiveProvider::Venice | LiveProvider::VeniceDeepSeek
    ) {
        for (field, total, responses) in [
            (
                "usd",
                &mut row.provider_reported_usd,
                &mut row.usd_cost_responses,
            ),
            (
                "diem",
                &mut row.provider_reported_diem,
                &mut row.diem_cost_responses,
            ),
        ] {
            if let Some(value) = reply["cost"][field]
                .as_f64()
                .filter(|v| v.is_finite() && (0.0..=1000.0).contains(v))
            {
                *total += value;
                *responses += 1;
            }
        }
    }
}

pub(super) fn observe_bytes(
    records: &mut Vec<InferenceUsage>,
    provider: LiveProvider,
    bytes: &[u8],
    stream: bool,
) {
    let reply = if stream {
        // Usage and cost can arrive on separate trailing chunks. Each is a
        // cumulative per-request total: retain the last, never sum the chunks.
        let mut summary = json!({});
        for value in bytes
            .split(|b| *b == b'\n')
            .filter_map(|line| line.strip_prefix(b"data:"))
            .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        {
            for field in ["usage", "cost"] {
                if value[field].is_object() {
                    summary[field] = value[field].clone();
                }
            }
        }
        summary
    } else {
        serde_json::from_slice(bytes).unwrap_or(Value::Null)
    };
    observe(records, provider, &reply);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_cost_cache_and_missing_data_stay_distinct() {
        let mut rows = vec![];
        let reply = json!({"usage":{"prompt_tokens":1000,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":900}},"cost":{"usd":0.00004,"diem":0.00002}});
        observe(&mut rows, LiveProvider::VeniceDeepSeek, &reply);
        observe(&mut rows, LiveProvider::VeniceDeepSeek, &json!({}));
        let row = &rows[0];
        assert_eq!(
            (
                row.responses,
                row.token_usage_responses,
                row.usd_cost_responses
            ),
            (2, 1, 1)
        );
        assert_eq!(row.cached_prompt_tokens, 900);
        assert_eq!(row.provider_reported_usd, 0.00004);
        assert_eq!(row.provider_reported_diem, 0.00002);
        assert!(row.valid(2));
        assert_eq!(
            token_cost(LiveProvider::VeniceDeepSeek, 1000, 20),
            Some(357)
        );
    }
    #[test]
    fn streaming_totals_are_observed_once_even_if_repeated() {
        let mut rows = vec![];
        let bytes = b"data: {\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":5}}\n\ndata: {\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":5},\"cost\":{\"usd\":0.001}}\n\ndata: [DONE]\n";
        observe_bytes(&mut rows, LiveProvider::VeniceDeepSeek, bytes, true);
        assert_eq!(rows[0].responses, 1);
        assert_eq!(rows[0].prompt_tokens, 100);
        assert_eq!(rows[0].cache_usage_responses, 0);
        assert_eq!(rows[0].provider_reported_usd, 0.001);
    }
}
