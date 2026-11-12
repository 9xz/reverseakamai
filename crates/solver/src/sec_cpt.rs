//! `sec-cpt` (`428 Precondition Required` / `bm-verify`) challenge handling.

use std::time::Duration;

use serde_json::json;

use akamai_codec::pow::solve_sec_cpt;

use crate::Result;

/// A parsed escalation challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecCptChallenge {
    pub provider: String,
    pub token: String,
    pub nonce: String,
    pub difficulty: u32,
    pub timestamp: u64,
    pub chlg_duration: u64,
    pub verify_url: String,
}

impl SecCptChallenge {
    /// Detect a `428` / `sec-cpt-if` / `sec-cp-challenge` payload.
    pub fn detect(status: u16, html: &str) -> Option<Self> {
        if status != 428 && !html.contains("sec-cpt-if") && !html.contains("sec-cp-challenge") {
            return None;
        }
        if let Some(start) = html.find('{')
            && let Some(end) = html.rfind('}')
            && end > start
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&html[start..=end])
            && value.get("sec-cp-challenge").is_some()
        {
            return Some(Self::from_json(&value));
        }

        let provider = attr(html, "provider").unwrap_or_else(|| "crypto".to_owned());
        let encoded = attr(html, "challenge")?;
        let decoded = b64_decode(&encoded)?;
        let value: serde_json::Value = serde_json::from_str(&decoded).ok()?;
        let mut challenge = Self::from_json(&value);
        challenge.provider = provider;
        if let Some(duration) = attr(html, "data-duration").and_then(|v| v.parse().ok()) {
            challenge.chlg_duration = duration;
        }
        if let Some(src) = attr(html, "src") {
            challenge.verify_url = src;
        }
        Some(challenge)
    }

    fn from_json(value: &serde_json::Value) -> Self {
        let string = |key: &str| {
            value
                .get(key)
                .and_then(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .or_else(|| v.as_i64().map(|n| n.to_string()))
                })
                .unwrap_or_default()
        };
        let number = |key: &str| {
            value
                .get(key)
                .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
                .unwrap_or(0)
        };
        Self {
            provider: string("provider"),
            token: string("token"),
            nonce: string("nonce"),
            difficulty: number("difficulty") as u32,
            timestamp: number("timestamp"),
            chlg_duration: number("chlg_duration"),
            verify_url: "/_sec/cp_challenge/verify".to_owned(),
        }
    }
}

fn attr(html: &str, name: &str) -> Option<String> {
    ['"', '\''].into_iter().find_map(|quote| {
        let needle = format!("{name}={quote}");
        let start = html.find(&needle)? + needle.len();
        let end = html[start..].find(quote)? + start;
        Some(html[start..end].to_owned())
    })
}

fn b64_decode(input: &str) -> Option<String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::new();
    for byte in input.bytes().filter(|b| !b"=\r\n\t ".contains(b)) {
        let value = TABLE.iter().position(|c| *c == byte)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    String::from_utf8(out).ok()
}

/// Solve the crypto part of a challenge and verify it with the edge.
pub async fn solve_and_verify(
    client: &wreq::Client,
    page: &url::Url,
    challenge: &SecCptChallenge,
    user_agent: &str,
    headers: &[(String, String)],
) -> Result<u16> {
    let answers = if challenge.difficulty > 0 {
        solve_sec_cpt(
            challenge.timestamp,
            &challenge.nonce,
            challenge.difficulty,
            10,
            10_000_000,
        )
        .map_err(|e| e.to_string())?
    } else {
        Vec::new()
    };

    if challenge.chlg_duration > 0 {
        tokio::time::sleep(Duration::from_secs(challenge.chlg_duration.min(60))).await;
    }

    let verify = page.join(&challenge.verify_url)?;
    let body = json!({
        "provider": challenge.provider,
        "token": challenge.token,
        "nonce": challenge.nonce,
        "timestamp": challenge.timestamp,
        "difficulty": challenge.difficulty,
        "answers": answers,
    })
    .to_string();

    let response = crate::request(client, wreq::Method::POST, verify.as_str(), headers)
        .header(wreq::header::USER_AGENT, user_agent)
        .header(wreq::header::CONTENT_TYPE, "application/json")
        .header(wreq::header::REFERER, page.as_str())
        .body(body)
        .send()
        .await?;
    Ok(response.status().as_u16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_challenge() {
        let html = r#"{"sec-cp-challenge": "true", "provider": "crypto", "chlg_duration": 0, "token": "AAQ", "timestamp": 1713283747, "nonce": "ebccdb479fcb92636fbc", "difficulty": 4}"#;
        let challenge = SecCptChallenge::detect(428, html).expect("challenge");
        assert_eq!(challenge.provider, "crypto");
        assert_eq!(challenge.difficulty, 4);
        assert_eq!(challenge.nonce, "ebccdb479fcb92636fbc");
        assert_eq!(challenge.timestamp, 1_713_283_747);
    }

    #[test]
    fn ignores_plain_pages() {
        assert!(SecCptChallenge::detect(200, "<html>ok</html>").is_none());
    }
}
