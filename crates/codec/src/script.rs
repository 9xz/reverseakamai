//! Offline JavaScript build fingerprinting and browser-API coverage analysis.
//!
//! This module inspects source text only. It does not execute scripts, make
//! network requests, or construct challenge payloads.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use native_payload::template::parse_js_string_array;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
/// Coarse, heuristic script family for build inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptFamily {
    Bmak,
    Sbsd,
    Unknown,
}

impl ScriptFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bmak => "bmak",
            Self::Sbsd => "sbsd",
            Self::Unknown => "unknown",
        }
    }
}

/// Stable build identity plus static source markers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptReport {
    pub sha256: String,
    pub bytes: usize,
    pub lines: usize,
    pub family: ScriptFamily,
    pub string_literals: usize,
    pub max_string_literal_bytes: usize,
    pub catch_splice_markers: usize,
    pub browser_apis: BTreeMap<&'static str, bool>,
    pub shuffle_key: Option<u32>,
    pub version_token: Option<String>,
}

/// Analyze JavaScript source without evaluating it.
pub fn analyze_script(source: &str) -> ScriptReport {
    let digest = Sha256::digest(source.as_bytes());
    let mut sha256 = String::with_capacity(64);
    for byte in digest {
        write!(sha256, "{byte:02x}").expect("writing to a string cannot fail");
    }

    let family = if source.contains("bmak") || source.contains("sensor_data") {
        ScriptFamily::Bmak
    } else if source.contains("onconnect")
        || source.contains("SharedWorker")
        || source.contains("getHighEntropyValues")
    {
        ScriptFamily::Sbsd
    } else {
        ScriptFamily::Unknown
    };

    let features: &[(&str, &[&str])] = &[
        ("automation_checks", &["webdriver"]),
        ("blob_object_urls", &["createObjectURL"]),
        ("canvas_2d", &["measureText", "getImageData"]),
        ("dedicated_worker", &["new Worker"]),
        ("extension_probes", &["chrome-extension://"]),
        ("high_entropy_hints", &["getHighEntropyValues"]),
        ("media_devices", &["enumerateDevices"]),
        ("offscreen_canvas", &["OffscreenCanvas"]),
        ("offline_audio", &["OfflineAudioContext"]),
        ("permissions", &["permissions.query"]),
        ("self_integrity", &["Function.prototype.toString"]),
        ("service_worker", &["serviceWorker"]),
        ("shared_worker", &["SharedWorker", "onconnect"]),
        ("speech_synthesis", &["speechSynthesis"]),
        ("web_crypto", &["crypto.subtle"]),
        ("webgl", &["webgl"]),
        ("webrtc", &["RTCPeerConnection"]),
    ];
    let browser_apis = features
        .iter()
        .map(|(name, markers)| (*name, markers.iter().any(|marker| source.contains(marker))))
        .collect();
    let (string_literals, max_string_literal_bytes) = string_metrics(source);

    ScriptReport {
        sha256,
        bytes: source.len(),
        lines: if source.is_empty() {
            0
        } else {
            source.bytes().filter(|byte| *byte == b'\n').count() + 1
        },
        family,
        string_literals,
        max_string_literal_bytes,
        catch_splice_markers: count_catch_splice_markers(source),
        browser_apis,
        shuffle_key: extract_bmak_shuffle_key(source),
        version_token: extract_bmak_ver(source),
    }
}

/// JSON representation suitable for build inventories and cache keys.
pub fn report_json(report: &ScriptReport) -> Value {
    json!({
        "sha256": report.sha256,
        "bytes": report.bytes,
        "lines": report.lines,
        "family": report.family.as_str(),
        "metrics": {
            "string_literals": report.string_literals,
            "max_string_literal_bytes": report.max_string_literal_bytes,
            "catch_splice_markers": report.catch_splice_markers,
        },
        "shuffle_key": report.shuffle_key,
        "version_token": report.version_token,
        "browser_apis": report.browser_apis,
    })
}

fn count_catch_splice_markers(source: &str) -> usize {
    let mut count = 0;
    let mut rest = source;
    while let Some(index) = rest.find("catch") {
        rest = &rest[index + 5..];
        let end = rest.find('}').unwrap_or(rest.len());
        if rest[..end].contains(".splice(") {
            count += 1;
        }
        rest = &rest[end..];
    }
    count
}

/// Statically extract the `bmak` v3 `shuffle_key` (`s8[10]`) from the digit-ciphered
/// `s8` constant array (`4294967295.000000`, `8388607.000000`, `8888888`).
pub fn extract_bmak_shuffle_key(source: &str) -> Option<u32> {
    let mut cursor = 0;
    while let Some(rel) = source[cursor..].find("[['") {
        let start = cursor + rel + 1;
        cursor = start + 2;
        let slice = &source[start..source.len().min(start + 2048)];
        let arr = parse_js_string_array(slice);
        if arr.len() < 23 {
            continue;
        }
        let s4 = arr[4].as_bytes();
        let s6 = arr[6].as_bytes();
        let s9 = arr[9].as_bytes();
        if s4.len() != 17 || s6.len() != 14 || s9.len() != 7 || !s9.iter().all(|&b| b == s9[0]) {
            continue;
        }
        let zero_ch = s4[11];
        if !s4[11..17].iter().all(|&b| b == zero_ch) {
            continue;
        }
        let mut map = [255u8; 256];
        map[zero_ch as usize] = 0;
        map[s4[1] as usize] = 2;
        map[s6[1] as usize] = 3;
        map[s4[0] as usize] = 4;
        map[s4[9] as usize] = 5;
        map[s4[5] as usize] = 6;
        map[s4[6] as usize] = 7;
        map[s6[0] as usize] = 8;
        map[s4[2] as usize] = 9;
        for item in &arr {
            let b = item.as_bytes();
            if b.len() == 4
                && b[1] == zero_ch
                && b[2] == zero_ch
                && b[3] == zero_ch
                && map[b[0] as usize] == 255
            {
                map[b[0] as usize] = 1;
                break;
            }
        }
        let mut value = 0u32;
        for &ch in arr[10].as_bytes() {
            let digit = map[ch as usize];
            if digit > 9 {
                return None;
            }
            value = value.checked_mul(10)?.checked_add(u32::from(digit))?;
        }
        return Some(value);
    }
    None
}

/// Statically extract the 44-character Base64 `ver` constant from a `bmak` v3 script's
/// XOR-encoded string table arrays.
pub fn extract_bmak_ver(source: &str) -> Option<String> {
    for marker in ["return [\"", "W2=[\""] {
        let mut cursor = 0;
        while let Some(rel) = source[cursor..].find(marker) {
            let bracket = cursor + rel + marker.len() - 2;
            cursor = bracket + 2;
            let Some(end_rel) = source[bracket..].find("];") else {
                continue;
            };
            if !(500..=250_000).contains(&end_rel) {
                continue;
            }
            let arr = parse_js_string_array(&source[bracket..=bracket + end_rel]);
            let len44: Vec<&str> = arr
                .iter()
                .map(String::as_str)
                .filter(|s| s.len() == 44)
                .collect();
            let len20: Vec<&str> = arr
                .iter()
                .map(String::as_str)
                .filter(|s| s.len() == 20)
                .collect();
            if len44.is_empty() || len20.is_empty() {
                continue;
            }
            for &qat in &len44 {
                let qbytes: Vec<u8> = qat.chars().map(|c| c as u8).collect();
                if qbytes.len() != 44 {
                    continue;
                }
                for &s20 in &len20 {
                    let s20_bytes: Vec<u8> = s20.chars().map(|c| c as u8).collect();
                    if s20_bytes.len() != 20 {
                        continue;
                    }
                    for master in &arr {
                        let mbytes: Vec<u8> = master.chars().map(|c| c as u8).collect();
                        if mbytes.len() < 20 || std::ptr::eq(master.as_str(), s20) {
                            continue;
                        }
                        for d9w in 0..=mbytes.len() - 20 {
                            let mut z5t = [0u8; 20];
                            let mut ascii_ok = true;
                            for k in 0..20 {
                                let b = s20_bytes[k] ^ mbytes[d9w + k];
                                if !(32..=126).contains(&b) {
                                    ascii_ok = false;
                                    break;
                                }
                                z5t[k] = b;
                            }
                            if !ascii_ok {
                                continue;
                            }
                            let needed_last = qbytes[43] ^ b'=';
                            for shift in 0..20 {
                                if z5t[(43 + shift) % 20] != needed_last {
                                    continue;
                                }
                                let mut out = [0u8; 44];
                                out[43] = b'=';
                                let mut valid = true;
                                for i in 0..43 {
                                    let ch = qbytes[i] ^ z5t[(i + shift) % 20];
                                    if !(ch.is_ascii_alphanumeric() || ch == b'+' || ch == b'/') {
                                        valid = false;
                                        break;
                                    }
                                    out[i] = ch;
                                }
                                if valid {
                                    return String::from_utf8(out.to_vec()).ok();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Count quoted/template literals while ignoring comments. Lengths are source
/// bytes, including escape sequences, not decoded UTF-8 string lengths.
fn string_metrics(source: &str) -> (usize, usize) {
    #[derive(Clone, Copy)]
    enum State {
        Code,
        Quoted(u8),
        LineComment,
        BlockComment,
    }

    let bytes = source.as_bytes();
    let mut state = State::Code;
    let mut start = 0;
    let mut count = 0;
    let mut longest = 0;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::Code => match (byte, next) {
                (b'/', Some(b'/')) => {
                    state = State::LineComment;
                    index += 1;
                }
                (b'/', Some(b'*')) => {
                    state = State::BlockComment;
                    index += 1;
                }
                (quote @ (b'\'' | b'"' | b'`'), _) => {
                    state = State::Quoted(quote);
                    start = index + 1;
                }
                _ => {}
            },
            State::Quoted(quote) => {
                if byte == b'\\' {
                    index += 1;
                } else if byte == quote {
                    count += 1;
                    longest = longest.max(index - start);
                    state = State::Code;
                }
            }
            State::LineComment => {
                if byte == b'\n' {
                    state = State::Code;
                }
            }
            State::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    state = State::Code;
                    index += 1;
                }
            }
        }
        index += 1;
    }
    (count, longest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_source_and_reports_browser_api_coverage() {
        let source = r#"
            // "comment is not a literal"
            const worker = new SharedWorker(URL.createObjectURL(new Blob(["abc"])));
            const canvas = new OffscreenCanvas(1, 1).getContext("webgl");
            navigator.userAgentData.getHighEntropyValues(["brands"]);
            try { work(); } catch (error) { XC.splice(0, 1); }
        "#;
        let report = analyze_script(source);
        assert_eq!(report.family, ScriptFamily::Sbsd);
        assert_eq!(report.string_literals, 3);
        assert_eq!(report.max_string_literal_bytes, 6);
        assert_eq!(report.catch_splice_markers, 1);
        assert!(report.browser_apis["shared_worker"]);
        assert!(report.browser_apis["blob_object_urls"]);
        assert!(report.browser_apis["offscreen_canvas"]);
        assert!(report.browser_apis["high_entropy_hints"]);
        assert!(!report.browser_apis["dedicated_worker"]);
        assert_eq!(report_json(&report)["metrics"]["catch_splice_markers"], 1);
    }

    #[test]
    fn computes_standard_sha256_and_handles_empty_input() {
        let report = analyze_script("abc");
        assert_eq!(
            report.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(report.bytes, 3);
        assert_eq!(report.lines, 1);
        assert_eq!(report.family, ScriptFamily::Unknown);

        let empty = analyze_script("");
        assert_eq!(empty.lines, 0);
        assert_eq!(empty.string_literals, 0);
    }

    #[test]
    fn recognizes_bmak_and_ignores_commented_markers_for_literal_metrics() {
        let report = analyze_script(
            "const bmak = {}; /* `hidden` */ const body = \"{\\\"sensor_data\\\":1}\";",
        );
        assert_eq!(report.family, ScriptFamily::Bmak);
        assert_eq!(report.string_literals, 1);
        assert_eq!(report.max_string_literal_bytes, 19);
    }

    #[test]
    fn extracts_shuffle_key_from_s8_digit_cipher_array() {
        let snippet = "s8=fA(G9,[['CAr3qAAAAAA','C','r5','b3Mrf','C5rCrbM5r3qAAAAAA','C595bbf','9f99bAMqAAAAAA','f5','b33f3qAAAAAA','9999999','bC3f9rI','IA5C','5AC9','fbAA','CArb','9Ir5','Ibf9C','f5Mb9','IfIAM5','5','I3','I5AA','IAAA'],0]);";
        assert_eq!(extract_bmak_shuffle_key(snippet), Some(6_453_891));
    }
}
