//! Offline JavaScript build fingerprinting and browser-API coverage analysis.
//!
//! This module inspects source text only. It does not execute scripts, make
//! network requests, or construct challenge payloads.

use std::collections::BTreeMap;
use std::fmt::Write as _;

mod literals;

use literals::string_arrays;
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

/// Extract the per-build shuffle seed from either supported numeric-table layout.
/// The mathematical anchors validate the layout and the digit substitution;
/// the seed itself is always decoded from the served table.
pub fn extract_bmak_shuffle_key(source: &str) -> Option<u32> {
    const LEGACY: &[(usize, &[u8])] = &[
        (4, b"4294967295.000000"),
        (6, b"8388607.000000"),
        (8, b"65535.000000"),
        (9, b"8888888"),
    ];
    const CURRENT: &[(usize, &[u8])] = &[
        (0, b"4095.000000"),
        (5, b"65535.000000"),
        (6, b"65793"),
        (7, b"4282663"),
        (8, b"8388607.000000"),
        (9, b"4294967295.000000"),
        (10, b"3"),
    ];
    let arrays: Vec<_> = string_arrays(source).collect();
    let mut matched = None;
    for arr in &arrays {
        for (anchors, key_index) in [(LEGACY, 10), (CURRENT, 11)] {
            let Some(map) = anchors.iter().try_fold([255; 256], |map, &(index, plain)| {
                extend_digit_map(map, arr.get(index)?.as_bytes(), plain)
            }) else {
                continue;
            };
            let strings: Vec<_> = arr.iter().map(String::as_bytes).collect();
            let map = complete_digit_map(map, &strings)?;
            let key = arr.get(key_index)?;
            if key.is_empty() || !key.bytes().all(|ch| map[ch as usize].is_ascii_digit()) {
                return None;
            }
            let value = decode_integer(key.as_bytes(), &map)?;
            if matched.is_some_and(|previous| previous != value) {
                return None;
            }
            matched = Some(value);
        }
    }
    if let Some(value) = recover_reordered_seed(&arrays).ok()? {
        if matched.is_some_and(|previous| previous != value) {
            return None;
        }
        matched = Some(value);
    }
    matched
}

// Rotated builds can move constants between tables. Validate the digit map
// with both large mathematical anchors, then require a complete LCG table
// containing exactly one non-standard seed in the codec's recovery range.
// Ambiguous tables are unsupported rather than selecting an arbitrary value.
fn recover_reordered_seed(arrays: &[Vec<String>]) -> Result<Option<u32>, ()> {
    let strings: Vec<&[u8]> = arrays.iter().flatten().map(String::as_bytes).collect();
    let mut matched = None;
    for &maximum in strings.iter().filter(|s| s.len() == 17) {
        let Some(base) = extend_digit_map([255; 256], maximum, b"4294967295.000000") else {
            continue;
        };
        for &mask in strings.iter().filter(|s| s.len() == 14) {
            let Some(map) = extend_digit_map(base, mask, b"8388607.000000") else {
                continue;
            };
            if !arrays.iter().any(|array| {
                [65_793, 4_282_663, 8_388_607].iter().all(|&value| {
                    array
                        .iter()
                        .any(|s| decode_integer(s.as_bytes(), &map) == Some(value))
                })
            }) {
                continue;
            }
            let map = complete_digit_map(map, &strings).ok_or(())?;
            for array in arrays {
                let values: Vec<_> = array
                    .iter()
                    .filter_map(|s| decode_integer(s.as_bytes(), &map))
                    .collect();
                // The build seed can live in the separate initializer table.
                // Exclude ordinary string tables before collecting candidates.
                if array.len() < 12 || values.len() * 2 <= array.len() {
                    continue;
                }
                for value in values.into_iter().filter(|value| {
                    (65_536..(1 << 25)).contains(value) && !fixed_numeric_constant(*value)
                }) {
                    if matched.is_some_and(|previous| previous != value) {
                        return Err(());
                    }
                    matched = Some(value);
                }
            }
        }
    }
    Ok(matched)
}

fn complete_digit_map(mut map: [u8; 256], strings: &[&[u8]]) -> Option<[u8; 256]> {
    if !map.contains(&b'1') {
        let mut one = None;
        for value in strings {
            if value.len() == 4
                && value[1..].iter().all(|&ch| map[ch as usize] == b'0')
                && map[value[0] as usize] == 255
            {
                if one.is_some_and(|previous| previous != value[0]) {
                    return None;
                }
                one = Some(value[0]);
            }
        }
        map[one? as usize] = b'1';
    }
    Some(map)
}

fn extend_digit_map(mut map: [u8; 256], encoded: &[u8], plain: &[u8]) -> Option<[u8; 256]> {
    if encoded.len() != plain.len() {
        return None;
    }
    for (&ch, &value) in encoded.iter().zip(plain) {
        if (map[ch as usize] != 255 && map[ch as usize] != value)
            || (map[ch as usize] == 255 && map.contains(&value))
        {
            return None;
        }
        map[ch as usize] = value;
    }
    Some(map)
}

fn decode_integer(encoded: &[u8], map: &[u8; 256]) -> Option<u32> {
    let mut value = 0u32;
    let mut fractional = false;
    let mut integer_digits = 0;
    let mut fractional_digits = 0;
    if encoded.is_empty() {
        return None;
    }
    for &ch in encoded {
        match map[ch as usize] {
            b'.' if !fractional && integer_digits > 0 => fractional = true,
            b'0' if fractional => fractional_digits += 1,
            digit @ b'0'..=b'9' if !fractional => {
                integer_digits += 1;
                value = value
                    .checked_mul(10)?
                    .checked_add(u32::from(digit - b'0'))?
            }
            _ => return None,
        }
    }
    (integer_digits > 0 && (!fractional || fractional_digits > 0)).then_some(value)
}

fn fixed_numeric_constant(value: u32) -> bool {
    if [65_793, 4_282_663, 8_888_888, 3_600_000, 21_600_000].contains(&value)
        || value.is_power_of_two()
        || (value + 1).is_power_of_two()
        || (value - 1).is_power_of_two()
    {
        return true;
    }
    (5..=8).any(|exponent| value.abs_diff(10u32.pow(exponent)) <= 1)
}

/// Recover the version token from the served XOR tables. Supported key periods
/// are 8..=64 bytes, with a short printable master (or the legacy 20-byte key's
/// longer master). Derived keys can contain control bytes; master offsets wrap.
pub fn extract_bmak_ver(source: &str) -> Option<String> {
    let mut matched: Option<String> = None;
    for arr in string_arrays(source) {
        let strings: Vec<Vec<u8>> = arr
            .iter()
            .filter_map(|s| {
                s.chars()
                    .map(|ch| u8::try_from(u32::from(ch)).ok())
                    .collect()
            })
            .collect();
        for qat in strings.iter().filter(|s| s.len() == 44) {
            for seed in strings.iter().filter(|s| (8..=64).contains(&s.len())) {
                let key_len = seed.len();
                for master in &strings {
                    if std::ptr::eq(master, seed)
                        || !((key_len == 20 && master.len() >= 20)
                            || ((8..=64).contains(&master.len())
                                && master.iter().all(|ch| (32..=127).contains(ch))))
                    {
                        continue;
                    }
                    for offset in 0..master.len() {
                        let mut key = [0u8; 64];
                        for i in 0..key_len {
                            key[i] = seed[i] ^ master[(offset + i) % master.len()];
                        }
                        for shift in 0..key_len {
                            if key[(43 + shift) % key_len] != (qat[43] ^ b'=') {
                                continue;
                            }
                            let mut out = [0u8; 44];
                            out[43] = b'=';
                            let valid = (0..43).all(|i| {
                                out[i] = qat[i] ^ key[(i + shift) % key_len];
                                out[i].is_ascii_alphanumeric() || matches!(out[i], b'+' | b'/')
                            });
                            if !valid {
                                continue;
                            }
                            // A 32-byte Base64 token has two zero pad bits.
                            if !b"AEIMQUYcgkosw048".contains(&out[42]) {
                                continue;
                            }
                            let token = String::from_utf8(out.to_vec()).ok()?;
                            if matched.as_ref().is_some_and(|previous| previous != &token) {
                                return None;
                            }
                            matched = Some(token);
                        }
                    }
                }
            }
        }
    }
    matched
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

#[cfg(test)]
mod bmak_tests;
