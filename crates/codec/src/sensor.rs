//! `sensor_data` framing, keys, checksums, and encode/decode.
//!
//! Ciphertext can contain `;`, so framing is parsed from the front and the
//! remainder is kept whole.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use native_payload::profile::DeviceProfile;
use native_payload::template::{patch_json_str, url_path_segment_from_end};
use serde_json::{Value, json, value::RawValue};

use crate::lcg::{desubstitute, permute_join, substitute, unpermute_join};
use crate::pixel::seed_token;
use crate::script::analyze_script;
use crate::{CodecError, Result};

const DEFAULT_V3_TEMPLATE_JSON: &str = include_str!("v3_default.json");
/// Fallback substitution key when `bm_sz` is absent or malformed.
pub const DEFAULT_SUB_KEY: u32 = 8_888_888;

/// Extract the substitution key from `bm_sz` (`<token>~<blob>~<sub_key>~<int>`),
/// falling back to [`DEFAULT_SUB_KEY`] as the client script does.
pub fn bm_sz_seed(cookie: &str) -> u32 {
    cookie
        .split('~')
        .nth(2)
        .and_then(|field| field.trim().parse().ok())
        .unwrap_or(DEFAULT_SUB_KEY)
}

/// Generation 2 ASCII checksum: sum of char codes below 128, XOR 24.
pub fn checksum_v2(body: &str) -> u32 {
    let sum: u32 = body.bytes().filter(|byte| *byte < 128).map(u32::from).sum();
    sum ^ 24
}

/// Parsed outer envelope: the plain prefix fields plus the ciphertext tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub version: u8,
    pub header: Vec<String>,
    pub ciphertext: String,
}

impl Envelope {
    /// Split `raw` into `header_fields` plain `;`-separated fields (including
    /// the leading version) and keep the rest as `ciphertext`.
    ///
    /// Pass `0` to pick the field count automatically from the version and
    /// field shapes (`7` for v3, `5` or `4` for v2).
    pub fn parse(raw: &str, header_fields: usize) -> Result<Self> {
        let count = if header_fields > 0 {
            header_fields
        } else {
            infer_header_count(raw)?
        };
        let mut fields = Vec::with_capacity(count);
        let mut rest = raw;
        for _ in 0..count {
            let Some((head, tail)) = rest.split_once(';') else {
                return Err(CodecError::Format(format!(
                    "expected {count} header fields"
                )));
            };
            fields.push(head.to_owned());
            rest = tail;
        }
        let version = fields
            .first()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| CodecError::Format("bad version field".to_owned()))?;
        Ok(Self {
            version,
            header: fields,
            ciphertext: rest.to_owned(),
        })
    }

    /// Separator the permutation pass uses for this generation.
    pub fn separator(&self) -> char {
        if self.version >= 3 { ':' } else { ',' }
    }

    /// Generation 2 carries the substitution and shuffle keys in the header.
    pub fn v2_keys(&self) -> Option<(u32, u32)> {
        if self.version != 2 {
            return None;
        }
        match self.header.as_slice() {
            [_, _, sub, shuffle, _] => Some((sub.parse().ok()?, shuffle.parse().ok()?)),
            [_, sub, shuffle, _] => Some((sub.parse().ok()?, shuffle.parse().ok()?)),
            _ => None,
        }
    }
}

fn infer_header_count(raw: &str) -> Result<usize> {
    let parts: Vec<&str> = raw.splitn(9, ';').collect();
    let version: u8 = parts
        .first()
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| CodecError::Format("missing version".to_owned()))?;
    if version >= 3 {
        return Ok(7);
    }
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let timings = |s: &str| s.contains(',') && s.bytes().all(|b| b.is_ascii_digit() || b == b',');
    if parts.len() > 5
        && numeric(parts[1])
        && numeric(parts[2])
        && numeric(parts[3])
        && timings(parts[4])
    {
        Ok(5)
    } else {
        Ok(4)
    }
}

/// Encode `plaintext` into ciphertext: permute on `sep` with `shuffle_key`,
/// then substitute with `sub_key`.
pub fn encode_body(plaintext: &str, sep: char, sub_key: u32, shuffle_key: u32) -> String {
    let shuffled = permute_join(plaintext, sep, shuffle_key);
    substitute(&shuffled, sub_key)
}

/// Decode `ciphertext`: undo substitution with `sub_key`, then undo the
/// permutation on `sep` when `shuffle_key` is known.
pub fn decode_body(ciphertext: &str, sep: char, sub_key: u32, shuffle_key: Option<u32>) -> String {
    let unsub = desubstitute(ciphertext, sub_key);
    match shuffle_key {
        Some(key) => unpermute_join(&unsub, sep, key),
        None => unsub,
    }
}

/// Search `[low, high)` for a v3 shuffle key whose inverse places `{"ver"` at
/// token 0 and produces a substring matching `header_token` (field 5).
pub fn recover_v3_shuffle_key(
    unsubstituted: &str,
    header_token: &str,
    low: u32,
    high: u32,
) -> Option<u32> {
    if low >= high {
        return None;
    }
    let parts: Vec<&str> = unsubstituted.split(':').collect();
    if parts.is_empty() || !parts.contains(&"{\"ver\"") {
        return None;
    }
    let count = parts.len();
    let expected_prefix = if header_token.is_empty() {
        "{\"ver\":\"".to_owned()
    } else {
        format!("{{\"ver\":\"{header_token}\"")
    };
    let total = high - low;
    let threads = if total >= 65_536 {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(16) as u32
    } else {
        1
    };
    let found = AtomicBool::new(false);
    let best = AtomicU32::new(u32::MAX);
    let chunk = total.div_ceil(threads);
    let parts_ref = &parts;
    let prefix_ref = &expected_prefix;
    std::thread::scope(|scope| {
        for worker in 0..threads {
            let start = low.saturating_add(worker.saturating_mul(chunk));
            let end = start.saturating_add(chunk).min(high);
            if start >= end {
                continue;
            }
            let found = &found;
            let best = &best;
            scope.spawn(move || {
                for key in start..end {
                    if (key - start) & 0xfff == 0
                        && found.load(Ordering::Relaxed)
                        && key >= best.load(Ordering::Relaxed)
                    {
                        break;
                    }
                    let mut index_of_zero = 0usize;
                    let mut state = key;
                    for _ in 0..count {
                        let first = (crate::lcg::draw(state) as usize) % count;
                        state = crate::lcg::step(state);
                        let second = (crate::lcg::draw(state) as usize) % count;
                        state = crate::lcg::step(state);
                        if index_of_zero == first {
                            index_of_zero = second;
                        } else if index_of_zero == second {
                            index_of_zero = first;
                        }
                    }
                    if parts_ref[index_of_zero] != "{\"ver\"" {
                        continue;
                    }
                    let candidate = unpermute_join(unsubstituted, ':', key);
                    if candidate.starts_with(prefix_ref)
                        && candidate.ends_with('}')
                        && serde_json::from_str::<Value>(&candidate).is_ok()
                    {
                        found.store(true, Ordering::Relaxed);
                        best.fetch_min(key, Ordering::Relaxed);
                        break;
                    }
                }
            });
        }
    });
    found
        .load(Ordering::Relaxed)
        .then(|| best.load(Ordering::Relaxed))
}

/// One decoded sensor post within a cached build template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostTemplate {
    pub header: Vec<String>,
    pub plaintext: String,
}

/// Reusable per-script-build template for native `sensor_data` encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildTemplate {
    pub script_sha256: String,
    pub version: u8,
    pub shuffle_key: u32,
    pub posts: Vec<PostTemplate>,
}

impl BuildTemplate {
    /// Extract a reusable build template from captured `sensor_data` posts.
    pub fn from_captured_posts(
        script_sha256: String,
        captured_posts: &[String],
        fallback_sub_key: u32,
    ) -> Result<Self> {
        if captured_posts.is_empty() {
            return Err(CodecError::Format("no captured sensor posts".to_owned()));
        }
        let mut parsed = Vec::with_capacity(captured_posts.len());
        for raw in captured_posts {
            let sensor_str = serde_json::from_str::<Value>(raw)
                .ok()
                .and_then(|val| val.get("sensor_data")?.as_str().map(str::to_owned))
                .unwrap_or_else(|| raw.clone());
            parsed.push(Envelope::parse(&sensor_str, 0)?);
        }
        let first = &parsed[0];
        let version = first.version;
        let shuffle_key = if let Some((_, shuf)) = first.v2_keys() {
            shuf
        } else {
            let sub = first
                .header
                .get(4)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(fallback_sub_key);
            let unsub = decode_body(&first.ciphertext, first.separator(), sub, None);
            let token = first.header.get(5).map(String::as_str).unwrap_or_default();
            recover_v3_shuffle_key(&unsub, token, 1 << 16, 1 << 25)
                .ok_or_else(|| CodecError::Key("unable to recover v3 shuffle key".to_owned()))?
        };
        let mut posts = Vec::with_capacity(parsed.len());
        for env in parsed {
            let sub = if let Some((sub, _)) = env.v2_keys() {
                sub
            } else {
                env.header
                    .get(4)
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(fallback_sub_key)
            };
            let plaintext = decode_body(&env.ciphertext, env.separator(), sub, Some(shuffle_key));
            posts.push(PostTemplate {
                header: env.header,
                plaintext,
            });
        }
        Ok(Self {
            script_sha256,
            version,
            shuffle_key,
            posts,
        })
    }

    /// Statically extract `(shuffle_key, ver)` from a served `bmak` script and
    /// bind them to the native 3-post v3 schema and [`DeviceProfile`].
    ///
    /// Returns an error if either build-specific value cannot be extracted;
    /// neither value falls back to the bundled template.
    pub fn from_bmak_script(source: &str, device: Option<&DeviceProfile>) -> Result<Self> {
        let report = analyze_script(source);
        let shuffle_key = report
            .shuffle_key
            .ok_or_else(|| CodecError::Key("unable to extract bmak shuffle_key".to_owned()))?;
        let ver = report
            .version_token
            .ok_or_else(|| CodecError::Format("unable to extract bmak ver".to_owned()))?;
        let default_val: Value = serde_json::from_str(DEFAULT_V3_TEMPLATE_JSON)
            .map_err(|e| CodecError::Format(e.to_string()))?;
        let mut tpl = Self::from_json(&default_val)?;
        tpl.script_sha256 = report.sha256;
        tpl.shuffle_key = shuffle_key;
        let profile = device.cloned().unwrap_or_default();
        let ucs = profile.ua_ascii_sum().to_string();
        let swi = profile.screen.width.to_string();
        let she = profile.screen.height.to_string();
        let asw = profile.screen.avail_width.to_string();
        let ash = profile.screen.avail_height.to_string();
        let wiw = profile.window.inner_width.to_string();
        let wih = profile.window.inner_height.to_string();
        let wow = profile.window.outer_width.to_string();
        let npl = profile.plugins_len.to_string();
        let hc = profile.hardware_concurrency.to_string();
        let dm = (profile.device_memory * 4).to_string();
        let wev = format!("{};wev;{}", profile.webgl.vendor, profile.webgl.vendor);
        let wre = format!("{};wre;{}", profile.webgl.renderer, profile.webgl.renderer);
        let s043 = profile
            .user_agent
            .strip_prefix("Mozilla/")
            .unwrap_or(&profile.user_agent)
            .to_owned();
        for post in &mut tpl.posts {
            if post.header.len() >= 6 {
                post.header[5] = ver.clone();
            }
            post.plaintext =
                patch_json_str(&post.plaintext, "ver", &ver).map_err(CodecError::Format)?;
            post.plaintext = patch_profile_fields(
                &post.plaintext,
                &[
                    ("ua", &profile.user_agent),
                    ("ucs", &ucs),
                    ("nal", &profile.language),
                    ("nap", &profile.product),
                    ("nps", &profile.product_sub),
                    ("wev", &wev),
                    ("wre", &wre),
                    ("s029", &profile.timezone),
                    ("s031", &profile.language),
                    ("s041", &profile.user_agent),
                    ("s043", &s043),
                    ("s045", &profile.platform),
                    ("s057", &profile.os_platform),
                    ("s067", &profile.webgl.vendor),
                    ("s069", &profile.webgl.renderer),
                    ("s071", &profile.webgl.vendor),
                    ("s073", &profile.webgl.renderer),
                ],
                &[
                    ("swi", &swi),
                    ("she", &she),
                    ("asw", &asw),
                    ("ash", &ash),
                    ("wiw", &wiw),
                    ("wih", &wih),
                    ("wow", &wow),
                    ("npl", &npl),
                    ("s035", &dm),
                    ("s037", &hc),
                ],
            )?;
        }
        Ok(tpl)
    }

    /// Encode post `index` natively using the session's live `bm_sz` `sub_key`.
    pub fn encode_post(&self, index: usize, sub_key: u32, page_url: &str) -> Result<String> {
        self.encode_post_for_script(index, sub_key, page_url, "")
    }

    /// Encode post `index` natively, patching both `pur` (`page_url`) and `ffl`
    /// (4th-from-last path segment of `script_url`).
    pub fn encode_post_for_script(
        &self,
        index: usize,
        sub_key: u32,
        page_url: &str,
        script_url: &str,
    ) -> Result<String> {
        let post = self
            .posts
            .get(index)
            .or_else(|| self.posts.last())
            .ok_or_else(|| CodecError::Format("template has no posts".to_owned()))?;
        let mut plaintext =
            patch_json_str(&post.plaintext, "pur", page_url).map_err(CodecError::Format)?;
        if let Some(ffl) = url_path_segment_from_end(script_url, 4) {
            plaintext = patch_json_str(&plaintext, "ffl", ffl).map_err(CodecError::Format)?;
        }
        let sep = if self.version >= 3 { ':' } else { ',' };
        let ciphertext = encode_body(&plaintext, sep, sub_key, self.shuffle_key);
        let mut header = post.header.clone();
        if self.version >= 3 {
            if let Some(slot) = header.get_mut(4) {
                *slot = sub_key.to_string();
            }
        } else if header.len() >= 4 {
            let sub_idx = header.len() - 3;
            header[sub_idx] = sub_key.to_string();
        }
        let sensor_data = format!("{};{ciphertext}", header.join(";"));
        Ok(json!({ "sensor_data": sensor_data }).to_string())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "script_sha256": self.script_sha256,
            "version": self.version,
            "shuffle_key": self.shuffle_key,
            "posts": self.posts.iter().map(|post| json!({
                "header": post.header,
                "plaintext": post.plaintext,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(value: &Value) -> Result<Self> {
        let script_sha256 = value
            .get("script_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| CodecError::Format("missing script_sha256".to_owned()))?
            .to_owned();
        let version = value
            .get("version")
            .and_then(Value::as_u64)
            .and_then(|v| u8::try_from(v).ok())
            .ok_or_else(|| CodecError::Format("missing version".to_owned()))?;
        let shuffle_key = value
            .get("shuffle_key")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| CodecError::Format("missing shuffle_key".to_owned()))?;
        let posts_arr = value
            .get("posts")
            .and_then(Value::as_array)
            .ok_or_else(|| CodecError::Format("missing posts array".to_owned()))?;
        let mut posts = Vec::with_capacity(posts_arr.len());
        for item in posts_arr {
            let header = item
                .get("header")
                .and_then(Value::as_array)
                .ok_or_else(|| CodecError::Format("missing post header".to_owned()))?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| CodecError::Format("non-string header field".to_owned()))
                })
                .collect::<Result<Vec<_>>>()?;
            let plaintext = item
                .get("plaintext")
                .and_then(Value::as_str)
                .ok_or_else(|| CodecError::Format("missing post plaintext".to_owned()))?
                .to_owned();
            posts.push(PostTemplate { header, plaintext });
        }
        if posts.is_empty() {
            return Err(CodecError::Format("empty posts array".to_owned()));
        }
        Ok(Self {
            script_sha256,
            version,
            shuffle_key,
            posts,
        })
    }
}

// Profile fields in the bundled schema live in din/dsi/sww as well as the root.
// native-payload's fallible JSON helpers intentionally patch top-level fields
// only. Borrow raw value spans to preserve every byte outside the replaced
// tokens, including key order and number formatting, without changing the
// workspace's serde_json serialization behavior.
fn patch_profile_fields(
    plaintext: &str,
    strings: &[(&str, &str)],
    raw: &[(&str, &str)],
) -> Result<String> {
    let mut fields: Vec<(&str, Value)> = strings
        .iter()
        .map(|&(key, value)| (key, Value::String(value.to_owned())))
        .collect();
    for &(key, value) in raw {
        fields.push((
            key,
            serde_json::from_str(value).map_err(|e| CodecError::Format(e.to_string()))?,
        ));
    }
    fn collect(
        plaintext: &str,
        node: &RawValue,
        fields: &[(&str, Value)],
        edits: &mut Vec<(usize, usize, String)>,
    ) -> Result<()> {
        match node.get().as_bytes()[0] {
            b'{' => {
                let object: std::collections::BTreeMap<String, &RawValue> =
                    serde_json::from_str(node.get())
                        .map_err(|e| CodecError::Format(e.to_string()))?;
                for (key, value) in object {
                    if let Some((_, replacement)) = fields.iter().find(|(name, _)| *name == key) {
                        let current: Value = serde_json::from_str(value.get())
                            .map_err(|e| CodecError::Format(e.to_string()))?;
                        if current.is_string() != replacement.is_string()
                            || current.is_number() != replacement.is_number()
                        {
                            return Err(CodecError::Format(format!(
                                "unexpected profile field type: {key}"
                            )));
                        }
                        // Deserializing &RawValue borrows a slice of plaintext.
                        let start = value.get().as_ptr() as usize - plaintext.as_ptr() as usize;
                        edits.push((
                            start,
                            start + value.get().len(),
                            serde_json::to_string(replacement)
                                .map_err(|e| CodecError::Format(e.to_string()))?,
                        ));
                    } else {
                        collect(plaintext, value, fields, edits)?;
                    }
                }
            }
            b'[' => {
                let array: Vec<&RawValue> = serde_json::from_str(node.get())
                    .map_err(|e| CodecError::Format(e.to_string()))?;
                for value in array {
                    collect(plaintext, value, fields, edits)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let value: &RawValue =
        serde_json::from_str(plaintext).map_err(|e| CodecError::Format(e.to_string()))?;
    let mut edits = Vec::new();
    collect(plaintext, value, &fields, &mut edits)?;
    edits.sort_unstable_by_key(|(start, _, _)| *start);
    let mut out = String::with_capacity(plaintext.len());
    let mut cursor = 0;
    for (start, end, replacement) in edits {
        out.push_str(&plaintext[cursor..start]);
        out.push_str(&replacement);
        cursor = end;
    }
    out.push_str(&plaintext[cursor..]);
    Ok(out)
}

/// Construct a native SBSD `{"body":"..."}` JSON payload from [`DeviceProfile`]
/// and the session's `bm_so` / `sbsd_o` cookie seed.
pub fn encode_sbsd_payload(
    page_url: &str,
    index: usize,
    cookie_seed: &str,
    device: Option<&DeviceProfile>,
) -> String {
    let profile = device.cloned().unwrap_or_default();
    let seed = native_payload::cipher::ascii_sum(cookie_seed)
        .wrapping_add(8_185)
        .wrapping_add(index as u32);
    let inner = json!({
        "ver": "s/vyEBEQSXrb0uoTcnPYyQ==",
        "signals": {
            "od001": "80",
            "od032": profile.screen.height.to_string(),
            "od072": (profile.hardware_concurrency * 2).to_string(),
            "od414": page_url,
            "od839": profile.screen.width.to_string(),
            "od908": "audioinput,videoinput,audiooutput",
        },
        "perf": 551 + (index * 122),
        "s": if index == 0 { "f" } else { "i" },
        "tid": "mwdo6nr3f6cg33044we",
    })
    .to_string();
    let body = substitute(&inner, seed);
    json!({ "body": body }).to_string()
}

/// Construct a native form-encoded `/akam/13/pixel_<hash>` beacon payload.
pub fn encode_pixel_payload(seed: u64, page_url: &str, device: Option<&DeviceProfile>) -> String {
    let profile = device.cloned().unwrap_or_default();
    let token = seed_token(&seed.to_string());
    let summary = format!(
        "{}|{}x{}|{}|{}",
        profile.user_agent, profile.screen.width, profile.screen.height, profile.platform, page_url
    );
    let encoded = substitute(&summary, (seed as u32) ^ 77);
    format!("u={encoded}&t={token}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm_sz_falls_back_to_default() {
        assert_eq!(bm_sz_seed(""), DEFAULT_SUB_KEY);
        assert_eq!(bm_sz_seed("tok~blob~3228984~4276793"), 3_228_984);
    }

    #[test]
    fn v2_both_header_shapes_parse() {
        let posted = Envelope::parse("2;2048;3360065;3683384;26,0,0,1,1,0;cipher;with;semi", 0)
            .expect("posted");
        assert_eq!(posted.header.len(), 5);
        assert_eq!(posted.ciphertext, "cipher;with;semi");
        assert_eq!(posted.v2_keys(), Some((3_360_065, 3_683_384)));

        let inline = Envelope::parse("2;3228209;4601909;9,0,0,1,3,1;cipher", 0).expect("inline");
        assert_eq!(inline.header.len(), 4);
        assert_eq!(inline.v2_keys(), Some((3_228_209, 4_601_909)));
    }

    #[test]
    fn body_round_trips_and_recovers_v3_key() {
        let plain = r#"{"ver":"tok123","fpt":"1","fpc":"2","sde":"0","hls":"0","pde":"0","pur":"https","din":[{"ua":"Mozilla"},{"npl":5}],"mst":[{"kc":0},{"mc":1},{"tc":0}]}"#;
        let cipher = encode_body(plain, ':', 4_000_000, 70_010);
        let unsub = decode_body(&cipher, ':', 4_000_000, None);
        let key = recover_v3_shuffle_key(&unsub, "tok123", 70_000, 70_050).expect("key");
        assert_eq!(key, 70_010);
        assert_eq!(decode_body(&cipher, ':', 4_000_000, Some(key)), plain);
    }

    #[test]
    fn v2_checksum_matches_formula() {
        assert_eq!(checksum_v2("ABC"), (65 + 66 + 67) ^ 24);
    }

    #[test]
    fn bundled_profile_template_keeps_serialization_and_nested_fields() {
        let template: Value = serde_json::from_str(DEFAULT_V3_TEMPLATE_JSON).unwrap();
        let template = BuildTemplate::from_json(&template).unwrap();
        for post in template.posts {
            assert_eq!(
                patch_profile_fields(&post.plaintext, &[], &[]).unwrap(),
                post.plaintext
            );
        }
        let plain = r#"{"ver":"tok","din":[{"ua":"old"},{"she":100}],"dsi":[{"wev":"old"}],"sww":{"s029":"old","s035":4},"keep":"\"ua\":\"old\""}"#;
        let patched = patch_profile_fields(
            plain,
            &[("ua", "new"), ("wev", "vendor"), ("s029", "")],
            &[("she", "200"), ("s035", "8")],
        )
        .unwrap();
        assert_eq!(
            patched,
            r#"{"ver":"tok","din":[{"ua":"new"},{"she":200}],"dsi":[{"wev":"vendor"}],"sww":{"s029":"","s035":8},"keep":"\"ua\":\"old\""}"#
        );
        assert!(patch_profile_fields(plain, &[("she", "string")], &[]).is_err());
        let formatted = r#" { "n":1.2300, "before":"é🙂", "din":[{"\u0075a":"old"}] } "#;
        assert_eq!(
            patch_profile_fields(formatted, &[("ua", "新")], &[]).unwrap(),
            r#" { "n":1.2300, "before":"é🙂", "din":[{"\u0075a":"新"}] } "#
        );
    }

    #[test]
    fn captured_template_patching_preserves_formatting_and_propagates_errors() {
        let plain = " { \"ver\":\"tok\", \"pur\" :\"old\", \"ffl\":\"old\", \"n\":1.2300 } ";
        let mut template = BuildTemplate {
            script_sha256: "synthetic".to_owned(),
            version: 3,
            shuffle_key: 65_914,
            posts: vec![PostTemplate {
                header: vec!["3", "0", "1", "0", "0", "tok", "0,0,0,0,0,0"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                plaintext: plain.to_owned(),
            }],
        };
        let encoded = template
            .encode_post_for_script(0, 4_538_946, "", "https://e.test/a/b/c/d/e.js")
            .unwrap();
        let body: Value = serde_json::from_str(&encoded).unwrap();
        let envelope = Envelope::parse(body["sensor_data"].as_str().unwrap(), 0).unwrap();
        assert_eq!(
            decode_body(&envelope.ciphertext, ':', 4_538_946, Some(65_914)),
            " { \"ver\":\"tok\", \"pur\" :\"\", \"ffl\":\"b\", \"n\":1.2300 } "
        );
        for invalid in [
            r#"{"nested":{"pur":"old"}}"#,
            r#"{"pur":1}"#,
            r#"{"pur":"a","pur":"b"}"#,
        ] {
            template.posts[0].plaintext = invalid.to_owned();
            assert!(matches!(
                template.encode_post(0, 1, "new"),
                Err(CodecError::Format(_))
            ));
        }
    }

    #[test]
    fn bmak_template_requires_both_build_values() {
        let shuffle = "s8=fA(G9,[['CAr3qAAAAAA','C','r5','b3Mrf','C5rCrbM5r3qAAAAAA','C595bbf','9f99bAMqAAAAAA','f5','b33f3qAAAAAA','9999999','bC3f9rI','IA5C','5AC9','fbAA','CArb','9Ir5','Ibf9C','f5Mb9','IfIAM5','5','I3','I5AA','IAAA'],0]);";
        // 'b' XOR '#' gives the 20-byte 'A' key; 'q' XOR 'A' is '0'.
        let ver = format!("{}=", "0".repeat(43));
        let table = format!(
            "return [\"{}|\",\"{}\",\"{}\",\"{}\"];",
            "q".repeat(43),
            "b".repeat(20),
            "#".repeat(21),
            "x".repeat(450),
        );
        for source in ["", "const bmak = {};", table.as_str()] {
            assert!(matches!(
                BuildTemplate::from_bmak_script(source, None),
                Err(CodecError::Key(message)) if message.contains("shuffle_key")
            ));
        }
        assert!(matches!(
            BuildTemplate::from_bmak_script(shuffle, None),
            Err(CodecError::Format(message)) if message.contains("ver")
        ));

        let tpl = BuildTemplate::from_bmak_script(&format!("{shuffle}{table}"), None)
            .expect("both build values extracted");
        assert_eq!(tpl.shuffle_key, 6_453_891);
        for index in 0..tpl.posts.len() {
            let payload = tpl
                .encode_post(index, 5_555_555, "https://example.com/")
                .unwrap();
            let outer: Value = serde_json::from_str(&payload).unwrap();
            let env = Envelope::parse(outer["sensor_data"].as_str().unwrap(), 0).unwrap();
            assert_eq!(env.header[5], ver);
            let decoded = decode_body(&env.ciphertext, ':', 5_555_555, Some(6_453_891));
            let plaintext: Value = serde_json::from_str(&decoded).unwrap();
            assert_eq!(plaintext["ver"], ver);
        }
    }

    #[test]
    fn build_template_recovers_and_reencodes_for_new_session_seed() {
        let plain = r#"{"ver":"tok123","fpt":"1","fpc":"2","sde":"0","hls":"0","pde":"0","pur":"https://old.example/","din":[{"ua":"Mozilla"},{"npl":5}],"mst":[{"kc":0},{"mc":1},{"tc":0}]}"#;
        let cipher = encode_body(plain, ':', 4_000_000, 65_914);
        let posted = json!({
            "sensor_data": format!("3;0;1;0;4000000;tok123;0,0,0,0,0,4;{cipher}")
        })
        .to_string();
        let tpl = BuildTemplate::from_captured_posts("sha".to_owned(), &[posted], 4_000_000)
            .expect("template");
        assert_eq!(tpl.shuffle_key, 65_914);

        let reencoded = tpl
            .encode_post(0, 5_555_555, "https://new.example/path")
            .expect("encode");
        let outer: Value = serde_json::from_str(&reencoded).unwrap();
        let env = Envelope::parse(outer["sensor_data"].as_str().unwrap(), 0).unwrap();
        assert_eq!(env.header[4], "5555555");
        let decoded = decode_body(&env.ciphertext, ':', 5_555_555, Some(tpl.shuffle_key));
        assert!(decoded.contains("\"pur\":\"https://new.example/path\""));

        let roundtrip = BuildTemplate::from_json(&tpl.to_json()).expect("from_json");
        assert_eq!(roundtrip, tpl);
    }
}
