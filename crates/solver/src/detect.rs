//! Mechanism detection from a page: sensor scripts, the pixel beacon, and
//! `sec-cpt` escalation challenges.

use url::Url;

use crate::sec_cpt::SecCptChallenge;

/// Everything the edge asked the client to do on this page.
#[derive(Debug, Default)]
pub struct Capabilities {
    pub sensors: Vec<String>,
    pub sbsd: Vec<String>,
    pub pixel: Option<Pixel>,
    pub sec_cpt: Option<SecCptChallenge>,
}

/// The `/akam/13/<hash>` pixel beacon wiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pixel {
    pub seed: u64,
    pub script_url: String,
    pub post_url: String,
}

/// Inspect `html` and report which mechanisms must run, in execution order.
pub fn detect(html: &str, status: u16, page: &Url) -> Capabilities {
    let (sbsd, candidates): (Vec<_>, Vec<_>) = candidate_scripts(html, page)
        .into_iter()
        .partition(|url| is_sbsd_script(url));
    let sensors = candidates
        .into_iter()
        .filter(|url| is_sensor_script(url))
        .collect();
    let mut caps = Capabilities {
        sensors,
        sbsd,
        pixel: pixel_tag(html, page),
        sec_cpt: SecCptChallenge::detect(status, html),
    };
    if caps.sec_cpt.is_some() {
        caps.sensors.clear();
        caps.sbsd.clear();
        caps.pixel = None;
    }
    caps
}

/// Same-origin external script URLs. Mechanism-specific filters run afterward.
fn candidate_scripts(html: &str, page: &Url) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(index) = rest.find("src=") {
        rest = &rest[index + 4..];
        let trimmed = rest.trim_start();
        let (quote, body) = match trimmed.chars().next() {
            Some(q @ ('"' | '\'')) => (q, &trimmed[1..]),
            _ => continue,
        };
        let Some(end) = body.find(quote) else {
            continue;
        };
        let src = &body[..end];
        if !(src.starts_with('/') || src.starts_with("http")) || src.contains("/akam/") {
            continue;
        }
        let src = src.replace("&amp;", "&");
        let Ok(absolute) = page.join(&src) else {
            continue;
        };
        if absolute.host_str() != page.host_str() {
            continue;
        }
        let value = absolute.to_string();
        if !found.contains(&value) {
            found.push(value);
        }
    }
    found
}

/// Sensor scripts: extension-less, 4+ segments, not `/akam/`.
fn is_sensor_script(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
    let last = segments.last().copied().unwrap_or_default();
    segments.len() >= 4 && !last.contains('.')
}

/// SBSD carries a UUID-shaped visitor id in `v`; `t` marks an active challenge.
fn is_sbsd_script(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    url.query_pairs()
        .find(|(name, _)| name == "v")
        .is_some_and(|(_, value)| {
            let mut lengths = value.split('-').map(str::len);
            lengths.by_ref().eq([8, 4, 4, 4, 12])
                && value
                    .chars()
                    .all(|character| character.is_ascii_hexdigit() || character == '-')
        })
}

fn pixel_tag(html: &str, page: &Url) -> Option<Pixel> {
    let marker = "bazadebezolkohpepadr";
    let idx = html.find(marker)?;
    let digits: String = html[idx..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        return None;
    }
    let seed: u64 = digits.parse().ok()?;
    let hash = format!("{:x}", 77 ^ seed);
    let script_url = page.join(&format!("/akam/13/{hash}")).ok()?;
    let post_url = page.join(&format!("/akam/13/pixel_{hash}")).ok()?;
    Some(Pixel {
        seed,
        script_url: script_url.to_string(),
        post_url: post_url.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_pixel_and_sensor() {
        let page = Url::parse("https://example.com/login").unwrap();
        let html = r#"<script type="text/javascript">bazadebezolkohpepadr="1320943881"</script>
            <script type="text/javascript" src="/akam/13/4ebc0144"></script>
            <script type="text/javascript" src="/yznG/A9tj/QHQnC/cRQWQ/1ciuJzJQLQQkwJN3/Fg8HLDlFNw/LXYlJA/AMO2c"></script>"#;
        let caps = detect(html, 200, &page);
        let pixel = caps.pixel.expect("pixel");
        assert_eq!(pixel.seed, 1_320_943_881);
        assert_eq!(pixel.script_url, "https://example.com/akam/13/4ebc0144");
        assert_eq!(pixel.post_url, "https://example.com/akam/13/pixel_4ebc0144");
        assert_eq!(caps.sensors.len(), 1);
        assert!(caps.sec_cpt.is_none());
    }

    #[test]
    fn ignores_vendor_and_extension_scripts() {
        let page = Url::parse("https://example.com/").unwrap();
        let html = r#"<script src="/etc.clientlibs/app.min.abc.js"></script>
            <script src="https://rum.hlx.page/.rum/micro.js"></script>"#;
        assert!(detect(html, 200, &page).sensors.is_empty());
    }

    #[test]
    fn separates_sbsd_state_scripts_from_bm_sensors() {
        let page = Url::parse("https://example.com/catalog").unwrap();
        let html = r#"<script src="/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj?v=f96b0144-83cf-fd90-7200-553b2f046010"></script>
            <script src="/yznG/A9tj/QHQnC/cRQWQ/1ciuJzJQLQQkwJN3/Fg8HLDlFNw/LXYlJA/AMO2c"></script>"#;
        let caps = detect(html, 200, &page);
        assert_eq!(
            caps.sbsd,
            vec![
                "https://example.com/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj?v=f96b0144-83cf-fd90-7200-553b2f046010"
            ]
        );
        assert_eq!(caps.sensors.len(), 1);
    }

    #[test]
    fn detects_active_sbsd_and_ignores_non_uuid_cache_busters() {
        let page = Url::parse("https://example.com/catalog").unwrap();
        let html = r#"<script src="/.well-known/sbsd?v=99b02ce6-f91f-0f49-40ae-6f8493e30214&amp;t=183446612"></script>
            <script src="/assets/vendor?v=123456"></script>"#;
        let caps = detect(html, 200, &page);
        assert_eq!(
            caps.sbsd,
            vec![
                "https://example.com/.well-known/sbsd?v=99b02ce6-f91f-0f49-40ae-6f8493e30214&t=183446612"
            ]
        );
        assert!(caps.sensors.is_empty());
    }
}
