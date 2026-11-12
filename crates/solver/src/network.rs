//! Browser request metadata and origin-scoped client hint negotiation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use serde_json::Value;
use url::Url;
use wreq::header::{HeaderMap, HeaderName, HeaderValue, OrigHeaderMap};

/// Captured metadata, with each secure origin's most recent Accept-CH policy.
#[derive(Clone)]
pub(crate) struct ClientHints {
    user_agent: String,
    baseline: Vec<(String, String)>,
    available: BTreeMap<String, String>,
    accepted: BTreeMap<String, BTreeSet<String>>,
}

impl ClientHints {
    pub(crate) fn new(device: Option<&Value>, user_agent: &str) -> Self {
        let ua_data = device.and_then(|value| value.pointer("/navigator/userAgentData"));
        let entropy = ua_data.and_then(|value| value.get("highEntropyValues"));
        let captured = |key: &str| {
            ua_data
                .and_then(|value| value.get(key))
                .or_else(|| entropy.and_then(|value| value.get(key)))
        };
        let chrome_version =
            ua_version(user_agent, "Chrome/").or_else(|| ua_version(user_agent, "Chromium/"));
        // Chrome can expose an empty UAData object while sending no UA hints.
        // An explicit capture takes precedence over inference from the UA string.
        if captured("brands")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            return Self {
                user_agent: user_agent.into(),
                baseline: vec![("accept-language".into(), accept_language(device))],
                available: BTreeMap::new(),
                accepted: BTreeMap::new(),
            };
        }
        let mut baseline = Vec::with_capacity(4);
        if let Some(brands) = captured("brands").and_then(brand_list).or_else(|| {
            let major = chrome_version?.split('.').next()?;
            let mut brands = format!("{};v={}", quoted("Chromium"), quoted(major));
            if user_agent.contains("Chrome/") && !user_agent.contains("Edg/") {
                brands.push_str(&format!(
                    ", {};v={}",
                    quoted("Google Chrome"),
                    quoted(major)
                ));
            }
            Some(brands)
        }) {
            baseline.push(("sec-ch-ua".into(), brands));
        }
        let mobile = captured("mobile")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| user_agent.contains("Mobile"));
        baseline.push(("sec-ch-ua-mobile".into(), boolean(mobile).into()));
        let platform = captured("platform")
            .and_then(Value::as_str)
            .or_else(|| {
                device
                    .and_then(|value| value.get("platform"))
                    .and_then(Value::as_str)
            })
            .or_else(|| {
                device
                    .and_then(|value| value.pointer("/navigator/platform"))
                    .and_then(Value::as_str)
            })
            .map(normalize_platform)
            .unwrap_or_else(|| ua_platform(user_agent));
        baseline.push(("sec-ch-ua-platform".into(), quoted(platform)));
        baseline.push(("accept-language".into(), accept_language(device)));

        let mut available = BTreeMap::new();
        for (key, name) in [
            ("platformVersion", "sec-ch-ua-platform-version"),
            ("architecture", "sec-ch-ua-arch"),
            ("bitness", "sec-ch-ua-bitness"),
            ("model", "sec-ch-ua-model"),
        ] {
            if let Some(value) = captured(key).and_then(Value::as_str) {
                available.insert(name.into(), quoted(value));
            }
        }
        if let Some(value) = captured("wow64").and_then(Value::as_bool) {
            available.insert("sec-ch-ua-wow64".into(), boolean(value).into());
        }
        if let Some(value) = captured("uaFullVersion")
            .and_then(Value::as_str)
            .or(chrome_version)
        {
            available.insert("sec-ch-ua-full-version".into(), quoted(value));
        }
        if let Some(value) = captured("fullVersionList").and_then(brand_list) {
            available.insert("sec-ch-ua-full-version-list".into(), value);
        }
        Self {
            user_agent: user_agent.into(),
            baseline,
            available,
            accepted: BTreeMap::new(),
        }
    }

    /// Only the caller may retry, and only once for a safe GET.
    pub(crate) fn observe(&mut self, response: &wreq::Response) -> bool {
        Url::parse(&response.uri().to_string())
            .map(|url| self.observe_headers(&url, response.headers()))
            .unwrap_or(false)
    }

    pub(crate) fn observe_headers(&mut self, url: &Url, headers: &HeaderMap) -> bool {
        if url.scheme() != "https" || !headers.contains_key("accept-ch") {
            return false;
        }
        let origin = url.origin().ascii_serialization();
        let previous = self.accepted.entry(origin).or_default();
        // Absence preserves the policy; an explicitly empty Accept-CH resets it.
        let next = hint_tokens(headers, "accept-ch");
        let retry = hint_tokens(headers, "critical-ch").iter().any(|name| {
            next.contains(name) && !previous.contains(name) && self.available.contains_key(name)
        });
        *previous = next;
        retry
    }

    pub(crate) fn headers_for(&self, url: &Url) -> Vec<(String, String)> {
        let mut headers = Vec::with_capacity(self.baseline.len() + self.available.len());
        for (name, value) in &self.baseline {
            if url.scheme() == "https" || name == "accept-language" {
                headers.push((name.clone(), value.clone()));
            }
        }
        if url.scheme() == "https"
            && let Some(accepted) = self.accepted.get(&url.origin().ascii_serialization())
        {
            for name in accepted {
                if let Some(value) = self.available.get(name) {
                    headers.push((name.clone(), value.clone()));
                }
            }
        }
        headers
    }
}

pub(crate) struct RequestSpec<'a> {
    pub method: wreq::Method,
    pub url: &'a Url,
    pub headers: &'a BTreeMap<String, String>,
    pub body: Option<&'a str>,
    pub credentials: &'a str,
}

/// Builds a request without navigation defaults or script-controlled forbidden headers.
pub(crate) fn xhr_request(
    client: &wreq::Client,
    page: &Url,
    hints: &ClientHints,
    spec: RequestSpec<'_>,
) -> crate::Result<wreq::Request> {
    let RequestSpec {
        method,
        url,
        headers: request_headers,
        body,
        credentials,
    } = spec;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("unsupported browser request URL scheme: {}", url.scheme()).into());
    }
    let same_origin = url.origin() == page.origin();
    let mut headers = HeaderMap::new();
    for (name, value) in hints.headers_for(url) {
        insert_header(&mut headers, &name, &value)?;
    }
    insert_header(&mut headers, "user-agent", &hints.user_agent)?;
    insert_header(&mut headers, "accept", "*/*")?;
    insert_header(&mut headers, "accept-encoding", "gzip, deflate, br, zstd")?;
    insert_header(&mut headers, "priority", "u=1, i")?;
    insert_header(&mut headers, "sec-fetch-site", fetch_site(page, url))?;
    insert_header(&mut headers, "sec-fetch-mode", "cors")?;
    insert_header(&mut headers, "sec-fetch-dest", "empty")?;
    if method != wreq::Method::GET || !same_origin {
        insert_header(&mut headers, "origin", &page.origin().ascii_serialization())?;
    }
    if let Some(referer) = referrer(page, url) {
        insert_header(&mut headers, "referer", &referer)?;
    }
    let mut script_headers = HeaderMap::new();
    for (name, value) in request_headers {
        let name = HeaderName::from_bytes(name.as_bytes())?;
        if !forbidden_header(name.as_str(), value) {
            script_headers.append(name, HeaderValue::from_str(value)?);
        }
    }
    for name in script_headers.keys() {
        headers.remove(name);
        for value in script_headers.get_all(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    if body.is_some()
        && method != wreq::Method::GET
        && method != wreq::Method::HEAD
        && !headers.contains_key("content-type")
    {
        insert_header(&mut headers, "content-type", "text/plain;charset=UTF-8")?;
    }
    let mut order = OrigHeaderMap::with_capacity(16);
    for name in [
        "content-length",
        "sec-ch-ua-platform",
        "user-agent",
        "sec-ch-ua",
        "content-type",
        "sec-ch-ua-mobile",
        "accept",
        "origin",
        "sec-fetch-site",
        "sec-fetch-mode",
        "sec-fetch-dest",
        "referer",
        "accept-encoding",
        "accept-language",
        "cookie",
        "priority",
    ] {
        order.insert(name);
    }
    // ConfigService merges defaults at execution, not at build(), so removing them
    // from Request::headers_mut() would allow navigation headers to return later.
    let mut request = client
        .request(method, url.as_str())
        .default_headers(false)
        .headers(headers)
        .orig_headers(order)
        // The caller rebuilds each redirect so credentials and metadata are scoped
        // to the new URL rather than blindly retaining the initial request policy.
        .redirect(wreq::redirect::Policy::none());
    if credentials == "omit" || (credentials != "include" && !same_origin) {
        request = request.cookie_provider(no_cookies());
    }
    if let Some(body) = body {
        request = request.body(body.to_owned());
    }
    Ok(request.build()?)
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> crate::Result<()> {
    headers.insert(
        HeaderName::from_bytes(name.as_bytes())?,
        HeaderValue::from_str(value)?,
    );
    Ok(())
}

fn hint_tokens(headers: &HeaderMap, name: &str) -> BTreeSet<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn boolean(value: bool) -> &'static str {
    if value { "?1" } else { "?0" }
}

fn brand_list(value: &Value) -> Option<String> {
    let brands: Vec<_> = value
        .as_array()?
        .iter()
        .filter_map(|brand| {
            Some(format!(
                "{};v={}",
                quoted(brand.get("brand")?.as_str()?),
                quoted(brand.get("version")?.as_str()?)
            ))
        })
        .collect();
    (!brands.is_empty()).then(|| brands.join(", "))
}

fn ua_version<'a>(user_agent: &'a str, product: &str) -> Option<&'a str> {
    let rest = user_agent.split_once(product)?.1;
    let end = rest
        .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
        .unwrap_or(rest.len());
    let version = &rest[..end];
    (!version.is_empty()).then_some(version)
}

fn normalize_platform(platform: &str) -> &str {
    match platform {
        "MacIntel" | "MacPPC" | "macos" | "MacOS" => "macOS",
        "Win32" | "Win64" | "windows" => "Windows",
        "Linux x86_64" | "Linux i686" | "linux" => "Linux",
        other => other,
    }
}

fn ua_platform(user_agent: &str) -> &'static str {
    if user_agent.contains("Android") {
        "Android"
    } else if user_agent.contains("iPhone") || user_agent.contains("iPad") {
        "iOS"
    } else if user_agent.contains("Windows") {
        "Windows"
    } else if user_agent.contains("CrOS") {
        "Chrome OS"
    } else if user_agent.contains("Macintosh") {
        "macOS"
    } else if user_agent.contains("Linux") {
        "Linux"
    } else {
        ""
    }
}

fn accept_language(device: Option<&Value>) -> String {
    let languages: Vec<&str> = device
        .and_then(|value| value.pointer("/navigator/languages"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let primary = device
        .and_then(|value| {
            value
                .get("language")
                .or_else(|| value.pointer("/navigator/language"))
        })
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or("en-US");
    let languages = if languages.is_empty() {
        if primary == "en" {
            vec![primary]
        } else {
            vec![primary, "en"]
        }
    } else {
        languages
    };
    languages
        .iter()
        .enumerate()
        .map(|(index, language)| {
            if index == 0 {
                (*language).to_owned()
            } else {
                format!("{language};q=0.{}", 10usize.saturating_sub(index).max(1))
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn fetch_site(page: &Url, target: &Url) -> &'static str {
    if page.origin() == target.origin() {
        return "same-origin";
    }
    if page.scheme() == target.scheme()
        && let (Some(page_host), Some(target_host)) = (page.host_str(), target.host_str())
    {
        if page_host == target_host {
            return "same-site";
        }
        if page
            .host()
            .is_some_and(|host| matches!(host, url::Host::Domain(_)))
            && target
                .host()
                .is_some_and(|host| matches!(host, url::Host::Domain(_)))
            && let (Some(page_domain), Some(target_domain)) = (
                psl::domain(page_host.as_bytes()),
                psl::domain(target_host.as_bytes()),
            )
            && page_domain.as_bytes() == target_domain.as_bytes()
        {
            return "same-site";
        }
    }
    "cross-site"
}

fn referrer(page: &Url, target: &Url) -> Option<String> {
    if !matches!(page.scheme(), "http" | "https")
        || (page.scheme() == "https" && target.scheme() != "https")
    {
        return None;
    }
    if page.origin() != target.origin() {
        return Some(format!("{}/", page.origin().ascii_serialization()));
    }
    let mut page = page.clone();
    let _ = page.set_username("");
    let _ = page.set_password(None);
    page.set_fragment(None);
    Some(page.into())
}

fn forbidden_header(name: &str, value: &str) -> bool {
    name.starts_with("sec-")
        || name.starts_with("proxy-")
        || matches!(
            name,
            "accept-charset"
                | "accept-encoding"
                | "access-control-request-headers"
                | "access-control-request-method"
                | "connection"
                | "content-length"
                | "cookie"
                | "cookie2"
                | "date"
                | "dnt"
                | "expect"
                | "host"
                | "keep-alive"
                | "origin"
                | "permissions-policy"
                | "referer"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "via"
                | "user-agent"
                | "priority"
        )
        || (matches!(
            name,
            "x-http-method" | "x-http-method-override" | "x-method-override"
        ) && value.split(',').any(|method| {
            let method = method.trim();
            ["CONNECT", "TRACE", "TRACK"]
                .iter()
                .any(|blocked| method.eq_ignore_ascii_case(blocked))
        }))
}

/// Unlike an empty jar, this never accepts Set-Cookie or leaks state between requests.
struct NoCookies;

impl wreq::cookie::CookieStore for NoCookies {
    fn set_cookies(&self, _: &mut dyn Iterator<Item = &HeaderValue>, _: &wreq::Uri) {}

    fn cookies(&self, _: &wreq::Uri, _: wreq::Version) -> wreq::cookie::Cookies {
        wreq::cookie::Cookies::Empty
    }
}

fn no_cookies() -> Arc<NoCookies> {
    static STORE: LazyLock<Arc<NoCookies>> = LazyLock::new(|| Arc::new(NoCookies));
    Arc::clone(&STORE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn explicitly_empty_capture_disables_inferred_and_negotiated_ua_hints() {
        let capture = json!({"navigator":{"userAgentData":{
            "brands":[], "mobile":false, "platform":"",
            "highEntropyValues":{"fullVersionList":[], "platformVersion":""}
        }}});
        let mut hints = ClientHints::new(Some(&capture), "Mozilla/5.0 Chrome/157.0.0.0");
        let origin: Url = "https://example.test/".parse().unwrap();
        let mut response = HeaderMap::new();
        response.insert(
            "accept-ch",
            HeaderValue::from_static(
                "Sec-CH-UA, Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-UA-Full-Version",
            ),
        );
        response.insert("critical-ch", HeaderValue::from_static("Sec-CH-UA"));
        assert!(!hints.observe_headers(&origin, &response));
        assert_eq!(
            hints.headers_for(&origin),
            vec![("accept-language".into(), "en-US,en;q=0.9".into())]
        );
        let fallback = ClientHints::new(None, "Mozilla/5.0 Chrome/157.0.0.0");
        assert!(
            fallback
                .headers_for(&origin)
                .iter()
                .any(|(name, _)| name == "sec-ch-ua")
        );
    }

    #[test]
    fn negotiated_hints_are_origin_scoped_resettable_and_capture_backed() {
        let capture = json!({"navigator":{"userAgentData":{
            "platform":"macOS","mobile":false,"architecture":"arm","bitness":"64",
            "fullVersionList":[{"brand":"Chromium","version":"157.0.8103.39"}]
        }}});
        let mut hints = ClientHints::new(Some(&capture), "Mozilla/5.0 Chrome/157.0.0.0");
        let origin: Url = "https://example.test/".parse().unwrap();
        let other: Url = "https://other.test/".parse().unwrap();
        let mut response = HeaderMap::new();
        response.insert(
            "accept-ch",
            HeaderValue::from_static(
                "Sec-CH-UA-Arch, Sec-CH-UA-Model, Sec-CH-UA-Full-Version-List",
            ),
        );
        response.insert("critical-ch", HeaderValue::from_static("Sec-CH-UA-Arch"));
        assert!(hints.observe_headers(&origin, &response));
        assert!(!hints.observe_headers(&origin, &response));
        let headers: BTreeMap<_, _> = hints.headers_for(&origin).into_iter().collect();
        assert_eq!(
            headers.get("sec-ch-ua-arch").map(String::as_str),
            Some("\"arm\"")
        );
        assert_eq!(
            headers
                .get("sec-ch-ua-full-version-list")
                .map(String::as_str),
            Some("\"Chromium\";v=\"157.0.8103.39\"")
        );
        assert!(
            !headers.contains_key("sec-ch-ua-model"),
            "missing capture data must not be invented"
        );
        assert!(
            !hints
                .headers_for(&other)
                .iter()
                .any(|(name, _)| name == "sec-ch-ua-arch")
        );
        response.insert("accept-ch", HeaderValue::from_static(""));
        hints.observe_headers(&origin, &response);
        assert!(
            !hints
                .headers_for(&origin)
                .iter()
                .any(|(name, _)| name == "sec-ch-ua-arch")
        );
    }

    #[test]
    fn script_cannot_override_transport_owned_headers() {
        let client = wreq::Client::new();
        let page: Url = "https://example.test/page".parse().unwrap();
        let target: Url = "https://example.test/collect".parse().unwrap();
        let hints = ClientHints::new(None, "Mozilla/5.0 Chrome/157.0.0.0");
        let script = BTreeMap::from([
            ("Cookie".into(), "secret=forged".into()),
            ("Host".into(), "attacker.test".into()),
            ("Origin".into(), "https://attacker.test".into()),
            ("Sec-Fetch-Mode".into(), "navigate".into()),
            ("Content-Type".into(), "application/json".into()),
        ]);
        let request = xhr_request(
            &client,
            &page,
            &hints,
            RequestSpec {
                method: wreq::Method::POST,
                url: &target,
                headers: &script,
                body: Some("{}"),
                credentials: "same-origin",
            },
        )
        .unwrap();
        assert!(!request.headers().contains_key("cookie"));
        assert!(!request.headers().contains_key("host"));
        assert_eq!(request.headers()["origin"], "https://example.test");
        assert_eq!(request.headers()["sec-fetch-mode"], "cors");
        assert_eq!(request.headers()["content-type"], "application/json");
    }
}
