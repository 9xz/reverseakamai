//! High-level plug-and-play SDK for driving Akamai Bot Manager sessions and
//! reusing the validated transport/cookie/client-hint session across requests.
//!
//! ```no_run
//! use akamai_solver::{AkamaiClient, Profile};
//!
//! # async fn example() -> akamai_solver::Result<()> {
//! let mut client = AkamaiClient::builder()
//!     .profile(Profile::Chrome154)
//!     .posts(3)
//!     .build()?;
//!
//! let outcome = client.solve("https://www.bestbuy.com/").await?;
//! assert!(outcome.abck_advanced());
//!
//! let search = client
//!     .get("https://www.bestbuy.com/site/searchpage.jsp?st=iphone")
//!     .await?;
//! println!("search status: {}, {} bytes", search.status, search.body.len());
//! # Ok(())
//! # }
//! ```

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use url::Url;
use wreq_util::Profile;

use crate::{
    DEFAULT_UA, Mechanism, Result, SolveOptions, SolveOutcome, detect, device_profile_for,
    driver::get_response,
    env::load_device,
    network::{ClientHints, RequestSpec, xhr_request},
    sec_cpt,
};

pub(crate) fn cookie_snapshot(
    jar: &wreq::cookie::Jar,
    page: &url::Url,
) -> BTreeMap<String, String> {
    let mut snapshot = BTreeMap::new();
    for cookie in jar.matches(page.as_str()) {
        snapshot
            .entry(cookie.name().to_owned())
            .or_insert_with(|| cookie.value().to_owned());
    }
    snapshot
}

/// Response returned by [`AkamaiClient::get`], [`AkamaiClient::post`],
/// [`AkamaiClient::post_json`], or [`AkamaiClient::request`].
#[derive(Debug, Clone)]
pub struct SessionResponse {
    pub url: String,
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl SessionResponse {
    /// Decode the response body as UTF-8 (lossy for non-UTF-8 bytes).
    pub fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Parse the response body as JSON.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_slice(&self.body)?)
    }
}

/// Builder for configuring a reusable [`AkamaiClient`].
pub struct AkamaiClientBuilder {
    profile: Profile,
    user_agent: Option<String>,
    device: Option<serde_json::Value>,
    posts: usize,

    cookies: Option<Arc<wreq::cookie::Jar>>,
}

impl Default for AkamaiClientBuilder {
    fn default() -> Self {
        Self {
            profile: Profile::Chrome154,
            user_agent: None,
            device: None,
            posts: 3,

            cookies: None,
        }
    }
}

impl AkamaiClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the TLS / HTTP/2 browser profile (default: `Profile::Chrome154`).
    pub fn profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    /// Override the `User-Agent` header and `navigator.userAgent`.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Replay a captured browser environment JSON (`tools/capture-env.js`).
    pub fn device(mut self, device: serde_json::Value) -> Self {
        self.device = Some(device);
        self
    }

    /// Load and replay a captured browser environment JSON file.
    pub fn device_from_file(mut self, path: impl AsRef<Path>) -> Result<Self> {
        let path_str = path
            .as_ref()
            .to_str()
            .ok_or("device path must be valid UTF-8")?;
        self.device = Some(load_device(path_str)?);
        Ok(self)
    }

    /// Maximum telemetry posts per `solve()` call (default: `3`).
    pub fn posts(mut self, posts: usize) -> Self {
        self.posts = posts.max(1);
        self
    }

    /// Share an existing cookie jar with the client.
    pub fn cookie_jar(mut self, jar: Arc<wreq::cookie::Jar>) -> Self {
        self.cookies = Some(jar);
        self
    }

    /// Construct the [`AkamaiClient`].
    pub fn build(self) -> Result<AkamaiClient> {
        let user_agent = self
            .user_agent
            .clone()
            .or_else(|| self.device.as_ref()?.get("ua")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| DEFAULT_UA.to_owned());
        let cookies = self.cookies.unwrap_or_default();
        let mut opts = SolveOptions::new("https://example.com/");
        opts.profile = self.profile;
        opts.user_agent = Some(user_agent.clone());
        opts.device = self.device.clone();
        opts.posts = self.posts;

        let client = crate::client(&opts, &user_agent, cookies.clone())?;
        let hints = ClientHints::new(self.device.as_ref(), &user_agent);
        Ok(AkamaiClient {
            client,
            cookies,
            hints,
            user_agent,
            profile: self.profile,
            device: self.device,
            posts: self.posts,

            last_page: None,
            templates: BTreeMap::new(),
        })
    }
}

/// Stateful Akamai Bot Manager client holding a persistent TLS/H2 connection
/// pool, scoped RFC 6265 cookie jar, and negotiated `Accept-CH` client hints.
pub struct AkamaiClient {
    pub(crate) client: wreq::Client,
    pub(crate) cookies: Arc<wreq::cookie::Jar>,
    pub(crate) hints: ClientHints,
    pub(crate) user_agent: String,
    pub(crate) profile: Profile,
    pub(crate) device: Option<serde_json::Value>,
    pub(crate) posts: usize,

    pub(crate) last_page: Option<Url>,
    pub(crate) templates: BTreeMap<String, akamai_codec::sensor::BuildTemplate>,
}

impl AkamaiClient {
    /// Create a new [`AkamaiClientBuilder`].
    pub fn builder() -> AkamaiClientBuilder {
        AkamaiClientBuilder::default()
    }

    /// Create a default [`AkamaiClient`] (`Chrome154`, 3 posts, fast pacing).
    pub fn new() -> Result<Self> {
        Self::builder().build()
    }

    /// Construct an [`AkamaiClient`] matching a [`SolveOptions`] configuration.
    pub fn from_options(options: &SolveOptions) -> Result<Self> {
        let mut builder = Self::builder()
            .profile(options.profile)
            .posts(options.posts);
        if let Some(ua) = &options.user_agent {
            builder = builder.user_agent(ua.clone());
        }
        if let Some(device) = &options.device {
            builder = builder.device(device.clone());
        }
        builder.build()
    }

    /// Solve the Akamai challenge on `url` using this client's configured defaults.
    pub async fn solve(&mut self, url: impl Into<String>) -> Result<SolveOutcome> {
        let mut options = SolveOptions::new(url);
        options.profile = self.profile;
        options.user_agent = Some(self.user_agent.clone());
        options.device = self.device.clone();
        options.posts = self.posts;
        self.solve_with(options).await
    }

    /// Solve the Akamai challenge using explicit [`SolveOptions`], updating this
    /// client's cookie jar, client hints, and active referer page.
    pub async fn solve_with(&mut self, options: SolveOptions) -> Result<SolveOutcome> {
        let requested: Url = options.url.parse()?;
        let mut log = Vec::new();
        let mut mechanisms = Vec::new();
        let response = get_response(
            &self.client,
            &mut self.hints,
            requested,
            self.last_page.as_ref(),
        )
        .await?;
        let page_status = response.status().as_u16();
        let page: Url = response.uri().to_string().parse()?;
        let mut html = response.text().await?;
        log.push(format!("GET {page} -> {page_status}, {} bytes", html.len()));

        let mut caps = detect::detect(&html, page_status, &page);
        if let Some(challenge) = caps.sec_cpt.take() {
            let status = sec_cpt::solve_and_verify(
                &self.client,
                &page,
                &challenge,
                &self.user_agent,
                &self.hints.headers_for(&page),
            )
            .await?;
            mechanisms.push(Mechanism {
                kind: "sec-cpt",
                url: challenge.verify_url.clone(),
                payload_len: 0,
                status: Some(status),
            });
            log.push(format!("sec-cpt verify -> {status}"));
            let response = get_response(&self.client, &mut self.hints, page.clone(), None).await?;
            let status = response.status().as_u16();
            html = response.text().await?;
            caps = detect::detect(&html, status, &page);
        }

        let profile = device_profile_for(&self.user_agent, &options);
        if let Some(pixel) = caps.pixel.take() {
            let response = get_response(
                &self.client,
                &mut self.hints,
                pixel.script_url.parse()?,
                Some(&page),
            )
            .await?;
            let status = response.status();
            let source = response.text().await?;
            if !status.is_success()
                || source.trim_start().starts_with("Not Found")
                || source.trim_start().starts_with('<')
            {
                log.push("pixel: endpoint returned no JavaScript; skipping".to_owned());
            } else {
                let body = akamai_codec::sensor::encode_pixel_payload(
                    pixel.seed,
                    page.as_str(),
                    Some(&profile),
                );
                let mut pixel_status = None;
                if options.post {
                    let target: Url = pixel.post_url.parse()?;
                    let headers = BTreeMap::from([(
                        "content-type".to_owned(),
                        "application/x-www-form-urlencoded".to_owned(),
                    )]);
                    let built = xhr_request(
                        &self.client,
                        &page,
                        &self.hints,
                        RequestSpec {
                            method: wreq::Method::POST,
                            url: &target,
                            headers: &headers,
                            body: Some(&body),
                            credentials: "same-origin",
                        },
                    )?;
                    let resp = self.client.execute(built).await?;
                    pixel_status = Some(resp.status().as_u16());
                    self.hints.observe(&resp);
                    let _ = resp.bytes().await?;
                }
                mechanisms.push(Mechanism {
                    kind: "pixel",
                    url: pixel.post_url,
                    payload_len: body.len(),
                    status: pixel_status,
                });
            }
        }

        let mut sbsd_posted = 0;
        let mut sbsd_status = None;
        let mut sbsd_payload = None;
        for candidate in &caps.sbsd {
            let candidate_url: url::Url = candidate.parse()?;
            let active = candidate_url
                .query_pairs()
                .any(|(name, value)| name == "t" && !value.is_empty());
            if !active && (!caps.sensors.is_empty() || options.template.is_some()) {
                continue;
            }
            let response = get_response(
                &self.client,
                &mut self.hints,
                candidate_url.clone(),
                Some(&page),
            )
            .await?;
            let status = response.status();
            let source = response.text().await?;
            log.push(format!(
                "GET {candidate} -> {status}, {} bytes",
                source.len()
            ));
            if !status.is_success()
                || source.trim_start().starts_with("Not Found")
                || source.trim_start().starts_with('<')
            {
                continue;
            }
            let post_target = {
                let mut u = candidate_url.clone();
                if let Some(t_val) = candidate_url
                    .query_pairs()
                    .find(|(k, _)| k == "t")
                    .map(|(_, v)| v.into_owned())
                {
                    u.set_query(Some(&format!("t={t_val}")));
                } else {
                    u.set_query(None);
                }
                u
            };
            let count = if active { 1 } else { 2 };
            let headers =
                BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]);
            for idx in 0..count {
                let snap = cookie_snapshot(&self.cookies, &page);
                let cookie_seed = snap
                    .get("sbsd_o")
                    .or_else(|| snap.get("bm_so"))
                    .or_else(|| snap.get("bm_o"))
                    .map(String::as_str)
                    .unwrap_or_default();
                let body = akamai_codec::sensor::encode_sbsd_payload(
                    page.as_str(),
                    idx,
                    cookie_seed,
                    Some(&profile),
                );
                sbsd_payload = Some(body.clone());
                if !options.post {
                    break;
                }
                let built = xhr_request(
                    &self.client,
                    &page,
                    &self.hints,
                    RequestSpec {
                        method: wreq::Method::POST,
                        url: &post_target,
                        headers: &headers,
                        body: Some(&body),
                        credentials: "same-origin",
                    },
                )?;
                let resp = self.client.execute(built).await?;
                sbsd_status = Some(resp.status().as_u16());
                self.hints.observe(&resp);
                let _ = resp.bytes().await?;
                sbsd_posted += 1;
            }
            mechanisms.push(Mechanism {
                kind: "sbsd",
                url: candidate.clone(),
                payload_len: sbsd_payload.as_ref().map_or(0, String::len),
                status: sbsd_status,
            });
        }

        let mut script_url = String::new();
        let mut script = String::new();
        for candidate in &caps.sensors {
            let response = get_response(
                &self.client,
                &mut self.hints,
                candidate.parse()?,
                Some(&page),
            )
            .await?;
            let status = response.status();
            let source = response.text().await?;
            log.push(format!(
                "GET {candidate} -> {status}, {} bytes",
                source.len()
            ));
            if status.is_success() && source.contains("bmak") {
                script_url = candidate.clone();
                script = source;
                break;
            }
        }

        if script.is_empty() && mechanisms.is_empty() {
            return Err("no sensor script, pixel beacon, or sec-cpt challenge found".into());
        }
        let abck_before = cookie_snapshot(&self.cookies, &page).get("_abck").cloned();
        let mut payload = sbsd_payload;
        let mut payloads_posted = sbsd_posted;
        let mut post_status = sbsd_status;

        if !script.is_empty() {
            let script_sha256 = akamai_codec::script::analyze_script(&script).sha256;
            let tpl = if let Some(explicit) = &options.template {
                explicit.clone()
            } else if let Some(cached) = self.templates.get(&script_sha256) {
                cached.clone()
            } else {
                let extracted =
                    akamai_codec::sensor::BuildTemplate::from_bmak_script(&script, Some(&profile))
                        .map_err(|e| e.to_string())?;
                self.templates
                    .insert(script_sha256.clone(), extracted.clone());
                extracted
            };
            let target: Url = script_url.parse()?;
            let limit = options.posts.max(1);
            let headers = BTreeMap::from([(
                "content-type".to_owned(),
                "text/plain;charset=UTF-8".to_owned(),
            )]);
            for index in 0..limit {
                let sub_key = cookie_snapshot(&self.cookies, &page)
                    .get("bm_sz")
                    .map(|cookie| akamai_codec::sensor::bm_sz_seed(cookie))
                    .unwrap_or(akamai_codec::sensor::DEFAULT_SUB_KEY);
                let started = std::time::Instant::now();
                let body = if options.garbage {
                    serde_json::json!({ "sensor_data": "garbage" }).to_string()
                } else {
                    tpl.encode_post_for_script(index, sub_key, page.as_str(), &script_url)
                        .map_err(|e| e.to_string())?
                };
                let encode_us = started.elapsed().as_micros();
                log.push(format!(
                    "native payload {index}: {} bytes, sub={sub_key}, shuffle={}, encoded in {encode_us} us",
                    body.len(),
                    tpl.shuffle_key
                ));
                payload = Some(body.clone());
                if !options.post {
                    break;
                }
                let built = xhr_request(
                    &self.client,
                    &page,
                    &self.hints,
                    RequestSpec {
                        method: wreq::Method::POST,
                        url: &target,
                        headers: &headers,
                        body: Some(&body),
                        credentials: "same-origin",
                    },
                )?;
                let response = self.client.execute(built).await?;
                let status = response.status().as_u16();
                self.hints.observe(&response);
                let bytes = response.bytes().await?;
                log.push(format!(
                    "native POST {target} -> {status} ({} bytes)",
                    bytes.len()
                ));
                post_status = Some(status);
                payloads_posted += 1;
            }
            if let Some(body) = &payload {
                mechanisms.push(Mechanism {
                    kind: "sensor",
                    url: script_url.clone(),
                    payload_len: body.len(),
                    status: post_status,
                });
            }
        }
        let mut verify_status = None;
        let mut verify_bytes = None;
        if options.post && payloads_posted > 0 {
            let response =
                get_response(&self.client, &mut self.hints, page.clone(), Some(&page)).await?;
            let status = response.status().as_u16();
            let body = response.text().await?;
            verify_status = Some(status);
            verify_bytes = Some(body.len());
            log.push(format!("VERIFY {page} -> {status}, {} bytes", body.len()));
        }
        self.last_page = Some(page.clone());
        let snapshot = cookie_snapshot(&self.cookies, &page);
        let abck_after = snapshot.get("_abck").cloned();
        Ok(SolveOutcome {
            page_status,
            script_url,
            payload,
            payloads_posted,
            post_status,
            verify_status,
            verify_bytes,
            abck_before,
            abck_after,
            cookies: snapshot,
            log,
            mechanisms,
        })
    }

    /// Perform a GET request using the session's cookies, `Referer`, and negotiated client hints.
    pub async fn get(&mut self, url: &str) -> Result<SessionResponse> {
        let target: Url = url.parse()?;
        let response = get_response(
            &self.client,
            &mut self.hints,
            target,
            self.last_page.as_ref(),
        )
        .await?;
        self.session_response(response).await
    }

    /// Perform a POST request with an explicit `Content-Type` using the validated session.
    pub async fn post(
        &mut self,
        url: &str,
        content_type: &str,
        body: &str,
    ) -> Result<SessionResponse> {
        let headers = BTreeMap::from([("content-type".to_owned(), content_type.to_owned())]);
        self.request(wreq::Method::POST, url, &headers, Some(body))
            .await
    }

    /// Serialize `body` as JSON and POST it using the validated session.
    pub async fn post_json<T: serde::Serialize + ?Sized>(
        &mut self,
        url: &str,
        body: &T,
    ) -> Result<SessionResponse> {
        let payload = serde_json::to_string(body)?;
        let headers = BTreeMap::from([
            (
                "accept".to_owned(),
                "application/graphql-response+json, application/json".to_owned(),
            ),
            ("content-type".to_owned(), "application/json".to_owned()),
        ]);
        self.request(wreq::Method::POST, url, &headers, Some(&payload))
            .await
    }

    /// Execute an arbitrary XHR/fetch-style request on the validated session.
    pub async fn request(
        &mut self,
        method: wreq::Method,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&str>,
    ) -> Result<SessionResponse> {
        let target: Url = url.parse()?;
        let page = self.last_page.clone().unwrap_or_else(|| target.clone());
        let spec = RequestSpec {
            method,
            url: &target,
            headers,
            body,
            credentials: "include",
        };
        let req = xhr_request(&self.client, &page, &self.hints, spec)?;
        let response = self.client.execute(req).await?;
        let _ = self.hints.observe(&response);
        self.session_response(response).await
    }

    async fn session_response(&self, response: wreq::Response) -> Result<SessionResponse> {
        let status = response.status().as_u16();
        let url = response.uri().to_string();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let headers = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_owned(), v.to_owned()))
            })
            .collect();
        let body = response.bytes().await?.to_vec();
        Ok(SessionResponse {
            url,
            status,
            headers,
            content_type,
            body,
        })
    }

    /// Snapshot all cookies matching `url` in this session's cookie jar.
    pub fn cookies(&self, url: &str) -> Result<BTreeMap<String, String>> {
        let parsed: Url = url.parse()?;
        Ok(cookie_snapshot(&self.cookies, &parsed))
    }

    /// Format a `Cookie` request header (`k=v; k2=v2`) for `url` so callers can
    /// plug validated cookies directly into any external HTTP client.
    pub fn cookie_header(&self, url: &str) -> Result<String> {
        let parsed: Url = url.parse()?;
        Ok(self
            .cookies
            .matches(parsed.as_str())
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect::<Vec<_>>()
            .join("; "))
    }

    /// Returns `true` when the `_abck` cookie for `url` is in the validated `~0~` state.
    pub fn is_validated(&self, url: &str) -> Result<bool> {
        Ok(self
            .cookies(url)?
            .get("_abck")
            .and_then(|c| c.split('~').nth(1))
            .is_some_and(|state| state == "0"))
    }

    /// Access the underlying `wreq::Client`.
    pub fn http_client(&self) -> &wreq::Client {
        &self.client
    }

    /// Access the shared `wreq::cookie::Jar`.
    pub fn cookie_jar(&self) -> &Arc<wreq::cookie::Jar> {
        &self.cookies
    }

    /// Return the active `User-Agent` string for this session.
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }
}
