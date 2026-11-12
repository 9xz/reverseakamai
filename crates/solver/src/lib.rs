//! Unified Akamai web challenge driver.
//!
//! Detects and runs each mechanism the edge asks for, in order:
//! `sec-cpt` escalation, `/akam/13/` pixel beacon, SBSD state checks, and
//! the v2/v3 `bmak` sensor via native Rust payload construction (`native-payload`
//! + `akamai-codec`). Mobile BMP/BAP native SDKs are out of scope.

mod detect;
mod driver;
pub mod env;
mod network;
mod sdk;
mod sec_cpt;
pub use driver::solve;
pub use native_payload::profile::DeviceProfile;
pub use sdk::{AkamaiClient, AkamaiClientBuilder, SessionResponse};
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
pub use wreq_util::Profile;

use network::ClientHints;
use wreq::header::REFERER;
use wreq_util::Emulation;
pub type Result<T, E = Box<dyn Error + Send + Sync>> = std::result::Result<T, E>;

const DEFAULT_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// What to solve and how.
pub struct SolveOptions {
    pub url: String,
    pub profile: Profile,
    pub user_agent: Option<String>,
    /// Submit the captured payload. `false` only builds it.
    pub post: bool,
    /// Submit a deliberately invalid payload, as a control arm.
    pub garbage: bool,
    /// Submit at most this many telemetry posts in one session.
    pub posts: usize,
    /// Optional pre-extracted native build template (`BuildTemplate`).
    pub template: Option<akamai_codec::sensor::BuildTemplate>,
    /// Optional recorded browser environment (`tools/capture-env.js`).
    pub device: Option<serde_json::Value>,
}

impl SolveOptions {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            profile: Profile::Chrome131,
            user_agent: None,
            post: true,
            garbage: false,
            posts: 1,
            template: None,
            device: None,
        }
    }
}

/// One mechanism that ran.
pub struct Mechanism {
    pub kind: &'static str,
    pub url: String,
    pub payload_len: usize,
    pub status: Option<u16>,
}

/// What happened.
pub struct SolveOutcome {
    pub page_status: u16,
    pub script_url: String,
    pub payload: Option<String>,
    pub payloads_posted: usize,
    pub post_status: Option<u16>,
    /// Status of re-requesting the protected URL after telemetry.
    pub verify_status: Option<u16>,
    /// Response body size of that verification request.
    pub verify_bytes: Option<usize>,
    pub abck_before: Option<String>,
    pub abck_after: Option<String>,
    pub cookies: BTreeMap<String, String>,
    pub log: Vec<String>,
    pub mechanisms: Vec<Mechanism>,
}

impl SolveOutcome {
    /// True only when the server explicitly marks `_abck` as validated.
    pub fn abck_advanced(&self) -> bool {
        self.abck_after
            .as_deref()
            .and_then(|cookie| cookie.split('~').nth(1))
            .is_some_and(|state| state == "0")
    }

    /// Length of `_abck` field 2 (the edge state blob) before and after.
    pub fn state_growth(&self) -> Option<(usize, usize)> {
        let before = field2_len(&self.abck_before)?;
        let after = field2_len(&self.abck_after)?;
        Some((before, after))
    }
}

fn field2_len(cookie: &Option<String>) -> Option<usize> {
    cookie.as_ref()?.split('~').nth(2).map(str::len)
}

fn request(
    client: &wreq::Client,
    method: wreq::Method,
    url: &str,
    headers: &[(String, String)],
) -> wreq::RequestBuilder {
    let mut request = client.request(method, url);
    for (name, value) in headers {
        request = request.header(name.as_str(), value.as_str());
    }
    request
}

fn client(
    options: &SolveOptions,
    user_agent: &str,
    cookies: Arc<wreq::cookie::Jar>,
) -> Result<wreq::Client> {
    let profile = if options.profile == Profile::Chrome131
        && options
            .device
            .as_ref()
            .and_then(|dev| dev.get("chromeVersion"))
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|major| major >= 152)
    {
        Profile::Chrome154
    } else if options.profile == Profile::Chrome131
        && options
            .device
            .as_ref()
            .and_then(|dev| dev.get("chromeVersion"))
            .and_then(|v| v.as_str())
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|major| major >= 149)
    {
        Profile::Chrome149
    } else {
        options.profile
    };
    let emulation = Emulation::builder()
        .profile(profile)
        .platform(wreq_util::Platform::MacOS)
        .http2(true)
        .build();
    let mut emulation = wreq::IntoEmulation::into_emulation(emulation);
    // ClientHints owns these values, including an explicitly disabled capture.
    // Otherwise wreq restores profile defaults when a request omits UA hints.
    for name in ["sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"] {
        emulation.headers.remove(name);
    }
    Ok(wreq::Client::builder()
        .emulation(emulation)
        .user_agent(user_agent)
        .redirect(wreq::redirect::Policy::none())
        .cookie_provider(cookies)
        .timeout(Duration::from_secs(30))
        .build()?)
}

pub(crate) fn device_profile_for(
    user_agent: &str,
    options: &SolveOptions,
) -> native_payload::profile::DeviceProfile {
    if let Some(dev) = &options.device
        && let Ok(mut profile) = native_payload::profile::DeviceProfile::from_capture_json(dev)
    {
        if options.user_agent.is_some() {
            profile.user_agent = user_agent.to_owned();
        }
        return profile;
    }
    let major = user_agent
        .split("Chrome/")
        .nth(1)
        .and_then(|v| v.split('.').next())
        .unwrap_or("156");
    let mut profile = native_payload::profile::DeviceProfile::chrome_macos(major);
    profile.user_agent = user_agent.to_owned();
    profile
}
