use super::*;

/// Fetch a page, run its detected mechanisms, and verify the protected route.
pub async fn solve(options: SolveOptions) -> Result<SolveOutcome> {
    let mut client = AkamaiClient::from_options(&options)?;
    client.solve_with(options).await
}

pub(crate) async fn get_response(
    client: &wreq::Client,
    hints: &mut ClientHints,
    mut url: url::Url,
    referer: Option<&url::Url>,
) -> Result<wreq::Response> {
    let mut critical_retried = false;
    for _ in 0..12 {
        let mut outgoing = request(
            client,
            wreq::Method::GET,
            url.as_str(),
            &hints.headers_for(&url),
        );
        if let Some(referer) = referer {
            outgoing = outgoing.header(REFERER, referer.as_str());
        }
        let response = outgoing.send().await?;
        let needs_retry = hints.observe(&response);
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308)
            && let Some(location) = response.headers().get("location")
        {
            url = url.join(location.to_str()?)?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err("unsupported redirect scheme".into());
            }
            continue;
        }
        if needs_retry && !critical_retried {
            critical_retried = true;
            continue;
        }
        return Ok(response);
    }
    Err("too many redirects or client-hint retries".into())
}
