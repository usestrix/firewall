use rama::http::header::{CONTENT_TYPE, HOST};
use rama::http::{Body, Request, Response, StatusCode};
use std::borrow::Cow;

/// The host is in the URI on h2 and in the Host header on h1.
pub fn https_url(req: &Request) -> Option<String> {
    let host = match req.uri().host_str() {
        Some(host) => host,
        None => Cow::Borrowed(req.headers().get(HOST)?.to_str().ok()?),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    Some(format!("https://{host}{}", req.uri().request_target()))
}

pub fn reply(status: u16, ctype: &str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY))
        .header(CONTENT_TYPE, ctype)
        .body(Body::from(body))
        .expect("status and content type are valid")
}

pub fn text(status: u16, body: &str) -> Response {
    reply(status, "text/plain", body.as_bytes().to_vec())
}

pub fn blocked(reason: &str) -> Response {
    text(403, &format!("blocked by firewall: {reason}\n"))
}
