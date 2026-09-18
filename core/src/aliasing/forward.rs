use crate::policies::{self, registries};
use rama::http::body::util::BodyExt;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::{CONTENT_LENGTH, HOST};
use rama::http::layer::decompression::DecompressionLayer;
use rama::http::layer::remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer};
use rama::http::server::HttpServer;
use rama::http::{Body, Method, Request, Response, StatusCode};
use rama::rt::blocking::Runtime;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener;
use rama::{Layer, Service};
use std::convert::Infallible;
use tracing::{error, info, warn};

/// Speaks plaintext to clients and HTTPS upstream, so the full URL is visible
/// without a certificate.
pub fn spawn(port: u16) -> std::io::Result<u16> {
    let bound = std::net::TcpListener::bind(("127.0.0.1", port))?;
    let local = bound.local_addr()?.port();
    bound.set_nonblocking(true)?;

    let runtime = Runtime::try_new()?;
    std::thread::spawn(move || {
        runtime.block_on(async move {
            let exec = Executor::default();
            let listener = match TcpListener::try_from_std_tcp_listener(bound, exec.clone()) {
                Ok(listener) => listener,
                Err(e) => return error!(error = %e, "forward proxy could not take over the socket"),
            };
            let server = HttpServer::auto(exec).service(
                (RemoveResponseHeaderLayer::hop_by_hop(), RemoveRequestHeaderLayer::hop_by_hop())
                    .into_layer(service_fn(handle)),
            );
            listener.serve(server).await;
        });
    });
    Ok(local)
}

async fn handle(req: Request) -> Result<Response, Infallible> {
    if req.method() == Method::CONNECT {
        warn!(uri = %req.uri(), "refused CONNECT, only plain HTTP can be screened");
        return Ok(text(
            403,
            "firewall: HTTPS tunnelling is disabled, request it over http:// instead\n",
        ));
    }

    let Some(url) = upstream_url(&req) else {
        warn!(method = %req.method(), uri = %req.uri(), "unroutable, expected an absolute URL");
        return Ok(text(400, "firewall: expected an absolute URL\n"));
    };

    if let Some(reason) = policies::screen(&url).await {
        warn!(method = %req.method(), %url, %reason, "blocked");
        return Ok(text(403, &format!("blocked by firewall: {reason}\n")));
    }

    // Over plain HTTP the bytes could be swapped after OSV cleared them.
    if !url.starts_with("https://") {
        unreachable!("upstream fetch is not https: {url}");
    }

    info!(method = %req.method(), %url, "forwarding");
    let index = registries::is_index_url(&url);
    let (mut parts, body) = req.into_parts();
    let Ok(uri) = url.parse() else {
        return Ok(text(400, "firewall: expected an absolute URL\n"));
    };
    parts.uri = uri;

    let client = DecompressionLayer::new().into_layer(EasyHttpWebClient::default());
    let response = match client.serve(Request::from_parts(parts, body)).await {
        Ok(response) => response,
        Err(e) => {
            warn!(%url, error = %e, "upstream request failed");
            return Ok(text(502, &format!("firewall: upstream error: {e}\n")));
        }
    };
    let (mut parts, body) = response.into_parts();
    if !index {
        return Ok(Response::from_parts(parts, Body::new(body)));
    }

    let Ok(collected) = body.collect().await else {
        warn!(%url, "could not read the upstream body");
        return Ok(text(502, "firewall: could not read the upstream body\n"));
    };
    // The rewrite changes the length, so let the server state it again.
    parts.headers.remove(CONTENT_LENGTH);
    Ok(Response::from_parts(parts, Body::from(downgrade(collected.to_bytes().to_vec()))))
}

fn text(status: u16, body: &str) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY))
        .header("content-type", "text/plain")
        .body(Body::from(body.to_string()))
        .expect("status and content type are valid")
}

pub fn upstream_url(req: &Request) -> Option<String> {
    let path = req.uri().request_target();
    let host = match req.uri().authority() {
        Some(authority) => authority.to_string(),
        None => req.headers().get(HOST)?.to_str().ok()?.to_string(),
    };
    Some(format!("https://{host}{path}"))
}

/// crates.io serves config.json as octet-stream, so UTF-8 validity decides what is text.
pub fn downgrade(body: Vec<u8>) -> Vec<u8> {
    let mut text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(raw) => return raw.into_bytes(),
    };
    for host in registries::hosts() {
        text = text.replace(&format!("https://{host}"), &format!("http://{host}"));
    }
    text.into_bytes()
}
