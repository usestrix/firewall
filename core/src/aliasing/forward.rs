use crate::http::{blocked, https_url, text};
use crate::{policies, telemetry};
use crate::{Firewall, FirewallConfig};
use rama::dns::client::DnsConnectorLayer;
use rama::http::body::util::BodyExt;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::CONTENT_LENGTH;
use rama::http::layer::decompression::DecompressionLayer;
use rama::http::layer::remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer};
use rama::http::layer::upgrade::{EagerHttpProxyConnector, UpgradeLayer};
use rama::http::server::HttpServer;
use rama::http::{Body, Method, Request, Response};
use rama::matcher::match_fn;
use rama::net::proxy::IoForwardService;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::client::service::TcpConnector;
use rama::tcp::server::TcpListener;
use rama::{Layer, Service};
use std::convert::Infallible;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Plaintext to clients and HTTPS upstream, so URLs are visible without a certificate.
pub fn spawn(port: u16, config: FirewallConfig) -> std::io::Result<u16> {
    let bound = std::net::TcpListener::bind(("127.0.0.1", port))?;
    let local = bound.local_addr()?.port();
    bound.set_nonblocking(true)?;

    let runtime = crate::runtime()?;
    std::thread::spawn(move || {
        runtime.block_on(async move {
            let firewall = Arc::new(Firewall::new(config));
            let exec = Executor::default();
            let listener = match TcpListener::try_from_std_tcp_listener(bound, exec.clone()) {
                Ok(listener) => listener,
                Err(e) => return error!(error = %e, "forward proxy could not take over the socket"),
            };
            // Tunnels skip screening, so a registry's CONNECT falls through to `handle`, which refuses it.
            let hosts = firewall.hosts();
            let tunnel = UpgradeLayer::new(
                exec.clone(),
                match_fn(move |req: &Request| {
                    let host = req.uri().host().map(|host| host.to_str());
                    req.method() == Method::CONNECT
                        && host.is_some_and(|host| !hosts.contains(&host.as_ref()))
                }),
                EagerHttpProxyConnector::new(
                    DnsConnectorLayer::new().into_layer(TcpConnector::new()),
                    IoForwardService::default(),
                ),
            );
            let server = HttpServer::auto(exec).service(
                (
                    RemoveResponseHeaderLayer::hop_by_hop(),
                    RemoveRequestHeaderLayer::hop_by_hop(),
                    tunnel,
                )
                    .into_layer(service_fn(move |req: Request| {
                        let firewall = Arc::clone(&firewall);
                        async move { handle(req, &firewall).await }
                    })),
            );
            listener.serve(server).await;
        });
    });
    Ok(local)
}

async fn handle(req: Request, firewall: &Firewall) -> Result<Response, Infallible> {
    if req.method() == Method::CONNECT {
        warn!(uri = %req.uri(), "refused CONNECT, only plain HTTP can be screened");
        return Ok(text(
            403,
            "firewall: HTTPS tunnelling is disabled, request it over http:// instead\n",
        ));
    }

    let Some(url) = https_url(&req) else {
        warn!(method = %req.method(), uri = %req.uri(), "unroutable, expected an absolute URL");
        return Ok(text(400, "firewall: expected an absolute URL\n"));
    };

    let reason = policies::screen(&url, firewall).await;
    telemetry::screened(firewall, &url, reason.as_deref());
    if let Some(reason) = reason {
        warn!(method = %req.method(), %url, %reason, "blocked");
        return Ok(blocked(&reason));
    }

    info!(method = %req.method(), %url, "forwarding");
    // Only an HTTPS registry was downgraded to reach us, so only it is upgraded back and rewritten.
    let tls = firewall.is_https_url(&url);
    let index = tls && firewall.is_index_url(&url);
    let (mut parts, body) = req.into_parts();
    if tls {
        let Ok(uri) = url.parse() else {
            return Ok(text(400, "firewall: expected an absolute URL\n"));
        };
        parts.uri = uri;
    }

    let client = DecompressionLayer::new().into_layer(EasyHttpWebClient::default());
    let response = match client.serve(Request::from_parts(parts, body)).await {
        Ok(response) => response,
        Err(e) => {
            telemetry::error("upstream");
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
    Ok(Response::from_parts(parts, Body::from(downgrade(firewall, collected.to_bytes().to_vec()))))
}

/// crates.io serves config.json as octet-stream, so UTF-8 validity decides what is text.
pub fn downgrade(firewall: &Firewall, body: Vec<u8>) -> Vec<u8> {
    let mut text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(raw) => return raw.into_bytes(),
    };
    for host in firewall.hosts() {
        text = text.replace(&format!("https://{host}"), &format!("http://{host}"));
    }
    text.into_bytes()
}
