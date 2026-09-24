use crate::http::{blocked, reply, text};
use crate::policies::{self, Check, Decision};
use crate::{Firewall, FirewallConfig};
use rama::http::body::util::BodyExt;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::CONTENT_TYPE;
use rama::http::server::HttpServer;
use rama::http::service::client::HttpClientExt;
use rama::http::{Request, Response};
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener;
use std::convert::Infallible;
use std::sync::Arc;
use tracing::{info, info_span, warn, Instrument};

pub fn serve(config: FirewallConfig) -> std::io::Result<()> {
    let bound = std::net::TcpListener::bind(("127.0.0.1", config.port))?;
    bound.set_nonblocking(true)?;
    crate::runtime()?.block_on(async move {
        let firewall = Arc::new(Firewall::new(config));
        let exec = Executor::default();
        let listener = TcpListener::try_from_std_tcp_listener(bound, exec.clone())?;
        let server = HttpServer::auto(exec).service(service_fn(move |req: Request| {
            let firewall = Arc::clone(&firewall);
            async move { Ok::<_, Infallible>(handle(req, &firewall).await) }
        }));
        listener.serve(server).await;
        Ok(())
    })
}

async fn handle(req: Request, firewall: &Firewall) -> Response {
    let target = req.uri().request_target().into_owned();
    let span = info_span!("request", method = %req.method(), %target);
    screen(target, firewall).instrument(span).await
}

async fn screen(target: String, firewall: &Firewall) -> Response {
    match policies::decide(&target, firewall).await {
        Decision::Unroutable => {
            warn!("no route, unknown prefix");
            text(404, "No route.\n")
        }
        Decision::Block { eco, pkg, filter, reason } => {
            let reason = format!("{} {reason}", pkg.label());
            warn!(%eco, %filter, "blocked by firewall: {reason}");
            blocked(&reason)
        }
        Decision::Allow { target, check } => {
            match &check {
                Check::NoPackage => {}
                Check::Allowed(pkg) => {
                    info!(eco = %target.eco, pkg = %pkg.label(), "cleared by every filter")
                }
                Check::Unverified { pkg, filter, error } => {
                    info!(pkg = %pkg.label(), %filter, %error, "filter could not check, allowing")
                }
            }
            info!(eco = %target.eco, upstream = %target.upstream, "fetching upstream");

            mirror(&target).await
        }
    }
}

async fn mirror(target: &policies::Target) -> Response {
    let client = EasyHttpWebClient::default();
    let response = match client.get(&target.upstream).send().await {
        Ok(response) => response,
        Err(e) => {
            warn!(error = %e, "upstream request failed");
            return text(502, &e.to_string());
        }
    };

    let status = response.status().as_u16();
    let ctype = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let bytes = match response.into_body().collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) => {
            warn!(error = %e, "could not read the upstream body");
            return text(502, &e.to_string());
        }
    };

    let (body, rewrites) = match &target.rewrite {
        Some((from, to)) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let hits = text.matches(from.as_str()).count();
            (text.replace(from.as_str(), to).into_bytes(), hits)
        }
        None => (bytes, 0),
    };

    info!(status, size = %human(body.len()), rewrites, "served");
    reply(status, &ctype, body)
}

fn human(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.1} MB", n as f64 / (1 << 20) as f64)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}
