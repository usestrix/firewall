use crate::routing::{self, Check, Decision, Package, Reason};
use crate::Config;
use rama::http::body::util::BodyExt;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::CONTENT_TYPE;
use rama::http::server::HttpServer;
use rama::http::service::client::HttpClientExt;
use rama::http::{Body, Request, Response, StatusCode};
use rama::rt::blocking::Runtime;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener;
use std::convert::Infallible;
use std::sync::Arc;
use tracing::{info, info_span, warn, Instrument};

pub fn serve(cfg: Config) -> std::io::Result<()> {
    let bound = std::net::TcpListener::bind(("127.0.0.1", cfg.port))?;
    bound.set_nonblocking(true)?;
    let cfg = Arc::new(cfg);
    Runtime::try_new()?.block_on(async move {
        let exec = Executor::default();
        let listener = TcpListener::try_from_std_tcp_listener(bound, exec.clone())?;
        let server = HttpServer::auto(exec).service(service_fn(move |req: Request| {
            let cfg = Arc::clone(&cfg);
            async move { Ok::<_, Infallible>(handle(req, &cfg).await) }
        }));
        listener.serve(server).await;
        Ok(())
    })
}

async fn handle(req: Request, cfg: &Config) -> Response {
    let target = req.uri().request_target().into_owned();
    let span = info_span!("request", method = %req.method(), %target);
    screen(target, cfg).instrument(span).await
}

async fn screen(target: String, cfg: &Config) -> Response {
    match routing::decide(&target, cfg).await {
        Decision::Unroutable => {
            warn!("no route, unknown prefix");
            reply(404, "text/plain", b"No route.\n".to_vec())
        }
        Decision::Block { eco, pkg, reason } => {
            let msg = blocked(eco, &pkg, &reason);
            warn!("{msg}");
            reply(403, "text/plain", format!("{msg}\n").into_bytes())
        }
        Decision::Allow { target, check } => {
            match &check {
                Check::NoPackage => {}
                Check::Clean(pkg) => info!(eco = %target.eco, pkg = %pkg.label(), "OSV clean"),
                Check::Unverified(pkg, e) => {
                    info!(pkg = %pkg.label(), error = %e, "OSV lookup failed, allowing")
                }
            }
            info!(eco = %target.eco, upstream = %target.upstream, "fetching upstream");

            let (status, ctype, body, rewrites) = mirror(&target).await;
            info!(status, size = %human(body.len()), rewrites, "served");
            reply(status, &ctype, body)
        }
    }
}

async fn mirror(target: &routing::Target) -> (u16, String, Vec<u8>, usize) {
    let client = EasyHttpWebClient::default();
    let response = match client.get(&target.upstream).send().await {
        Ok(response) => response,
        Err(e) => {
            warn!(error = %e, "upstream request failed");
            return (502, "text/plain".to_string(), e.to_string().into_bytes(), 0);
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
            return (502, "text/plain".to_string(), e.to_string().into_bytes(), 0);
        }
    };

    match &target.rewrite {
        Some((from, to)) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let hits = text.matches(from.as_str()).count();
            (status, ctype, text.replace(from.as_str(), to).into_bytes(), hits)
        }
        None => (status, ctype, bytes, 0),
    }
}

fn reply(status: u16, ctype: &str, body: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY))
        .header(CONTENT_TYPE, ctype)
        .body(Body::from(body))
        .expect("status and content type are valid")
}

fn blocked(eco: &str, pkg: &Package, reason: &Reason) -> String {
    let detail = match reason {
        Reason::Malicious(ids) => format!("is flagged malicious by OSV ({})", ids.join(", ")),
        Reason::Unverified(e) => format!("could not be verified against OSV ({})", e),
    };
    format!("blocked by firewall: {} {} {}", eco, pkg.label(), detail)
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
