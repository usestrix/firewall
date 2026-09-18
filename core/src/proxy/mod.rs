mod process;

use crate::routing::{self, Check, Decision, Package, Reason};
use crate::Config;
use rama::extensions::ExtensionsRef;
use rama::http::body::util::BodyExt;
use rama::http::client::EasyHttpWebClient;
use rama::http::header::CONTENT_TYPE;
use rama::http::server::HttpServer;
use rama::http::service::client::HttpClientExt;
use rama::http::{Body, Request, Response, StatusCode};
use rama::net::stream::SocketInfo;
use rama::rt::blocking::Runtime;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener;
use std::convert::Infallible;
use std::io::Write;
use std::sync::Arc;

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
    let peer_port = req.extensions().get_ref::<SocketInfo>().map_or(0, |s| s.peer_addr().port);
    let target = req.uri().request_target().into_owned();

    let (proc_name, cmdline) = process::lookup(peer_port);
    let mut log = format!(
        "\n{}\n[{}] {} {}\n  process : {}\n",
        "=".repeat(74),
        crate::hms(),
        req.method(),
        target,
        proc_name
    );
    if !cmdline.is_empty() {
        let c: String = cmdline.chars().take(150).collect();
        log.push_str(&format!("  cmdline : {c}\n"));
    }

    let response = match routing::decide(&target, cfg).await {
        Decision::Unroutable => {
            log.push_str("  --> no route (unknown prefix)\n");
            reply(404, "text/plain", b"No route.\n".to_vec())
        }
        Decision::Block { eco, pkg, reason } => {
            let msg = blocked(eco, &pkg, &reason);
            log.push_str(&format!("  !!! {msg}\n"));
            reply(403, "text/plain", format!("{msg}\n").into_bytes())
        }
        Decision::Allow { target, check } => {
            match &check {
                Check::NoPackage => {}
                Check::Clean(p) => {
                    log.push_str(&format!("  ok  OSV clean: {}/{}\n", target.eco, p.label()))
                }
                Check::Unverified(p, e) => log.push_str(&format!(
                    "  ??? OSV lookup failed for {} ({}) -- ALLOWING\n",
                    p.label(),
                    e
                )),
            }
            log.push_str(&format!("  --> {} upstream {}\n", target.eco, target.upstream));
            let (status, ctype, body, note) = mirror(&target).await;
            log.push_str(&format!("  <-- {} {}{}\n", status, human(body.len()), note));
            reply(status, &ctype, body)
        }
    };

    emit(&log);
    response
}

async fn mirror(target: &routing::Target) -> (u16, String, Vec<u8>, String) {
    let client = EasyHttpWebClient::default();
    let response = match client.get(&target.upstream).send().await {
        Ok(response) => response,
        Err(e) => {
            return (502, "text/plain".to_string(), e.to_string().into_bytes(), String::new())
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
            return (502, "text/plain".to_string(), e.to_string().into_bytes(), String::new())
        }
    };

    match &target.rewrite {
        Some((from, to)) => {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let hits = text.matches(from.as_str()).count();
            (
                status,
                ctype,
                text.replace(from.as_str(), to).into_bytes(),
                format!(", rewrote {hits} URLs"),
            )
        }
        None => (status, ctype, bytes, String::new()),
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

fn emit(s: &str) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = lock.write_all(s.as_bytes());
    let _ = lock.flush();
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
