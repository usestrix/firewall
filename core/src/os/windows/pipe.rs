//! How the tray asks the service what it blocked, as the macOS app messages its extension.

use super::security_descriptor;
use crate::blocks;
use rama::error::BoxError;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::Win32::Security::SECURITY_ATTRIBUTES;

pub(super) const PIPE: &str = r"\\.\pipe\StrixFirewall";
/// Signed-in users can connect, as the tray runs as them.
const PIPE_ACL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

pub(super) async fn serve() -> Result<(), BoxError> {
    let mut server = create(true)?;
    loop {
        server.connect().await?;
        let client = std::mem::replace(&mut server, create(false)?);
        tokio::spawn(async move {
            if let Err(error) = answer(client).await {
                tracing::debug!(%error, "could not answer the tray");
            }
        });
    }
}

fn create(first: bool) -> Result<NamedPipeServer, BoxError> {
    let acl = security_descriptor(PIPE_ACL)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: acl.0,
        bInheritHandle: false.into(),
    };
    let attributes = (&raw mut attributes).cast();
    let mut options = ServerOptions::new();
    // Fails if anyone else made the pipe first.
    options.first_pipe_instance(first);
    Ok(unsafe { options.create_with_security_attributes_raw(PIPE, attributes)? })
}

/// A line each way.
async fn answer(client: NamedPipeServer) -> Result<(), BoxError> {
    let mut client = BufReader::new(client);
    let mut request = String::new();
    (&mut client)
        .take(64 * 1024)
        .read_line(&mut request)
        .await?;
    let reply = match request.trim_end() {
        "blocks" => serde_json::to_string(&blocks::take())?,
        other => format!("error: unknown request {other}"),
    };
    client.write_all(format!("{reply}\n").as_bytes()).await?;
    // Closing before the tray hangs up could discard the reply.
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read(&mut [0])).await;
    Ok(())
}
