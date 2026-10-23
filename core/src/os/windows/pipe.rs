//! How the tray asks the service what it blocked, and allows a new package once, as the macOS
//! app messages its extension.

use super::{config_file, security_descriptor};
use crate::{blocks, Firewall};
use rama::error::BoxError;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows::core::{Owned, PWSTR};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::*;

pub(super) const PIPE: &str = r"\\.\pipe\StrixFirewall";
/// Signed-in users can connect, as the tray runs as them.
const PIPE_ACL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

pub(super) async fn serve(firewall: Arc<Firewall>) -> Result<(), BoxError> {
    let mut server = create(true)?;
    loop {
        server.connect().await?;
        let client = std::mem::replace(&mut server, create(false)?);
        let firewall = Arc::clone(&firewall);
        tokio::spawn(async move {
            if let Err(error) = answer(client, &firewall).await {
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
async fn answer(client: NamedPipeServer, firewall: &Firewall) -> Result<(), BoxError> {
    let mut client = BufReader::new(client);
    let mut request = String::new();
    (&mut client)
        .take(64 * 1024)
        .read_line(&mut request)
        .await?;
    let request = request.trim_end();
    // Only the app can message the macOS extension; here any program could connect.
    let reply = if !client_is_tray(client.get_ref())? {
        "error: only the tray can ask".to_owned()
    } else if request.starts_with("allow ") {
        // Trusting writes the config for every user, so it is left to an administrator.
        "error: trusting a package takes an administrator".to_owned()
    } else {
        blocks::answer(firewall, &config_file(), request)
    };
    client.write_all(format!("{reply}\n").as_bytes()).await?;
    // Closing before the tray hangs up could discard the reply.
    let _ = tokio::time::timeout(Duration::from_secs(5), client.read(&mut [0])).await;
    Ok(())
}

fn client_is_tray(client: &NamedPipeServer) -> Result<bool, BoxError> {
    let mut id = 0;
    unsafe { GetNamedPipeClientProcessId(HANDLE(client.as_raw_handle()), &mut id)? };
    let process = unsafe { Owned::new(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, id)?) };
    let mut path = [0u16; 1024];
    let mut len = path.len() as u32;
    let flags = PROCESS_NAME_WIN32;
    unsafe { QueryFullProcessImageNameW(*process, flags, PWSTR(path.as_mut_ptr()), &mut len)? };
    let path = String::from_utf16(&path[..len as usize])?;
    let tray = std::env::current_exe()?.with_file_name("firewall-tray.exe");
    // Windows paths ignore case.
    Ok(path.to_lowercase() == tray.to_string_lossy().to_lowercase())
}
