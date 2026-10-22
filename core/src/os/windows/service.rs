use super::ca::{load_or_create_ca, secure_data_dir};
use super::tpm::CaKey;
use super::{config_file, loopback_addresses, write_hosts_entries, CRL_ADDRESS, SERVICE_NAME};
use crate::config::FirewallConfig;
use crate::http::{reply, text};
use crate::{mitm, telemetry, Firewall};
use rama::dns::client::hickory::resolver::config::ResolveHosts;
use rama::dns::client::hickory::{default_resolver_opts, HickoryDnsResolver};
use rama::dns::client::resolver::DnsAddressResolver;
use rama::dns::client::try_init_global_dns_resolver;
use rama::error::BoxError;
use rama::http::server::HttpServer;
use rama::http::{Request, Response};
use rama::io::BridgeIo;
use rama::layer::ConsumeErrLayer;
use rama::net::address::Domain;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener;
use rama::tcp::TcpStream;
use rama::{Layer, Service};
use rcgen::SigningKey;
use std::convert::Infallible;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_service::service::*;
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

const CRL_PATH: &str = "/ca.crl";
/// Past this the log moves aside, keeping one previous file.
const LOG_ROTATE_SIZE: u64 = 1 << 20;

define_windows_service!(ffi_service_main, service_main);

/// Called by the service control manager, never by hand.
pub fn run() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// stderr goes nowhere in a service, so events go to a file beside the CA.
fn service_main(_arguments: Vec<OsString>) {
    let log = secure_data_dir().and_then(|dir| {
        let path = dir.join("firewall.log");
        // At each start, so the last crash survives the restart that follows it.
        if std::fs::metadata(&path).is_ok_and(|log| log.len() > LOG_ROTATE_SIZE) {
            let _ = std::fs::rename(&path, dir.join("firewall.log.1"));
        }
        std::fs::File::options()
            .create(true)
            .append(true)
            .open(path)
    });
    if let Ok(file) = log {
        let filter = crate::log_filter("info");
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(Mutex::new(file))
            .try_init();
    }
    std::panic::set_hook(Box::new(|panic| tracing::error!("{panic}")));
    if let Err(error) = run_until_stopped() {
        tracing::error!(%error, "the service stopped");
    }
}

fn run_until_stopped() -> Result<(), BoxError> {
    let (control_sender, mut control_receiver) = tokio::sync::mpsc::unbounded_channel();
    let status = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop
        | ServiceControl::Shutdown
        | ServiceControl::Pause
        | ServiceControl::Continue => {
            let _ = control_sender.send(control);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    set_status(&status, ServiceState::StartPending, false)?;
    let served = crate::runtime()?.block_on(async {
        let hosts = match start_screening(&status).await {
            Ok(hosts) => hosts,
            Err(error) => {
                telemetry::send().await;
                return Err(error);
            }
        };
        // Only pausing removes our hosts entries; a stop or crash keeps them, failing closed.
        while let Some(control) = control_receiver.recv().await {
            let (hosts, state) = match control {
                ServiceControl::Pause => (&[][..], ServiceState::Paused),
                ServiceControl::Continue => (&hosts[..], ServiceState::Running),
                _ => break,
            };
            match write_hosts_entries(hosts) {
                Ok(()) => set_status(&status, state, false)?,
                Err(error) => tracing::error!(%error, "could not rewrite the hosts file"),
            }
        }
        Ok::<_, BoxError>(())
    });
    // A failed stop is what makes the service manager restart it.
    set_status(&status, ServiceState::Stopped, served.is_err())?;
    served
}

async fn start_screening(status: &ServiceStatusHandle) -> Result<Vec<&'static str>, BoxError> {
    telemetry::set_mode("service");
    telemetry::heartbeat();
    // Never the hosts file, which points back at us; the Firewall's lookups included.
    let mut options = default_resolver_opts();
    options.use_hosts_file = ResolveHosts::Never;
    let resolver = HickoryDnsResolver::try_new_system_with_options(options)?;
    let _ = try_init_global_dns_resolver(resolver.clone());
    let config =
        FirewallConfig::load_from(&[config_file()]).inspect_err(|_| telemetry::error("config"))?;
    let firewall = Arc::new(Firewall::new(config));
    let hosts = firewall.hosts();
    let key = CaKey::load_or_create().inspect_err(|_| telemetry::error("tpm"))?;
    let signer: mitm::CaSigner = Arc::new(key);
    let ca = load_or_create_ca(&hosts, &*signer).inspect_err(|_| telemetry::error("ca"))?;
    let exec = Executor::default();

    // An empty CRL for the leaves to point at, signed fresh for each fetch.
    let crl_url = format!("http://{CRL_ADDRESS}{CRL_PATH}");
    let (crl_hosts, crl_signer) = (hosts.clone(), Arc::clone(&signer));
    let crl = service_fn(move |req: Request| {
        let response = if req.uri().request_target() == CRL_PATH {
            crl_response(&crl_hosts, &*crl_signer)
        } else {
            text(404, "No route.\n")
        };
        async move { Ok::<_, Infallible>(response) }
    });
    let crl = HttpServer::auto(exec.clone()).service(crl);
    tokio::spawn(listen_on(CRL_ADDRESS, 80, &exec)?.serve(crl));

    let service = mitm::mitm_service(firewall, &ca, signer, Some(crl_url), exec.clone());
    for (address, host) in loopback_addresses(&hosts) {
        for port in [80, 443] {
            let upstream = RedirectedHost {
                host,
                port,
                resolver: resolver.clone(),
                service: service.clone(),
            };
            let upstream = ConsumeErrLayer::trace_as_debug().into_layer(upstream);
            tokio::spawn(listen_on(address, port, &exec)?.serve(upstream));
        }
    }
    // Rewritten on every start, so a restart picks up a changed host list.
    write_hosts_entries(&hosts)?;
    tracing::info!(?hosts, "screening redirected registry traffic");
    set_status(status, ServiceState::Running, false)?;
    Ok(hosts)
}

fn crl_response(hosts: &[&str], signer: &dyn SigningKey) -> Response {
    match mitm::crl(hosts, signer) {
        Ok(der) => reply(200, "application/pkix-crl", der),
        Err(error) => text(503, &format!("{error}\n")),
    }
}

fn listen_on(address: Ipv4Addr, port: u16, exec: &Executor) -> std::io::Result<TcpListener> {
    let bound = std::net::TcpListener::bind((address, port))?;
    bound.set_nonblocking(true)?;
    TcpListener::try_from_std_tcp_listener(bound, exec.clone())
}

/// Each listener is bound to one host's address, which is how it knows where to connect.
#[derive(Clone)]
struct RedirectedHost {
    host: &'static str,
    port: u16,
    resolver: HickoryDnsResolver,
    service: mitm::MitmService,
}

impl Service<TcpStream> for RedirectedHost {
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, ingress: TcpStream) -> Result<(), BoxError> {
        let address = self.resolve().await?;
        let egress = tokio::net::TcpStream::connect((address, self.port)).await?;
        let streams = BridgeIo(ingress, TcpStream::from(egress));
        self.service.serve(streams).await
    }
}

impl RedirectedHost {
    /// IPv4 if it has one, else IPv6.
    async fn resolve(&self) -> Result<IpAddr, BoxError> {
        let domain = Domain::from_static(self.host);
        if let Some(Ok(v4)) = self.resolver.lookup_ipv4_first(domain.clone()).await {
            return Ok(v4.into());
        }
        match self.resolver.lookup_ipv6_first(domain).await {
            Some(v6) => Ok(v6?.into()),
            None => Err(format!("{} has no address", self.host).into()),
        }
    }
}

fn set_status(
    status: &ServiceStatusHandle,
    state: ServiceState,
    failed: bool,
) -> windows_service::Result<()> {
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: match state {
            ServiceState::Running | ServiceState::Paused => {
                ServiceControlAccept::STOP
                    | ServiceControlAccept::SHUTDOWN
                    | ServiceControlAccept::PAUSE_CONTINUE
            }
            _ => ServiceControlAccept::empty(),
        },
        exit_code: if failed {
            ServiceExitCode::ServiceSpecific(1)
        } else {
            ServiceExitCode::Win32(0)
        },
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    })
}
