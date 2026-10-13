use super::ca::{certificate_authority, data_dir_ready};
use super::tpm::TpmKey;
use super::{redirects, write_hosts, CRL_ADDRESS, SERVICE_NAME};
use crate::config::FirewallConfig;
use crate::http::{reply, text};
use crate::{mitm, telemetry, Firewall};
use rama::dns::client::hickory::resolver::config::ResolveHosts;
use rama::dns::client::hickory::{default_resolver_opts, HickoryDnsResolver};
use rama::dns::client::resolver::DnsAddressResolver;
use rama::dns::client::try_init_global_dns_resolver;
use rama::error::BoxError;
use rama::http::server::HttpServer;
use rama::http::Request;
use rama::io::BridgeIo;
use rama::layer::ConsumeErrLayer;
use rama::net::address::Domain;
use rama::rt::Executor;
use rama::service::service_fn;
use rama::tcp::server::TcpListener;
use rama::tcp::TcpStream;
use rama::{Layer, Service};
use std::convert::Infallible;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_service::service::*;
use windows_service::service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

/// Called by the service control manager, never by hand.
pub fn run() -> windows_service::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// stderr goes nowhere in a service, so events go to a file beside the CA.
fn service_main(_arguments: Vec<OsString>) {
    let log = data_dir_ready()
        .and_then(|dir| std::fs::File::options().create(true).append(true).open(dir.join("firewall.log")));
    if let Ok(file) = log {
        let filter = crate::log_filter("info");
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_ansi(false).with_writer(Mutex::new(file)).try_init();
    }
    std::panic::set_hook(Box::new(|panic| tracing::error!("{panic}")));
    if let Err(error) = serve() {
        tracing::error!(%error, "the service stopped");
    }
}

fn serve() -> Result<(), BoxError> {
    let (controls, mut received) = tokio::sync::mpsc::unbounded_channel();
    let status = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Pause | ServiceControl::Continue => {
            let _ = controls.send(control);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    report(&status, ServiceState::StartPending, false)?;
    let served = crate::runtime()?.block_on(async {
        let hosts = match listen(&status).await {
            Ok(hosts) => hosts,
            Err(error) => {
                telemetry::send().await;
                return Err(error);
            }
        };
        // Only pausing lifts the block; a stop or crash keeps it, so traffic fails closed.
        while let Some(control) = received.recv().await {
            let (hosts, state) = match control {
                ServiceControl::Pause => (&[][..], ServiceState::Paused),
                ServiceControl::Continue => (&hosts[..], ServiceState::Running),
                _ => break,
            };
            match write_hosts(hosts) {
                Ok(()) => report(&status, state, false)?,
                Err(error) => tracing::error!(%error, "could not rewrite the hosts file"),
            }
        }
        Ok::<_, BoxError>(())
    });
    // A failed stop is what makes the service manager restart it.
    report(&status, ServiceState::Stopped, served.is_err())?;
    served
}

async fn listen(status: &ServiceStatusHandle) -> Result<Vec<&'static str>, BoxError> {
    telemetry::heartbeat();
    // Never the hosts file, which points back at us; the Firewall's lookups included.
    let mut options = default_resolver_opts();
    options.use_hosts_file = ResolveHosts::Never;
    let resolver = HickoryDnsResolver::try_new_system_with_options(options)?;
    let _ = try_init_global_dns_resolver(resolver.clone());
    let config = FirewallConfig::load().inspect_err(|_| telemetry::error("config"))?;
    let firewall = Arc::new(Firewall::new(config));
    let hosts = firewall.hosts();
    let key = TpmKey::load_or_create().inspect_err(|_| telemetry::error("tpm"))?;
    let signer: mitm::CaSigner = Arc::new(key);
    let ca = certificate_authority(&hosts, &*signer).inspect_err(|_| telemetry::error("ca"))?;
    let exec = Executor::default();

    // An empty CRL for the leaves to point at, signed fresh for each fetch.
    let (crl_hosts, crl_signer) = (hosts.clone(), Arc::clone(&signer));
    let crl = HttpServer::auto(exec.clone()).service(service_fn(move |req: Request| {
        let crl = match &*req.uri().request_target() {
            "/ca.crl" => mitm::crl(&crl_hosts, &*crl_signer).map(|der| reply(200, "application/pkix-crl", der)),
            _ => Ok(text(404, "No route.\n")),
        };
        async move { Ok::<_, Infallible>(crl.unwrap_or_else(|error| text(503, &format!("{error}\n")))) }
    }));
    tokio::spawn(bind(CRL_ADDRESS, 80, &exec)?.serve(crl));

    let crl_url = format!("http://{CRL_ADDRESS}/ca.crl");
    let service = mitm::mitm_service(firewall, &ca, signer, Some(crl_url), exec.clone());
    for (address, host) in redirects(&hosts) {
        for port in [80, 443] {
            let upstream = Upstream { host, port, resolver: resolver.clone(), service: service.clone() };
            let upstream = ConsumeErrLayer::trace_as_debug().into_layer(upstream);
            tokio::spawn(bind(address, port, &exec)?.serve(upstream));
        }
    }
    // Rewritten on every start, so a restart picks up a changed host list.
    write_hosts(&hosts)?;
    tracing::info!(?hosts, "screening registry traffic redirected by the hosts file");
    report(status, ServiceState::Running, false)?;
    Ok(hosts)
}

fn bind(address: Ipv4Addr, port: u16, exec: &Executor) -> std::io::Result<TcpListener> {
    let bound = std::net::TcpListener::bind((address, port))?;
    bound.set_nonblocking(true)?;
    TcpListener::try_from_std_tcp_listener(bound, exec.clone())
}

/// Each listener is bound to one host's address, which is how it knows where to connect.
#[derive(Clone)]
struct Upstream {
    host: &'static str,
    port: u16,
    resolver: HickoryDnsResolver,
    service: mitm::MitmService,
}

impl Service<TcpStream> for Upstream {
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, ingress: TcpStream) -> Result<(), BoxError> {
        let domain = Domain::from_static(self.host);
        let address: IpAddr = match self.resolver.lookup_ipv4_first(domain.clone()).await {
            Some(Ok(v4)) => v4.into(),
            _ => self.resolver.lookup_ipv6_first(domain).await.ok_or(self.host)??.into(),
        };
        let egress = tokio::net::TcpStream::connect((address, self.port)).await?;
        self.service.serve(BridgeIo(ingress, TcpStream::from(egress))).await
    }
}

fn report(status: &ServiceStatusHandle, state: ServiceState, failed: bool) -> windows_service::Result<()> {
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: match state {
            ServiceState::Running | ServiceState::Paused => {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::PAUSE_CONTINUE
            }
            _ => ServiceControlAccept::empty(),
        },
        exit_code: if failed { ServiceExitCode::ServiceSpecific(1) } else { ServiceExitCode::Win32(0) },
        checkpoint: 0,
        wait_hint: Duration::from_secs(30),
        process_id: None,
    })
}
