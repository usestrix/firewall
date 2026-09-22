use crate::config::FirewallConfig;
use crate::mitm;
use crate::Firewall;
use rama::bytes::Bytes;
use rama::error::BoxError;
use rama::io::BridgeIo;
use rama::layer::ConsumeErrLayer;
use rama::net::address::Domain;
use rama::net::apple::networkextension::ffi::tproxy::TransparentProxyInitConfig;
use rama::net::apple::networkextension::tproxy::{
    FlowAction, TransparentProxyConfig, TransparentProxyEngineBuilder, TransparentProxyFlowMeta,
    TransparentProxyHandler, TransparentProxyHandlerFactory, TransparentProxyNetworkRule,
    TransparentProxyRuleProtocol, TransparentProxyServiceContext,
};
use rama::net::apple::networkextension::{
    system_keychain, transparent_proxy_ffi, NwTcpStream, TcpFlow,
};
use rama::rt::Executor;
use rama::telemetry::tracing::apple::oslog::{OsLogLayer, Privacy};
use rama::{Layer, Service};
use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const BUNDLE_ID: &str = "com.strix.firewall";
const KEYCHAIN_ACCOUNT: &str = "ca";

#[derive(Clone)]
struct Handler {
    ca: Arc<mitm::CertificateAuthority>,
    hosts: Vec<&'static str>,
    service: mitm::MitmService,
}

impl TransparentProxyHandler for Handler {
    /// Claim only the registries we screen; every other flow stays in the kernel.
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        let mut rules = Vec::with_capacity(self.hosts.len() * 2);
        for host in &self.hosts {
            // Plaintext installs are screened as well, so port 80 is claimed too.
            for port in [80, 443] {
                rules.push(
                    TransparentProxyNetworkRule::any()
                        .with_remote_network(Domain::from_static(host))
                        .with_remote_port(port)
                        .with_protocol(TransparentProxyRuleProtocol::Tcp),
                );
            }
        }
        TransparentProxyConfig::new().with_rules(rules)
    }

    /// The installer asks for the CA over this channel; nothing else is served.
    fn handle_app_message(
        &self,
        _exec: Executor,
        _message: Bytes,
    ) -> impl Future<Output = Option<Bytes>> + Send + '_ {
        std::future::ready(Some(Bytes::from(self.ca.pem.clone())))
    }

    fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> impl Future<
        Output = FlowAction<
            impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>,
        >,
    > + Send
           + '_ {
        let service = ConsumeErrLayer::trace_as_debug().into_layer(self.service.clone());
        std::future::ready(FlowAction::Intercept { service, meta })
    }
}

#[derive(Clone, Copy)]
struct Factory;

impl TransparentProxyHandlerFactory for Factory {
    type Handler = Handler;
    type Error = BoxError;

    fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> impl Future<Output = Result<Self::Handler, Self::Error>> + Send {
        std::future::ready(handler(ctx.executor.clone()))
    }
}

/// Trust is installed once, so the CA is re-minted only when the screened hosts change.
fn load_or_mint(hosts: &[&str]) -> Result<mitm::CertificateAuthority, BoxError> {
    if let Some(blob) = system_keychain::load_secret(BUNDLE_ID, KEYCHAIN_ACCOUNT)? {
        let stored = std::str::from_utf8(&blob).ok();
        match stored.and_then(|b| mitm::CertificateAuthority::from_blob(b, hosts)) {
            Some(ca) => {
                info!(?hosts, "restored the CA from the system keychain");
                return Ok(ca);
            }
            None => warn!("stored CA does not match the screened hosts, minting a new one"),
        }
    }
    let ca = mitm::CertificateAuthority::generate(hosts)?;
    system_keychain::store_secret(BUNDLE_ID, KEYCHAIN_ACCOUNT, ca.to_blob().as_bytes())?;
    info!(?hosts, "minted a name-constrained CA");
    Ok(ca)
}

fn handler(exec: Executor) -> Result<Handler, BoxError> {
    let firewall = Arc::new(Firewall::new(FirewallConfig::load()?));
    let hosts = firewall.hosts();
    let ca = Arc::new(load_or_mint(&hosts)?);
    let service = mitm::mitm_service(firewall, &ca, exec);
    Ok(Handler { ca, hosts, service })
}

/// stderr is invisible in a system extension, so events go to the unified log:
/// `log stream --predicate 'subsystem == "com.strix.firewall"'`.
fn init(_config: Option<&TransparentProxyInitConfig>) -> bool {
    if let Ok(oslog) = OsLogLayer::new(BUNDLE_ID, "extension") {
        let oslog = oslog.with_privacy(Privacy::Public);
        let _ = tracing_subscriber::registry().with(crate::log_filter()).with(oslog).try_init();
    }
    true
}

transparent_proxy_ffi! {
    init = init,
    engine_builder = TransparentProxyEngineBuilder::new(Factory),
}
