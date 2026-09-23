mod install;
mod uninstall;

use crate::config::FirewallConfig;
use crate::mitm;
use crate::Firewall;
use rama::bytes::Bytes;
use rama::error::BoxError;
use rama::io::BridgeIo;
use rama::layer::ConsumeErrLayer;
use rama::net::apple::networkextension::ffi::tproxy::TransparentProxyInitConfig;
use rama::net::apple::networkextension::tproxy::{
    FlowAction, TransparentProxyConfig, TransparentProxyEngineBuilder, TransparentProxyFlowMeta,
    TransparentProxyHandler, TransparentProxyHandlerFactory, TransparentProxyNetworkRule,
    TransparentProxyRuleProtocol, TransparentProxyServiceContext,
};
use rama::net::apple::networkextension::{transparent_proxy_ffi, NwTcpStream, TcpFlow};
use rama::rt::Executor;
use rama::telemetry::tracing::apple::oslog::{OsLogLayer, Privacy};
use rama::{Layer, Service};
use std::convert::Infallible;
use std::sync::Arc;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const BUNDLE_ID: &str = "com.strix.firewall";
const KEYCHAIN_SERVICE: &str = BUNDLE_ID;
const KEYCHAIN_ACCOUNT: &str = "ca";

#[derive(Clone)]
struct Handler {
    ca: Arc<mitm::CertificateAuthority>,
    hosts: Vec<&'static str>,
    service: mitm::MitmService,
}

impl TransparentProxyHandler for Handler {
    // We need to peek into the ClientHello, so we have to intercept all HTTPS traffic
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        let tcp_rule = |port| {
            TransparentProxyNetworkRule::any()
                .with_remote_port(port)
                .with_protocol(TransparentProxyRuleProtocol::Tcp)
        };
        TransparentProxyConfig::new().with_rules(vec![tcp_rule(80), tcp_rule(443)])
    }

    /// The installer drives setup over this channel; an empty reply is indistinguishable
    /// from no reply on the Swift side, so every answer carries something.
    async fn handle_app_message(&self, _exec: Executor, message: Bytes) -> Option<Bytes> {
        let message = String::from_utf8_lossy(&message).into_owned();
        Some(Bytes::from(match message.as_str() {
            "ca" => self.ca.pem.clone(),
            "uninstall" => match uninstall::certificate_authority(&self.ca) {
                Ok(()) => "ok".to_owned(),
                Err(error) => format!("error: {error}"),
            },
            other => format!("error: unknown message {other}"),
        }))
    }

    async fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> FlowAction<impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>>
    {
        // A named flow reflects what the client resolved, so a non-registry name
        // can be declined unpeeked — at the cost of a client naming its own host.
        let hostname = meta.remote_hostname.as_deref();
        if hostname.is_some_and(|host| !self.hosts.contains(&host)) {
            return FlowAction::Passthrough;
        }
        let service = ConsumeErrLayer::trace_as_debug().into_layer(self.service.clone());
        FlowAction::Intercept { service, meta }
    }
}

#[derive(Clone, Copy)]
struct Factory;

impl TransparentProxyHandlerFactory for Factory {
    type Handler = Handler;
    type Error = BoxError;

    /// The engine enters its runtime only to poll, so the work belongs in the
    /// future: building it happens outside, where a spawn would panic.
    async fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> Result<Self::Handler, Self::Error> {
        handler(ctx.executor)
    }
}

fn handler(exec: Executor) -> Result<Handler, BoxError> {
    let firewall = Arc::new(Firewall::new(FirewallConfig::load()?));
    let hosts = firewall.hosts();
    let ca = Arc::new(install::certificate_authority(&hosts)?);
    let service = mitm::mitm_service(firewall, &ca, exec);
    Ok(Handler { ca, hosts, service })
}

/// stderr is invisible in a system extension, so events go to the unified log:
/// `log stream --predicate 'subsystem == "com.strix.firewall"'`.
fn init(_config: Option<&TransparentProxyInitConfig>) -> bool {
    // A panic crossing the FFI boundary aborts, and its message would go to stderr.
    std::panic::set_hook(Box::new(|panic| tracing::error!("{panic}")));
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
