mod enclave;
mod install;
mod uninstall;

pub use uninstall::uninstall;

use crate::config::FirewallConfig;
use crate::{mitm, telemetry};
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
use rama::net::apple::networkextension::{transparent_proxy_ffi, NwTcpStream, TcpFlow};
use rama::rt::Executor;
use rama::telemetry::tracing::apple::oslog::{OsLogLayer, Privacy};
use rama::{Layer, Service};
use std::convert::Infallible;
use std::sync::Arc;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const BUNDLE_ID: &str = "com.usestrix.firewall";
const KEYCHAIN_SERVICE: &str = BUNDLE_ID;
const KEYCHAIN_ACCOUNT: &str = "ca";
/// Must match `macos/LaunchAgents/com.usestrix.firewall.env.plist`, which points npm at it.
const CA_FILE: &str = "/Library/Application Support/Firewall/ca.pem";

#[derive(Clone)]
struct Handler {
    ca: Arc<mitm::CertificateAuthority>,
    hosts: Vec<&'static str>,
    service: mitm::MitmService,
}

impl TransparentProxyHandler for Handler {
    // Claim all web traffic; what to screen is decided from the ClientHello.
    fn transparent_proxy_config(&self) -> TransparentProxyConfig {
        let tcp_rule = |port| {
            TransparentProxyNetworkRule::any()
                .with_remote_port(port)
                .with_protocol(TransparentProxyRuleProtocol::Tcp)
        };
        TransparentProxyConfig::new().with_rules(vec![tcp_rule(80), tcp_rule(443)])
    }

    /// Setup requests from the app. Never empty: Swift cannot tell that from no reply.
    async fn handle_app_message(&self, _exec: Executor, message: Bytes) -> Option<Bytes> {
        let message = String::from_utf8_lossy(&message).into_owned();
        Some(Bytes::from(match message.as_str() {
            "ca" => self.ca.pem.clone(),
            other => format!("error: unknown message {other}"),
        }))
    }

    async fn match_tcp_flow(
        &self,
        _exec: Executor,
        meta: TransparentProxyFlowMeta,
    ) -> FlowAction<impl Service<BridgeIo<TcpFlow, NwTcpStream>, Output = (), Error = Infallible>>
    {
        // Skip peeking when the client's own hostname is not a registry; it could misreport it.
        let hostname = meta.remote_hostname.as_deref();
        let registry = |host: &str| self.hosts.iter().any(|h| Domain::from_static(h) == host);
        if hostname.is_some_and(|host| !registry(host)) {
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

    /// Build inside the future: spawning outside the engine's runtime panics.
    async fn create_transparent_proxy_handler(
        &self,
        ctx: TransparentProxyServiceContext,
    ) -> Result<Self::Handler, Self::Error> {
        let handler = handler(ctx.executor);
        if handler.is_err() {
            telemetry::send().await;
        }
        handler
    }
}

fn handler(exec: Executor) -> Result<Handler, BoxError> {
    telemetry::set_mode("extension");
    telemetry::heartbeat();
    let config = FirewallConfig::load().inspect_err(|_| telemetry::error("config"))?;
    let firewall = Arc::new(Firewall::new(config));
    let hosts = firewall.hosts();
    let key = enclave::EnclaveKey::load_or_create().inspect_err(|_| telemetry::error("enclave"))?;
    let signer: mitm::CaSigner = Arc::new(key);
    let ca = install::certificate_authority(&hosts, &*signer);
    let ca = Arc::new(ca.inspect_err(|_| telemetry::error("ca"))?);
    let service = mitm::mitm_service(firewall, &ca, signer, None, exec);
    Ok(Handler { ca, hosts, service })
}

/// stderr is invisible in a system extension, so events go to the unified log:
/// `log stream --predicate 'subsystem == "com.usestrix.firewall"'`.
fn init(_config: Option<&TransparentProxyInitConfig>) -> bool {
    // A panic crossing the FFI boundary aborts, and its message would go to stderr.
    std::panic::set_hook(Box::new(|panic| tracing::error!("{panic}")));
    if let Ok(oslog) = OsLogLayer::new(BUNDLE_ID, "extension") {
        let oslog = oslog.with_privacy(Privacy::Public);
        let _ = tracing_subscriber::registry().with(crate::log_filter("info")).with(oslog).try_init();
    }
    true
}

transparent_proxy_ffi! {
    init = init,
    engine_builder = TransparentProxyEngineBuilder::new(Factory),
}
