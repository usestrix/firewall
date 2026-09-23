mod ca;
mod issuer;
mod route;
mod screen;

pub use ca::{CaSigner, CertificateAuthority};

use crate::Firewall;
use issuer::ConstrainedCertIssuer;
use rama::http::proxy::mitm::HttpMitmRelay;
use rama::rt::Executor;
use rama::tls::boring::proxy::cert_issuer::CachedBoringMitmCertIssuer;
use rama::tls::boring::proxy::{TlsMitmEgressServerAuth, TlsMitmRelay, TlsMitmRelayService};
use rama::tls::client::ServerVerifyMode;
use rama::tls::server::PeekTlsClientHelloService;
use rama::Layer;
use route::SniRouter;
use screen::FirewallLayer;
use std::sync::Arc;

pub type MitmService = PeekTlsClientHelloService<SniRouter<InterceptService>, RelayService>;

/// Screens decoded HTTP traffic
type RelayService = Arc<HttpMitmRelay<FirewallLayer>>;

type InterceptService =
    TlsMitmRelayService<CachedBoringMitmCertIssuer<ConstrainedCertIssuer>, RelayService>;

/// Branch on ClientHello (registries are screened, everything else is relayed)
pub fn mitm_service(
    firewall: Arc<Firewall>,
    ca: &CertificateAuthority,
    signer: CaSigner,
    exec: Executor,
) -> MitmService {
    let hosts = firewall.hosts();
    let issuer = ConstrainedCertIssuer::new(ca.crt.clone(), signer, hosts.clone());

    // Plaintext traffic relay
    let relay = Arc::new(HttpMitmRelay::new(exec).with_http_middleware(FirewallLayer { firewall }));

    // Without this the relay accepts any upstream certificate.
    let auth = TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Auto);
    let tls = TlsMitmRelay::new_with_cached_issuer(issuer).with_egress_server_auth(auth);
    let router = SniRouter::new(hosts, tls.into_layer(Arc::clone(&relay)));
    PeekTlsClientHelloService::new(router).with_fallback(relay)
}
