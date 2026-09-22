mod ca;
mod issuer;
mod screen;

pub use ca::CertificateAuthority;

use crate::Firewall;
use issuer::ConstrainedCertIssuer;
use rama::http::proxy::mitm::HttpMitmRelay;
use rama::rt::Executor;
use rama::tls::boring::proxy::cert_issuer::CachedBoringMitmCertIssuer;
use rama::tls::boring::proxy::{TlsMitmEgressServerAuth, TlsMitmRelay, TlsMitmRelayService};
use rama::tls::client::ServerVerifyMode;
use rama::tls::server::PeekTlsClientHelloService;
use rama::Layer;
use screen::FirewallLayer;
use std::sync::Arc;

pub type MitmService = PeekTlsClientHelloService<InterceptService, RelayService>;

/// Screens and relays plaintext requests
type RelayService = Arc<HttpMitmRelay<FirewallLayer>>;

type InterceptService =
    TlsMitmRelayService<CachedBoringMitmCertIssuer<ConstrainedCertIssuer>, RelayService>;

/// We only claim flows headed for a registry, so every one of them is screened:
/// TLS gets terminated first, plaintext goes straight to the relay.
pub fn mitm_service(
    firewall: Arc<Firewall>,
    ca: &CertificateAuthority,
    exec: Executor,
) -> MitmService {
    let issuer = ConstrainedCertIssuer::new(ca.crt.clone(), ca.key.clone(), firewall.hosts());

    // Plaintext traffic relay
    let relay = Arc::new(HttpMitmRelay::new(exec).with_http_middleware(FirewallLayer { firewall }));

    // Without this the relay accepts any upstream certificate.
    let auth = TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Auto);
    let tls = TlsMitmRelay::new_with_cached_issuer(issuer).with_egress_server_auth(auth);
    PeekTlsClientHelloService::new(tls.into_layer(Arc::clone(&relay))).with_fallback(relay)
}
