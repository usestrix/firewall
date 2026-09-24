use rama::error::BoxError;
use rama::io::{BridgeIo, Io};
use rama::tls::server::InputWithClientHello;
use rama::Service;
use std::sync::Arc;
use tokio::io::copy_bidirectional;

/// The CA is name-constrained to the registries, so any other ClientHello must be copied through.
#[derive(Clone)]
pub struct SniRouter<S> {
    hosts: Arc<Vec<&'static str>>,
    intercept: S,
}

impl<S> SniRouter<S> {
    pub(super) fn new(hosts: Vec<&'static str>, intercept: S) -> Self {
        Self { hosts: Arc::new(hosts), intercept }
    }
}

impl<S, Ingress, Egress> Service<InputWithClientHello<BridgeIo<Ingress, Egress>>> for SniRouter<S>
where
    S: Service<InputWithClientHello<BridgeIo<Ingress, Egress>>, Output = (), Error: Into<BoxError>>,
    Ingress: Io + Unpin,
    Egress: Io + Unpin,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        input: InputWithClientHello<BridgeIo<Ingress, Egress>>,
    ) -> Result<(), Self::Error> {
        let server_name = input.client_hello.ext_server_name();
        let screened = server_name.is_some_and(|name| self.hosts.iter().any(|host| name == host));
        let server_name = server_name.map(tracing::field::display);
        if screened {
            tracing::debug!(server_name, "terminating TLS for a screened registry");
            return self.intercept.serve(input).await.map_err(Into::into);
        }
        tracing::debug!(server_name, "splicing, not a screened registry");
        let BridgeIo(mut ingress, mut egress) = input.input;
        let (from_client, from_server) = copy_bidirectional(&mut ingress, &mut egress).await?;
        tracing::debug!(from_client, from_server, "spliced flow closed");
        Ok(())
    }
}
