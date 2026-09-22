use crate::http::{blocked, https_url};
use crate::policies;
use crate::Firewall;
use rama::error::BoxError;
use rama::http::{Request, Response};
use rama::{Layer, Service};
use std::sync::Arc;
use tracing::warn;

#[derive(Clone)]
pub struct FirewallLayer {
    pub(super) firewall: Arc<Firewall>,
}

impl<S> Layer<S> for FirewallLayer {
    /// The relay clones the service it wraps, so the inner one is shared, not required to be `Clone`.
    type Service = FirewallService<Arc<S>>;

    fn layer(&self, inner: S) -> Self::Service {
        FirewallService { firewall: Arc::clone(&self.firewall), inner: Arc::new(inner) }
    }
}

#[derive(Clone)]
pub struct FirewallService<S> {
    firewall: Arc<Firewall>,
    inner: S,
}

impl<S> Service<Request> for FirewallService<S>
where
    S: Service<Request, Output = Response, Error: Into<BoxError>>,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Response, Self::Error> {
        if let Some(url) = https_url(&req) {
            if let Some(reason) = policies::screen(&url, &self.firewall).await {
                warn!(%url, "blocked by firewall: {reason}");
                return Ok(blocked(&reason));
            }
        }
        self.inner.serve(req).await.map_err(Into::into)
    }
}
