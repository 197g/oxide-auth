use async_trait::async_trait;
use crate::{OAuthRequest, OAuthResponse, OAuthOperation, WebError};
use oxide_auth::primitives::grant::Grant;
use oxide_auth_async::{
    endpoint::{
        Endpoint, access_token::AccessTokenFlow, authorization::AuthorizationFlow,
        resource::ResourceFlow, refresh::RefreshFlow,
    },
};

/// Authorization-related operations
pub struct Authorize(pub OAuthRequest);

#[async_trait]
impl OAuthOperation for Authorize {
    type Item = OAuthResponse;
    type Error = WebError;

    async fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest> + Send + Sync,
        E::Error: Send,
        WebError: From<E::Error>,
    {
        AuthorizationFlow::prepare(endpoint)?
            .execute(self.0)
            .await
            .map_err(WebError::from)
    }
}

/// Token-related operations
pub struct Token(pub OAuthRequest);

#[async_trait]
impl OAuthOperation for Token {
    type Item = OAuthResponse;
    type Error = WebError;

    async fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest> + Send + Sync,
        E::Error: Send,
        WebError: From<E::Error>,
    {
        AccessTokenFlow::prepare(endpoint)?
            .execute(self.0)
            .await
            .map_err(WebError::from)
    }
}

/// Refresh-related operations
pub struct Refresh(pub OAuthRequest);

#[async_trait]
impl OAuthOperation for Refresh {
    type Item = OAuthResponse;
    type Error = WebError;

    async fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest> + Send + Sync,
        E::Error: Send,
        WebError: From<E::Error>,
    {
        RefreshFlow::prepare(endpoint)?
            .execute(self.0)
            .await
            .map_err(WebError::from)
    }
}

/// Resource-related operations
pub struct Resource(pub OAuthRequest);

#[async_trait]
impl OAuthOperation for Resource {
    type Item = Grant;
    type Error = Result<OAuthResponse, WebError>;

    async fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest> + Send + Sync,
        E::Error: Send,
        WebError: From<E::Error>,
    {
        ResourceFlow::prepare(endpoint)
            .map_err(|e| Err(WebError::from(e)))?
            .execute(self.0)
            .await
            .map_err(|r| r.map_err(WebError::from))
    }
}
