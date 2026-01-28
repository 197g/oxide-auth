//! Async versions of all primitives traits.
use async_trait::async_trait;
use oxide_auth::OAuthOpaqueError;
use oxide_auth::primitives::{grant::Grant, scope::Scope};
use oxide_auth::primitives::issuer::{IssuedToken, RefreshedToken};
use oxide_auth::primitives::{
    authorizer, registrar, issuer,
    registrar::{ClientUrl, BoundClient, RegistrarError, PreGrant},
};

#[async_trait]
pub trait Authorizer {
    async fn authorize(&mut self, _: Grant) -> Result<String, OAuthOpaqueError>;

    async fn extract(&mut self, _: &str) -> Result<Option<Grant>, OAuthOpaqueError>;
}

#[async_trait]
impl<T> Authorizer for T
where
    T: authorizer::Authorizer + Send + ?Sized,
{
    async fn authorize(&mut self, grant: Grant) -> Result<String, OAuthOpaqueError> {
        authorizer::Authorizer::authorize(self, grant)
    }

    async fn extract(&mut self, token: &str) -> Result<Option<Grant>, OAuthOpaqueError> {
        authorizer::Authorizer::extract(self, token)
    }
}

#[async_trait]
pub trait Issuer {
    async fn issue(&mut self, _: Grant) -> Result<IssuedToken, OAuthOpaqueError>;

    async fn refresh(&mut self, _: &str, _: Grant) -> Result<RefreshedToken, OAuthOpaqueError>;

    async fn recover_token(&mut self, _: &str) -> Result<Option<Grant>, OAuthOpaqueError>;

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, OAuthOpaqueError>;
}

#[async_trait]
impl<T> Issuer for T
where
    T: issuer::Issuer + Send + ?Sized,
{
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, OAuthOpaqueError> {
        issuer::Issuer::issue(self, grant)
    }

    async fn refresh(&mut self, token: &str, grant: Grant) -> Result<RefreshedToken, OAuthOpaqueError> {
        issuer::Issuer::refresh(self, token, grant)
    }

    async fn recover_token(&mut self, token: &str) -> Result<Option<Grant>, OAuthOpaqueError> {
        issuer::Issuer::recover_token(self, token)
    }

    async fn recover_refresh(&mut self, token: &str) -> Result<Option<Grant>, OAuthOpaqueError> {
        issuer::Issuer::recover_refresh(self, token)
    }
}

#[async_trait]
pub trait Registrar {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError>;

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError>;

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError>;
}

#[async_trait]
impl<T> Registrar for T
where
    T: registrar::Registrar + Send + Sync + ?Sized,
{
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        registrar::Registrar::bound_redirect(self, bound)
    }

    async fn negotiate<'a>(
        &self, client: BoundClient<'a>, scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        registrar::Registrar::negotiate(self, client, scope)
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        registrar::Registrar::check(self, client_id, passphrase)
    }
}
