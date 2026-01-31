use async_trait::async_trait;
use oxide_auth::{
    endpoint::{Scopes, WebRequest, Template, OAuthError, OwnerConsent, Solicitation},
    frontends::simple::endpoint::Error,
    primitives::scope::Scope,
};

use crate::{
    endpoint::{
        Extension, Endpoint, OwnerSolicitor, access_token::AccessTokenFlow,
        authorization::AuthorizationFlow, refresh::RefreshFlow, resource::ResourceFlow,
    },
    primitives::{Registrar, Authorizer, Issuer},
};

use std::marker::PhantomData;

pub struct Generic<
    R: Send + Sync,
    A: Send + Sync,
    I: Send + Sync,
    S: Send + Sync = Vacant,
    C: Send + Sync = Vacant,
    L: Send + Sync = Vacant,
> {
    /// The registrar implementation, or `Vacant` if it is not necesary.
    pub registrar: R,

    /// The authorizer implementation, or `Vacant` if it is not necesary.
    pub authorizer: A,

    /// The issuer implementation, or `Vacant` if it is not necesary.
    pub issuer: I,

    /// A solicitor implementation fit for the request types, or `Vacant` if it is not necesary.
    pub solicitor: S,

    /// Determine scopes for the request types, or `Vacant` if this does not protect resources.
    pub scopes: C,

    /// Creates responses, or `Vacant` if `Default::default` is applicable.
    pub response: L,
}

pub struct ErrorInto<E, Error>(E, PhantomData<Error>);

impl<E, Error> ErrorInto<E, Error> {
    /// Create a new ErrorInto wrapping the supplied endpoint.
    pub fn new(endpoint: E) -> Self {
        ErrorInto(endpoint, PhantomData)
    }
}

pub struct Vacant;

pub struct FnSolicitor<F>(pub F);

impl<R: Send + Sync, A: Send + Sync, I: Send + Sync, O: Send + Sync, C: Send + Sync, L: Send + Sync>
    Generic<R, A, I, O, C, L>
{
    pub fn with_solicitor<N: Send + Sync>(self, new_solicitor: N) -> Generic<R, A, I, N, C, L> {
        Generic {
            registrar: self.registrar,
            authorizer: self.authorizer,
            issuer: self.issuer,
            solicitor: new_solicitor,
            scopes: self.scopes,
            response: self.response,
        }
    }

    pub fn with_scopes<S: Send + Sync>(self, new_scopes: S) -> Generic<R, A, I, O, S, L> {
        Generic {
            registrar: self.registrar,
            authorizer: self.authorizer,
            issuer: self.issuer,
            solicitor: self.solicitor,
            scopes: new_scopes,
            response: self.response,
        }
    }

    pub fn authorization_flow<W: WebRequest + Send + Sync>(self) -> AuthorizationFlow<Self, W>
    where
        Self: Endpoint<W>,
        W::Error: Send + Sync,
        R: Registrar,
        A: Authorizer,
    {
        match AuthorizationFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    pub fn access_token_flow<W: WebRequest + Send + Sync>(self) -> AccessTokenFlow<Self, W>
    where
        Self: Endpoint<W>,
        W::Error: Send + Sync,
        R: Registrar,
        A: Authorizer,
        I: Issuer,
    {
        match AccessTokenFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    /// Create a token refresh flow.
    ///
    /// Opposed to `RefreshFlow::prepare` this statically ensures that the construction succeeds.
    pub fn refresh_flow<W: WebRequest + Send + Sync>(self) -> RefreshFlow<Self, W>
    where
        Self: Endpoint<W>,
        W::Error: Send + Sync,
        R: Registrar,
        I: Issuer,
    {
        match RefreshFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    /// Create a resource access flow.
    ///
    /// Opposed to `ResourceFlow::prepare` this statically ensures that the construction succeeds.
    pub fn resource_flow<W: WebRequest + Send + Sync>(self) -> ResourceFlow<Self, W>
    where
        Self: Endpoint<W>,
        W::Error: Send + Sync,
        I: Issuer,
    {
        match ResourceFlow::prepare(self) {
            Ok(flow) => flow,
            Err(_) => unreachable!(),
        }
    }

    /// Check, statically, that this is an endpoint for some request.
    ///
    /// This is mainly a utility method intended for compilation and integration tests.
    pub fn assert<W: WebRequest>(self) -> Self
    where
        Self: Endpoint<W>,
    {
        self
    }
}

#[async_trait]
impl<E, Error, W> Endpoint<W> for ErrorInto<E, Error>
where
    E: Endpoint<W>,
    E::Error: Into<Error>,
    W: WebRequest,
{
    type Error = Error;

    fn registrar(&self) -> Option<&(dyn Registrar + Sync)> {
        self.0.registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        self.0.authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut (dyn Issuer + Send)> {
        self.0.issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<W> + Send)> {
        self.0.owner_solicitor()
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<W>> {
        self.0.scopes()
    }

    fn response(&mut self, request: &mut W, kind: Template<'_>) -> Result<W::Response, Self::Error> {
        self.0.response(request, kind).map_err(Into::into)
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        self.0.error(err).into()
    }

    fn web_error(&mut self, err: W::Error) -> Self::Error {
        self.0.web_error(err).into()
    }

    fn extension(&mut self) -> Option<&mut (dyn Extension + Send)> {
        self.0.extension()
    }
}

pub trait OptRegistrar {
    fn opt_ref(&self) -> Option<&(dyn Registrar + Sync)>;
}

impl<T: Registrar + Sync> OptRegistrar for T {
    fn opt_ref(&self) -> Option<&(dyn Registrar + Sync)> {
        Some(self)
    }
}

impl OptRegistrar for Vacant {
    fn opt_ref(&self) -> Option<&(dyn Registrar + Sync)> {
        Option::None
    }
}

pub trait OptAuthorizer {
    fn opt_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)>;
}

impl<T: Authorizer + Send> OptAuthorizer for T {
    fn opt_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        Some(self)
    }
}

impl OptAuthorizer for Vacant {
    fn opt_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        Option::None
    }
}

pub trait OptIssuer {
    fn opt_mut(&mut self) -> Option<&mut (dyn Issuer + Send)>;
}

impl<T: Issuer + Send> OptIssuer for T {
    fn opt_mut(&mut self) -> Option<&mut (dyn Issuer + Send)> {
        Some(self)
    }
}

impl OptIssuer for Vacant {
    fn opt_mut(&mut self) -> Option<&mut (dyn Issuer + Send)> {
        Option::None
    }
}

pub trait ResponseCreator<W: WebRequest> {
    fn create(&mut self, request: &mut W, kind: Template) -> W::Response;
}

impl<W: WebRequest, F> ResponseCreator<W> for F
where
    F: FnMut() -> W::Response,
{
    fn create(&mut self, _: &mut W, _: Template) -> W::Response {
        self()
    }
}

impl<W: WebRequest> ResponseCreator<W> for Vacant
where
    W::Response: Default,
{
    fn create(&mut self, _: &mut W, _: Template) -> W::Response {
        Default::default()
    }
}

impl<
        W: Send + Sync,
        R: Send + Sync,
        A: Send + Sync,
        I: Send + Sync,
        O: Send + Sync,
        C: Send + Sync,
        L: Send + Sync,
    > Endpoint<W> for Generic<R, A, I, O, C, L>
where
    W: WebRequest,
    R: OptRegistrar,
    A: OptAuthorizer,
    I: OptIssuer,
    O: OwnerSolicitor<W>,
    C: Scopes<W>,
    L: ResponseCreator<W>,
{
    type Error = Error<W>;

    fn registrar(&self) -> Option<&(dyn Registrar + Sync)> {
        self.registrar.opt_ref()
    }

    fn authorizer_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        self.authorizer.opt_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut (dyn Issuer + Send)> {
        self.issuer.opt_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<W> + Send)> {
        Some(&mut self.solicitor)
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<W>> {
        Some(&mut self.scopes)
    }

    fn response(&mut self, request: &mut W, kind: Template) -> Result<W::Response, Self::Error> {
        Ok(self.response.create(request, kind))
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        Error::OAuth(err)
    }

    fn web_error(&mut self, err: W::Error) -> Self::Error {
        Error::Web(err)
    }
}
