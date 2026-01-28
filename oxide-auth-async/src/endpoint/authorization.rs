use std::{borrow::Cow, marker::PhantomData};

use oxide_auth::{
    endpoint::{WebResponse, QueryParameter, NormalizedParameter},
    code_grant::authorization::{Error as AuthorizationError, Request as AuthorizationRequest},
};

use crate::code_grant::authorization::{
    authorization_code, Endpoint as AuthorizationEndpoint, Extension, Pending,
};

use super::*;
use url::Url;

/// All relevant methods for handling authorization code requests.
pub struct AuthorizationFlow<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    endpoint: WrappedAuthorization<E, R>,
}

struct WrappedAuthorization<E: Endpoint<R>, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    inner: E,
    extension_fallback: (),
    r_type: PhantomData<R>,
}

#[derive(Clone)]
pub struct WrappedRequest<R>
where
    R: WebRequest,
{
    /// The query in the url.
    query: NormalizedParameter,

    /// An error if one occurred.
    error: Option<R::Error>,
}

struct AuthorizationPending<'a, E: 'a, R: 'a>
where
    E: Endpoint<R> + Send,
    R: WebRequest,
{
    endpoint: &'a mut WrappedAuthorization<E, R>,
    pending: Pending,
    request: R,
}

/// A processed authentication request that may be waiting for authorization by the resource owner.
///
/// Note that this borrows from the `AuthorizationFlow` used to create it. You can `finish` the
/// authorization flow for this request to produce a response or an error.
struct AuthorizationPartial<'a, E: 'a, R: 'a>
where
    E: Endpoint<R> + Send,
    R: WebRequest,
{
    inner: AuthorizationPartialInner<'a, E, R>,

    /// TODO: offer this in the public api instead of dropping the request.
    _with_request: Option<Box<dyn FnOnce(R) + Send>>,
}

/// Result type from processing an authentication request.
enum AuthorizationPartialInner<'a, E: 'a, R: 'a>
where
    E: Endpoint<R> + Send,
    R: WebRequest,
{
    /// No error happened during processing and the resource owner can decide over the grant.
    Pending {
        /// A utility struct with which the request can be decided.
        pending: Box<AuthorizationPending<'a, E, R>>,
    },

    /// The request was faulty, e.g. wrong client data, but there is a well defined response.
    Failed {
        /// The request passed in.
        request: R,

        /// Final response to the client.
        ///
        /// This should be forwarded unaltered to the client. Modifications and amendments risk
        /// deviating from the OAuth2 rfc, enabling DoS, or even leaking secrets. Modify with care.
        response: R::Response,
    },

    /// An internal error happened during the request.
    Error {
        /// The request passed in.
        request: R,

        /// Error that happened while handling the request.
        error: E::Error,
    },
}

impl<E, R> AuthorizationFlow<E, R>
where
    E: Endpoint<R> + Send + Sync,
    R: WebRequest + Send + Sync,
    <R as WebRequest>::Error: Send + Sync,
{
    /// Check that the endpoint supports the necessary operations for handling requests.
    ///
    /// Binds the endpoint to a particular type of request that it supports, for many
    /// implementations this is probably single type anyways.
    ///
    /// ## Panics
    ///
    /// Indirectly `execute` may panic when this flow is instantiated with an inconsistent
    /// endpoint, for details see the documentation of `Endpoint`. For consistent endpoints,
    /// the panic is instead caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.authorizer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        Ok(AuthorizationFlow {
            endpoint: WrappedAuthorization {
                inner: endpoint,
                extension_fallback: (),
                r_type: PhantomData,
            },
        })
    }

    /// Use the checked endpoint to execute the authorization flow for a request.
    ///
    /// In almost all cases this is followed by executing `finish` on the result but some users may
    /// instead want to inspect the partial result.
    ///
    /// ## Panics
    ///
    /// When the registrar or the authorizer returned by the endpoint is suddenly `None` when
    /// previously it was `Some(_)`.
    pub async fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let negotiated =
            authorization_code(&mut self.endpoint, &WrappedRequest::new(&mut request)).await;

        let inner = match negotiated {
            Err(err) => match authorization_error(&mut self.endpoint.inner, &mut request, err) {
                Ok(response) => AuthorizationPartialInner::Failed { request, response },
                Err(error) => AuthorizationPartialInner::Error { request, error },
            },
            Ok(negotiated) => AuthorizationPartialInner::Pending {
                pending: Box::new(AuthorizationPending {
                    endpoint: &mut self.endpoint,
                    pending: negotiated,
                    request,
                }),
            },
        };

        let partial = AuthorizationPartial {
            inner,
            _with_request: None,
        };

        partial.finish().await
    }
}

impl<'a, E, R> AuthorizationPartial<'a, E, R>
where
    E: Endpoint<R> + Send,
    R: WebRequest + Send,
{
    /// Finish the authentication step.
    ///
    /// If authorization has not yet produced a hard error or an explicit response, executes the
    /// owner solicitor of the endpoint to determine owner consent.
    pub async fn finish(self) -> Result<R::Response, E::Error> {
        let (_request, result) = match self.inner {
            AuthorizationPartialInner::Pending { pending } => pending.finish().await,
            AuthorizationPartialInner::Failed { request, response } => (request, Ok(response)),
            AuthorizationPartialInner::Error { request, error } => (request, Err(error)),
        };

        result
    }
}

fn authorization_error<E, R>(
    endpoint: &mut E, request: &mut R, error: AuthorizationError,
) -> Result<R::Response, E::Error>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    match error {
        AuthorizationError::Ignore => Err(endpoint.error(OAuthError::DenySilently)),
        AuthorizationError::Redirect(mut target) => {
            let mut response =
                endpoint.response(request, Template::new_redirect(Some(target.description())))?;
            response
                .redirect(target.into())
                .map_err(|err| endpoint.web_error(err))?;
            Ok(response)
        }
        AuthorizationError::PrimitiveError => Err(endpoint.error(OAuthError::PrimitiveError)),
    }
}

impl<'a, E, R> AuthorizationPending<'a, E, R>
where
    E: Endpoint<R> + Send,
    R: WebRequest + Send,
{
    /// Resolve the pending status using the endpoint to query owner consent.
    async fn finish(mut self) -> (R, Result<R::Response, E::Error>) {
        let checked = self
            .endpoint
            .owner_solicitor()
            .check_consent(&mut self.request, self.pending.as_solicitation())
            .await;

        match checked {
            OwnerConsent::Denied => self.deny(),
            OwnerConsent::InProgress(resp) => self.in_progress(resp),
            OwnerConsent::Authorized(who) => self.authorize(who).await,
            OwnerConsent::Error(err) => (self.request, Err(self.endpoint.inner.web_error(err))),
        }
    }

    /// Postpones the decision over the request, to display data to the resource owner.
    ///
    /// This should happen at least once for each request unless the resource owner has already
    /// acknowledged and pre-approved a specific grant.  The response can also be used to determine
    /// the resource owner, if no login has been detected or if multiple accounts are allowed to be
    /// logged in at the same time.
    fn in_progress(self, response: R::Response) -> (R, Result<R::Response, E::Error>) {
        (self.request, Ok(response))
    }

    /// Denies the request, the client is not allowed access.
    fn deny(mut self) -> (R, Result<R::Response, E::Error>) {
        let result = self.pending.deny();
        let result = Self::convert_result(result, &mut self.endpoint.inner, &mut self.request);

        (self.request, result)
    }

    /// Tells the system that the resource owner with the given id has approved the grant.
    async fn authorize(mut self, who: String) -> (R, Result<R::Response, E::Error>) {
        let result = self.pending.authorize(self.endpoint, who.into()).await;
        let result = Self::convert_result(result, &mut self.endpoint.inner, &mut self.request);

        (self.request, result)
    }

    fn convert_result(
        result: Result<Url, AuthorizationError>, endpoint: &mut E, request: &mut R,
    ) -> Result<R::Response, E::Error> {
        match result {
            Ok(url) => {
                let mut response = endpoint.response(request, Template::new_redirect(None))?;
                response.redirect(url).map_err(|err| endpoint.web_error(err))?;
                Ok(response)
            }
            Err(err) => authorization_error(endpoint, request, err),
        }
    }
}

impl<E, R> WrappedAuthorization<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    fn owner_solicitor(&mut self) -> &mut (dyn OwnerSolicitor<R> + Send) {
        self.inner.owner_solicitor().unwrap()
    }
}

impl<E, R> AuthorizationEndpoint for WrappedAuthorization<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    fn registrar(&self) -> &(dyn Registrar + Sync) {
        self.inner.registrar().unwrap()
    }

    fn authorizer(&mut self) -> &mut (dyn Authorizer + Send) {
        self.inner.authorizer_mut().unwrap()
    }

    fn extension(&mut self) -> &mut (dyn Extension + Send) {
        self.inner
            .extension()
            .and_then(super::Extension::authorization)
            .unwrap_or(&mut self.extension_fallback)
    }
}

impl<'a, R> WrappedRequest<R>
where
    R: WebRequest + 'a,
{
    pub fn new(request: &'a mut R) -> Self {
        Self::new_or_fail(request).unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R) -> Result<Self, R::Error> {
        Ok(WrappedRequest {
            query: request.query()?.into_owned(),
            error: None,
        })
    }

    fn from_err(err: R::Error) -> Self {
        WrappedRequest {
            query: Default::default(),
            error: Some(err),
        }
    }
}

impl<R> AuthorizationRequest for WrappedRequest<R>
where
    R: WebRequest,
{
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn client_id(&self) -> Option<Cow<'_, str>> {
        self.query.unique_value("client_id")
    }

    fn scope(&self) -> Option<Cow<'_, str>> {
        self.query.unique_value("scope")
    }

    fn redirect_uri(&self) -> Option<Cow<'_, str>> {
        self.query.unique_value("redirect_uri")
    }

    fn state(&self) -> Option<Cow<'_, str>> {
        self.query.unique_value("state")
    }

    fn response_type(&self) -> Option<Cow<'_, str>> {
        self.query.unique_value("response_type")
    }

    fn extension(&self, key: &str) -> Option<Cow<'_, str>> {
        self.query.unique_value(key)
    }
}
