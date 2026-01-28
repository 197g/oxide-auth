use crate::code_grant::authorization::{
    authorization_code, Error as AuthorizationError, Extension, Endpoint as AuthorizationEndpoint,
    Request as AuthorizationRequest, Pending,
};

use super::*;

/// All relevant methods for handling authorization code requests.
pub struct AuthorizationFlow<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    endpoint: WrappedAuthorization<E, R>,
}

struct WrappedAuthorization<E: Endpoint<R>, R: WebRequest> {
    inner: E,
    extension_fallback: (),
    r_type: PhantomData<R>,
}

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The query in the url.
    query: Cow<'a, dyn QueryParameter + 'static>,

    /// An error if one occurred.
    error: Option<R::Error>,
}

struct AuthorizationPending<'a, E: 'a, R: 'a>
where
    E: Endpoint<R>,
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
    E: Endpoint<R>,
    R: WebRequest,
{
    inner: AuthorizationPartialInner<'a, E, R>,
}

/// Result type from processing an authentication request.
enum AuthorizationPartialInner<'a, E: 'a, R: 'a>
where
    E: Endpoint<R>,
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
    E: Endpoint<R>,
    R: WebRequest,
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
    pub fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let negotiated = authorization_code(&mut self.endpoint, &WrappedRequest::new(&mut request));

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

        let partial = AuthorizationPartial { inner };

        partial.finish()
    }
}

impl<'a, E: Endpoint<R>, R: WebRequest> AuthorizationPartial<'a, E, R> {
    /// Finish the authentication step.
    ///
    /// If authorization has not yet produced a hard error or an explicit response, executes the
    /// owner solicitor of the endpoint to determine owner consent.
    pub fn finish(self) -> Result<R::Response, E::Error> {
        let (_request, result) = match self.inner {
            AuthorizationPartialInner::Pending { pending } => pending.finish(),
            AuthorizationPartialInner::Failed { request, response } => (request, Ok(response)),
            AuthorizationPartialInner::Error { request, error } => (request, Err(error)),
        };

        result
    }
}

fn authorization_error<E: Endpoint<R>, R: WebRequest>(
    endpoint: &mut E, request: &mut R, error: AuthorizationError,
) -> Result<R::Response, E::Error> {
    match error {
        AuthorizationError::Ignore => Err(endpoint.error(OAuthError::DenySilently)),
        AuthorizationError::Redirect(mut target) => {
            let mut response = endpoint.response(
                request,
                InnerTemplate::Redirect {
                    authorization_error: Some(target.description()),
                }
                .into(),
            )?;
            response
                .redirect(target.into())
                .map_err(|err| endpoint.web_error(err))?;
            Ok(response)
        }
        AuthorizationError::PrimitiveError => Err(endpoint.error(OAuthError::PrimitiveError)),
    }
}

impl<'a, E: Endpoint<R>, R: WebRequest> AuthorizationPending<'a, E, R> {
    /// Resolve the pending status using the endpoint to query owner consent.
    fn finish(mut self) -> (R, Result<R::Response, E::Error>) {
        let checked = self
            .endpoint
            .owner_solicitor()
            .check_consent(&mut self.request, self.pending.as_solicitation());

        match checked {
            OwnerConsent::Denied => self.deny(),
            OwnerConsent::InProgress(resp) => self.in_progress(resp),
            OwnerConsent::Authorized(who) => self.authorize(who),
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
    fn authorize(mut self, who: String) -> (R, Result<R::Response, E::Error>) {
        let result = self.pending.authorize(self.endpoint, who.into());
        let result = Self::convert_result(result, &mut self.endpoint.inner, &mut self.request);

        (self.request, result)
    }

    fn convert_result(
        result: Result<Url, AuthorizationError>, endpoint: &mut E, request: &mut R,
    ) -> Result<R::Response, E::Error> {
        match result {
            Ok(url) => {
                let mut response = endpoint.response(
                    request,
                    InnerTemplate::Redirect {
                        authorization_error: None,
                    }
                    .into(),
                )?;
                response.redirect(url).map_err(|err| endpoint.web_error(err))?;
                Ok(response)
            }
            Err(err) => authorization_error(endpoint, request, err),
        }
    }
}

impl<E: Endpoint<R>, R: WebRequest> WrappedAuthorization<E, R> {
    fn owner_solicitor(&mut self) -> &mut dyn OwnerSolicitor<R> {
        self.inner.owner_solicitor().unwrap()
    }
}

impl<E: Endpoint<R>, R: WebRequest> AuthorizationEndpoint for WrappedAuthorization<E, R> {
    fn registrar(&self) -> &dyn Registrar {
        self.inner.registrar().unwrap()
    }

    fn authorizer(&mut self) -> &mut dyn Authorizer {
        self.inner.authorizer_mut().unwrap()
    }

    fn extension(&mut self) -> &mut dyn Extension {
        self.inner
            .extension()
            .and_then(super::Extension::authorization)
            .unwrap_or(&mut self.extension_fallback)
    }
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    pub fn new(request: &'a mut R) -> Self {
        Self::new_or_fail(request).unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R) -> Result<Self, R::Error> {
        Ok(WrappedRequest {
            request: PhantomData,
            query: request.query()?,
            error: None,
        })
    }

    fn from_err(err: R::Error) -> Self {
        WrappedRequest {
            request: PhantomData,
            query: Cow::Owned(Default::default()),
            error: Some(err),
        }
    }
}

impl<'a, R: WebRequest + 'a> AuthorizationRequest for WrappedRequest<'a, R> {
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
