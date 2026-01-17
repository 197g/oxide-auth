use std::borrow::Cow;
use std::str::from_utf8;
use std::marker::PhantomData;

use base64::{engine::general_purpose::STANDARD, Engine};
use oxide_auth::{
    endpoint::{
        NormalizedParameter, QueryParameter, WebResponse, WebRequest, Template, is_authorization_method,
    },
    code_grant::{
        accesstoken::ErrorDescription,
        client_credentials::{Error as ClientCredentialsError, Request as ClientCredentialsRequest},
        error::{AccessTokenError, AccessTokenErrorType},
    },
};

use super::{Endpoint, OAuthError, OwnerConsent};
use crate::{
    primitives::{Issuer, Registrar, Authorizer},
    code_grant::client_credentials::{
        Extension, client_credentials, Endpoint as ClientCredentialsEndpoint,
    },
};

/// Offers access tokens to authenticated third parties.
///
/// A client may request a token that provides access to their own resources.
///
/// Client credentials can be allowed to appear in the request body instead of being
/// required to be passed as HTTP Basic authorization. This is not recommended and must be
/// enabled explicitely. See [`allow_credentials_in_body`] for details.
///
/// [`allow_credentials_in_body`]: #method.allow_credentials_in_body
pub struct ClientCredentialsFlow<E, R>
where
    E: Endpoint<R> + Send,
    R: WebRequest,
{
    endpoint: WrappedToken<E, R>,
    allow_credentials_in_body: bool,
    allow_refresh_token: bool,
}

struct WrappedToken<E: Endpoint<R>, R: WebRequest> {
    inner: E,
    extension_fallback: (),
    r_type: PhantomData<R>,
}

struct WrappedRequest<R: WebRequest> {
    /// Original request.
    request: PhantomData<R>,

    /// The request body
    body: NormalizedParameter,

    /// The authorization tuple
    authorization: Option<Authorization>,

    /// An error if one occurred.
    error: Option<FailParse<R::Error>>,

    /// The credentials-in-body flag from the flow.
    allow_credentials_in_body: bool,
}

struct Invalid;

enum FailParse<E> {
    Invalid,
    Err(E),
}

struct Authorization(String, Vec<u8>);

impl<E, R> ClientCredentialsFlow<E, R>
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
    /// endpoint, for details see the documentation of `Endpoint` and `execute`. For
    /// consistent endpoints, the panic is instead caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.issuer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        Ok(ClientCredentialsFlow {
            endpoint: WrappedToken {
                inner: endpoint,
                extension_fallback: (),
                r_type: PhantomData,
            },
            allow_credentials_in_body: false,
            allow_refresh_token: false,
        })
    }

    /// Credentials in body should only be enabled if use of HTTP Basic is not possible.
    ///
    /// Allows the request body to contain the `client_secret` as a form parameter. This is NOT
    /// RECOMMENDED and need not be supported. The parameters MUST NOT appear in the request URI
    /// itself.
    ///
    /// Thus support is disabled by default and must be explicitely enabled.
    pub fn allow_credentials_in_body(&mut self, allow: bool) {
        self.allow_credentials_in_body = allow;
    }

    /// Allow the refresh token to be included in the response.
    ///
    /// According to [RFC-6749 Section 4.4.3][4.4.3] "A refresh token SHOULD NOT be included" in
    /// the response for the client credentials grant. Following that recommendation, the default
    /// behaviour of this flow is to discard any refresh token that is returned from the issuer.
    ///
    /// If this behaviour is not what you want (it is possible that your particular application
    /// does have a use for a client credentials refresh token), you may enable this feature.
    ///
    /// [4.4.3]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4.3
    pub fn allow_refresh_token(&mut self, allow: bool) {
        self.allow_refresh_token = allow;
    }

    /// Use the checked endpoint to check for authorization for a resource.
    ///
    /// ## Panics
    ///
    /// When the registrar, authorizer, or issuer returned by the endpoint is suddenly
    /// `None` when previously it was `Some(_)`.
    pub async fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let pending = client_credentials(
            &mut self.endpoint,
            &WrappedRequest::new(&mut request, self.allow_credentials_in_body),
        )
        .await;

        let pending = match pending {
            Err(error) => {
                return client_credentials_error(&mut self.endpoint.inner, &mut request, error)
            }
            Ok(pending) => pending,
        };

        let consent = self
            .endpoint
            .inner
            .owner_solicitor()
            .unwrap()
            .check_consent(&mut request, pending.as_solicitation())
            .await;

        let owner_id = match consent {
            OwnerConsent::Authorized(owner_id) => owner_id,
            OwnerConsent::Error(error) => return Err(self.endpoint.inner.web_error(error)),
            OwnerConsent::InProgress(..) => {
                // User interaction is not permitted in the client credentials flow, so
                // an InProgress response is invalid.
                return Err(self.endpoint.inner.error(OAuthError::PrimitiveError));
            }
            OwnerConsent::Denied => {
                let mut error = AccessTokenError::default();
                error.set_type(AccessTokenErrorType::InvalidClient);
                let mut json = ErrorDescription::new(error);
                let mut response = self.endpoint.inner.response(
                    &mut request,
                    Template::new_unauthorized(None, Some(json.description())),
                )?;

                response
                    .client_error()
                    .map_err(|err| self.endpoint.inner.web_error(err))?;
                response
                    .body_json(&json.to_json())
                    .map_err(|err| self.endpoint.inner.web_error(err))?;
                return Ok(response);
            }
        };

        let token = match pending
            .issue(&mut self.endpoint, owner_id, self.allow_refresh_token)
            .await
        {
            Err(error) => {
                return client_credentials_error(&mut self.endpoint.inner, &mut request, error)
            }
            Ok(token) => token,
        };

        let mut response = self.endpoint.inner.response(&mut request, Template::new_ok())?;
        response
            .body_json(&token.to_json())
            .map_err(|err| self.endpoint.inner.web_error(err))?;
        Ok(response)
    }
}

fn client_credentials_error<E: Endpoint<R>, R: WebRequest>(
    endpoint: &mut E, request: &mut R, error: ClientCredentialsError,
) -> Result<R::Response, E::Error> {
    Ok(match error {
        ClientCredentialsError::Ignore => return Err(endpoint.error(OAuthError::DenySilently)),
        ClientCredentialsError::Invalid(mut json) => {
            let mut response =
                endpoint.response(request, Template::new_bad(Some(json.description())))?;

            response.client_error().map_err(|err| endpoint.web_error(err))?;
            response
                .body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        }
        ClientCredentialsError::Unauthorized(mut json, scheme) => {
            let mut response = endpoint.response(
                request,
                Template::new_unauthorized(None, Some(json.description())),
            )?;

            response
                .unauthorized(&scheme)
                .map_err(|err| endpoint.web_error(err))?;
            response
                .body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        }
        ClientCredentialsError::Primitive(_) => {
            // FIXME: give the context for restoration.
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }
    })
}

impl<E: Endpoint<R>, R: WebRequest> ClientCredentialsEndpoint for WrappedToken<E, R> {
    fn registrar(&self) -> &(dyn Registrar + Sync) {
        self.inner.registrar().unwrap()
    }

    fn authorizer(&mut self) -> &mut (dyn Authorizer + Send) {
        self.inner.authorizer_mut().unwrap()
    }

    fn issuer(&mut self) -> &mut (dyn Issuer + Send) {
        self.inner.issuer_mut().unwrap()
    }

    fn extension(&mut self) -> &mut (dyn Extension + Send) {
        self.inner
            .extension()
            .and_then(super::Extension::client_credentials)
            .unwrap_or(&mut self.extension_fallback)
    }
}

impl<R: WebRequest> WrappedRequest<R> {
    pub fn new(request: &mut R, credentials: bool) -> Self {
        Self::new_or_fail(request, credentials).unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &mut R, credentials: bool) -> Result<Self, FailParse<R::Error>> {
        // If there is a header, it must parse correctly.
        let authorization = match request.authheader() {
            Err(err) => return Err(FailParse::Err(err)),
            Ok(Some(header)) => Self::parse_header(header).map(Some)?,
            Ok(None) => None,
        };

        Ok(WrappedRequest {
            request: PhantomData,
            body: request
                .urlbody()
                .map(|body| body.into_owned())
                .map_err(FailParse::Err)?,
            authorization,
            error: None,
            allow_credentials_in_body: credentials,
        })
    }

    fn from_err(err: FailParse<R::Error>) -> Self {
        WrappedRequest {
            request: PhantomData,
            body: Default::default(),
            authorization: None,
            error: Some(err),
            allow_credentials_in_body: false,
        }
    }

    fn parse_header(header: Cow<str>) -> Result<Authorization, Invalid> {
        let authorization = {
            let auth_data = match is_authorization_method(&header, "Basic ") {
                None => return Err(Invalid),
                Some(data) => data,
            };

            let combined = match STANDARD.decode(auth_data) {
                Err(_) => return Err(Invalid),
                Ok(vec) => vec,
            };

            let mut split = combined.splitn(2, |&c| c == b':');
            let client_bin = match split.next() {
                None => return Err(Invalid),
                Some(client) => client,
            };
            let passwd = match split.next() {
                None => return Err(Invalid),
                Some(passwd64) => passwd64,
            };

            let client = match from_utf8(client_bin) {
                Err(_) => return Err(Invalid),
                Ok(client) => client,
            };

            Authorization(client.to_string(), passwd.to_vec())
        };

        Ok(authorization)
    }
}

impl<R: WebRequest> ClientCredentialsRequest for WrappedRequest<R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn authorization(&self) -> Option<(Cow<'_, str>, Cow<'_, [u8]>)> {
        self.authorization
            .as_ref()
            .map(|auth| (auth.0.as_str().into(), auth.1.as_slice().into()))
    }

    fn grant_type(&self) -> Option<Cow<'_, str>> {
        self.body.unique_value("grant_type")
    }

    fn scope(&self) -> Option<Cow<'_, str>> {
        self.body.unique_value("scope")
    }

    fn extension(&self, key: &str) -> Option<Cow<'_, str>> {
        self.body.unique_value(key)
    }

    fn allow_credentials_in_body(&self) -> bool {
        self.allow_credentials_in_body
    }
}

impl<E> From<Invalid> for FailParse<E> {
    fn from(_: Invalid) -> Self {
        FailParse::Invalid
    }
}
