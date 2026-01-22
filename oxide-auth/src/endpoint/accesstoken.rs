use std::borrow::Cow;
use std::str::from_utf8;
use std::marker::PhantomData;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::code_grant::accesstoken::{
    access_token, Error as TokenError, Extension, Endpoint as TokenEndpoint, Request as TokenRequest,
    Authorization as TokenAuthorization,
};
use crate::primitives::{authorizer::Authorizer, registrar::Registrar, issuer::Issuer};
use super::{
    Endpoint, InnerTemplate, OAuthError, QueryParameter, WebRequest, WebResponse,
    is_authorization_method,
};

/// Offers access tokens to authenticated third parties.
///
/// After having received an authorization code from the resource owner, a client must
/// directly contact the OAuth endpoint–authenticating itself–to receive the access
/// token. The token is then used as authorization in requests to the resource. This
/// request MUST be protected by TLS.
///
/// Client credentials can be allowed to appear in the request body instead of being
/// required to be passed as HTTP Basic authorization. This is not recommended and must be
/// enabled explicitely. See [`allow_credentials_in_body`] for details.
///
/// [`allow_credentials_in_body`]: #method.allow_credentials_in_body
pub struct AccessTokenFlow<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    endpoint: WrappedToken<E, R>,
    allow_credentials_in_body: bool,
}

struct WrappedToken<E: Endpoint<R>, R: WebRequest> {
    inner: E,
    extension_fallback: (),
    r_type: PhantomData<R>,
}

struct WrappedRequest<'a, R: WebRequest + 'a> {
    /// Original request.
    request: PhantomData<R>,

    /// The query in the url.
    body: Cow<'a, dyn QueryParameter + 'static>,

    /// The authorization tuple
    authorization: Option<Authorization>,

    /// An error if one occurred.
    error: Option<FailParse<R::Error>>,

    /// The credentials-in-body flag from the flow.
    allow_credentials_in_body: bool,
}

#[derive(Debug)]
struct Invalid;

enum FailParse<E> {
    Invalid,
    Err(E),
}

#[derive(Debug, PartialEq, Eq)]
struct Authorization(String, Option<Vec<u8>>);

impl<E, R> AccessTokenFlow<E, R>
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
    /// endpoint, for details see the documentation of `Endpoint` and `execute`. For
    /// consistent endpoints, the panic is instead caught as an error here.
    pub fn prepare(mut endpoint: E) -> Result<Self, E::Error> {
        if endpoint.registrar().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.authorizer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        if endpoint.issuer_mut().is_none() {
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }

        Ok(AccessTokenFlow {
            endpoint: WrappedToken {
                inner: endpoint,
                extension_fallback: (),
                r_type: PhantomData,
            },
            allow_credentials_in_body: false,
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

    /// Use the checked endpoint to check for authorization for a resource.
    ///
    /// ## Panics
    ///
    /// When the registrar, authorizer, or issuer returned by the endpoint is suddenly
    /// `None` when previously it was `Some(_)`.
    pub fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let issued = access_token(
            &mut self.endpoint,
            &WrappedRequest::new(&mut request, self.allow_credentials_in_body),
        );

        let token = match issued {
            Err(error) => return token_error(&mut self.endpoint.inner, &mut request, error),
            Ok(token) => token,
        };

        let mut response = self
            .endpoint
            .inner
            .response(&mut request, InnerTemplate::Ok.into())?;
        response
            .body_json(&token.to_json())
            .map_err(|err| self.endpoint.inner.web_error(err))?;
        Ok(response)
    }
}

fn token_error<E: Endpoint<R>, R: WebRequest>(
    endpoint: &mut E, request: &mut R, error: TokenError,
) -> Result<R::Response, E::Error> {
    Ok(match error {
        TokenError::Invalid(mut json) => {
            let mut response = endpoint.response(
                request,
                InnerTemplate::BadRequest {
                    access_token_error: Some(json.description()),
                }
                .into(),
            )?;
            response.client_error().map_err(|err| endpoint.web_error(err))?;
            response
                .body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        }
        TokenError::Unauthorized(mut json, scheme) => {
            let mut response = endpoint.response(
                request,
                InnerTemplate::Unauthorized {
                    error: None,
                    access_token_error: Some(json.description()),
                }
                .into(),
            )?;
            response
                .unauthorized(&scheme)
                .map_err(|err| endpoint.web_error(err))?;
            response
                .body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        }
        TokenError::Primitive(_) => {
            // FIXME: give the context for restoration.
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }
    })
}

impl<E: Endpoint<R>, R: WebRequest> TokenEndpoint for WrappedToken<E, R> {
    fn registrar(&self) -> &dyn Registrar {
        self.inner.registrar().unwrap()
    }

    fn authorizer(&mut self) -> &mut dyn Authorizer {
        self.inner.authorizer_mut().unwrap()
    }

    fn issuer(&mut self) -> &mut dyn Issuer {
        self.inner.issuer_mut().unwrap()
    }

    fn extension(&mut self) -> &mut dyn Extension {
        self.inner
            .extension()
            .and_then(super::Extension::access_token)
            .unwrap_or(&mut self.extension_fallback)
    }
}

impl<'a, R: WebRequest + 'a> WrappedRequest<'a, R> {
    pub fn new(request: &'a mut R, credentials: bool) -> Self {
        Self::new_or_fail(request, credentials).unwrap_or_else(Self::from_err)
    }

    fn new_or_fail(request: &'a mut R, credentials: bool) -> Result<Self, FailParse<R::Error>> {
        // If there is a header, it must parse correctly.
        let authorization = match request.authheader() {
            Err(err) => return Err(FailParse::Err(err)),
            Ok(Some(header)) => Self::parse_header(header).map(Some)?,
            Ok(None) => None,
        };

        Ok(WrappedRequest {
            request: PhantomData,
            body: request.urlbody().map_err(FailParse::Err)?,
            authorization,
            error: None,
            allow_credentials_in_body: credentials,
        })
    }

    fn from_err(err: FailParse<R::Error>) -> Self {
        WrappedRequest {
            request: PhantomData,
            body: Cow::Owned(Default::default()),
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
                Some([]) => None,
                Some(passwd64) => Some(passwd64),
            };

            let client = match from_utf8(client_bin) {
                Err(_) => return Err(Invalid),
                Ok(client) => client,
            };

            Authorization(client.to_string(), passwd.map(|passwd| passwd.to_vec()))
        };

        Ok(authorization)
    }
}

impl<'a, R: WebRequest> TokenRequest for WrappedRequest<'a, R> {
    fn valid(&self) -> bool {
        self.error.is_none()
    }

    fn code(&self) -> Option<Cow<'_, str>> {
        self.body.unique_value("code")
    }

    fn authorization(&self) -> TokenAuthorization<'_> {
        match &self.authorization {
            None => TokenAuthorization::None,
            Some(Authorization(username, None)) => TokenAuthorization::Username(username.into()),
            Some(Authorization(username, Some(password))) => {
                TokenAuthorization::UsernamePassword(username.into(), password.into())
            }
        }
    }

    fn client_id(&self) -> Option<Cow<'_, str>> {
        self.body.unique_value("client_id")
    }

    fn redirect_uri(&self) -> Option<Cow<'_, str>> {
        self.body.unique_value("redirect_uri")
    }

    fn grant_type(&self) -> Option<Cow<'_, str>> {
        self.body.unique_value("grant_type")
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::endpoint::accesstoken::WrappedRequest;
    use crate::frontends::simple::request::Request;

    #[test]
    fn test_client_id_only() {
        let result = WrappedRequest::<Request>::parse_header("Basic Zm9vOg==".into());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, Authorization("foo".into(), None));
    }

    #[test]
    fn test_client_id_and_secret() {
        let result = WrappedRequest::<Request>::parse_header("Basic Zm9vOmJhcg==".into());
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result, Authorization("foo".into(), Some("bar".into())));
    }
}
