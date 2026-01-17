use std::str::from_utf8;
use std::{borrow::Cow, marker::PhantomData};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oxide_auth::{
    endpoint::{QueryParameter, WebRequest, OAuthError, WebResponse, Template, NormalizedParameter},
    code_grant::{
        accesstoken::{
            Error as TokenError, Request as TokenRequest, Authorization as TokenAuthorization,
        },
    },
};

use super::Endpoint;
use crate::{
    code_grant::access_token::{Extension, Endpoint as TokenEndpoint, access_token},
    primitives::{Issuer, Registrar, Authorizer},
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

struct WrappedToken<E, R>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    inner: E,
    extension_fallback: (),
    r_type: PhantomData<R>,
}

#[derive(Clone)]
pub struct WrappedRequest<R: WebRequest> {
    /// The query in the url.
    body: NormalizedParameter,

    /// The authorization tuple
    authorization: Option<Authorization>,

    /// An error if one occurred.
    error: Option<FailParse<R::Error>>,

    /// The credentials-in-body flag from the flow.
    allow_credentials_in_body: bool,
}

#[derive(Debug)]
struct Invalid;

#[derive(Clone)]
enum FailParse<E> {
    Invalid,
    Err(E),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Authorization(String, Option<Vec<u8>>);

impl<E, R> AccessTokenFlow<E, R>
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
    pub async fn execute(&mut self, mut request: R) -> Result<R::Response, E::Error> {
        let issued = access_token(
            &mut self.endpoint,
            &WrappedRequest::new(&mut request, self.allow_credentials_in_body),
        )
        .await;

        let token = match issued {
            Err(error) => return token_error(&mut self.endpoint.inner, &mut request, error),
            Ok(token) => token,
        };

        let mut response = self.endpoint.inner.response(&mut request, Template::new_ok())?;
        response
            .body_json(&token.to_json())
            .map_err(|err| self.endpoint.inner.web_error(err))?;
        Ok(response)
    }
}

fn token_error<E, R>(
    endpoint: &mut E, request: &mut R, error: TokenError,
) -> Result<R::Response, E::Error>
where
    E: Endpoint<R>,
    R: WebRequest,
{
    Ok(match error {
        TokenError::Invalid(mut json) => {
            let mut response =
                endpoint.response(request, Template::new_bad(Some(json.description())))?;
            response.client_error().map_err(|err| endpoint.web_error(err))?;
            response
                .body_json(&json.to_json())
                .map_err(|err| endpoint.web_error(err))?;
            response
        }
        TokenError::Unauthorized(mut json, scheme) => {
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
        TokenError::Primitive(_) => {
            // FIXME: give the context for restoration.
            return Err(endpoint.error(OAuthError::PrimitiveError));
        }
    })
}

impl<E, R> TokenEndpoint for WrappedToken<E, R>
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

    fn issuer(&mut self) -> &mut (dyn Issuer + Send) {
        self.inner.issuer_mut().unwrap()
    }

    fn extension(&mut self) -> &mut (dyn Extension + Send) {
        self.inner
            .extension()
            .and_then(super::Extension::access_token)
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
            body: request.urlbody().map_err(FailParse::Err)?.into_owned(),
            authorization,
            error: None,
            allow_credentials_in_body: credentials,
        })
    }

    fn from_err(err: FailParse<R::Error>) -> Self {
        WrappedRequest {
            body: Default::default(),
            authorization: None,
            error: Some(err),
            allow_credentials_in_body: false,
        }
    }

    fn parse_header(header: Cow<str>) -> Result<Authorization, Invalid> {
        let authorization = {
            if !header.starts_with("Basic ") {
                return Err(Invalid);
            }

            let combined = match STANDARD.decode(&header[6..]) {
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

impl<R: WebRequest> TokenRequest for WrappedRequest<R> {
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
    use oxide_auth::frontends::simple::request::Request;
    use super::*;

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
