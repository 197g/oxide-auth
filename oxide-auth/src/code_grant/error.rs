//! Errors defined in [rfc6749].
//!
//! [rfc6749]: https://tools.ietf.org/html/rfc6749#section-6

use std::fmt;
use std::borrow::Cow;
use std::vec;
use url::Url;

/// Error codes returned from an authorization code request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationErrorType {
    /// The request is missing a required parameter, includes an invalid parameter value, includes
    /// a parameter more than once, or is otherwise malformed.
    InvalidRequest,

    /// The client is not authorized to request an authorization code using this method.
    UnauthorizedClient,

    /// The resource owner or authorization server denied the request.
    AccessDenied,

    /// The authorization server does not support obtaining an authorization code using this method.
    UnsupportedResponseType,

    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,

    /// The authorization server encountered an unexpected condition that prevented it from
    /// fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP
    /// status code cannot be returned to the client via an HTTP redirect.)
    ServerError,

    /// The authorization server is currently unable to handle the request due to a temporary
    /// overloading or maintenance of the server.  (This error code is needed because a 503 Service
    /// Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)
    TemporarilyUnavailable,
}

impl AuthorizationErrorType {
    fn description(self) -> &'static str {
        match self {
            AuthorizationErrorType::InvalidRequest => "invalid_request",
            AuthorizationErrorType::UnauthorizedClient => "unauthorized_client",
            AuthorizationErrorType::AccessDenied => "access_denied",
            AuthorizationErrorType::UnsupportedResponseType => "unsupported_response_type",
            AuthorizationErrorType::InvalidScope => "invalid_scope",
            AuthorizationErrorType::ServerError => "server_error",
            AuthorizationErrorType::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }
}

/// Represents parameters of an error in an [Authorization Error Response][Authorization Error].
///
/// [Authorization Error]: https://tools.ietf.org/html/rfc6749#section-4.2.2.1
#[derive(Clone, Debug)]
pub struct AuthorizationError {
    error: AuthorizationErrorType,
    description: Option<Cow<'static, str>>,
    uri: Option<Cow<'static, str>>,
}

impl AuthorizationError {
    #[allow(dead_code)]
    pub(crate) fn new(error: AuthorizationErrorType) -> Self {
        AuthorizationError {
            error,
            description: None,
            uri: None,
        }
    }

    /// Set the error type
    pub fn set_type(&mut self, new_type: AuthorizationErrorType) {
        self.error = new_type;
    }

    /// Get the formal kind of error.
    ///
    /// This can not currently be changed as to uphold the inner invariants for RFC compliance.
    pub fn kind(&mut self) -> AuthorizationErrorType {
        self.error
    }

    /// Provide a short text explanation for the error.
    pub fn explain<D: Into<Cow<'static, str>>>(&mut self, description: D) {
        self.description = Some(description.into())
    }

    /// A uri identifying a resource explaining the error in detail.
    pub fn explain_uri(&mut self, uri: Url) {
        self.uri = Some(String::from(uri).into())
    }

    /// Iterate over the key value pairs that describe this error.
    ///
    /// These pairs must be added to the detailed description of an error. To this end the pairs
    /// appear as part of a form urlencoded query component in the `Location` header of a server
    /// response.
    pub fn iter(&self) -> <Self as IntoIterator>::IntoIter {
        self.into_iter()
    }
}

/// All defined error codes
///
/// Details also found in <https://tools.ietf.org/html/rfc6749#section-5.2>.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessTokenErrorType {
    /// The request is missing a required parameter, includes an unsupported parameter value (other
    // than grant type), repeats a parameter, includes multiple credentials, utilizes more than one
    /// mechanism for authenticating the client, or is otherwise malformed.
    InvalidRequest,

    /// Client authentication failed (e.g., unknown client, no client authentication included, or
    /// unsupported authentication method).  The authorization server MAY return an HTTP 401
    /// (Unauthorized) status code to indicate which HTTP authentication schemes are supported.
    /// If the client attempted to authenticate via the "Authorization" request header field, the
    /// authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include
    /// the "WWW-Authenticate" response header field matching the authentication scheme used by the
    /// client.
    InvalidClient,

    /// The provided authorization grant (e.g., authorization code, resource owner credentials) or
    /// refresh token is invalid, expired, revoked, does not match the redirection URI used in the
    /// authorization request, or was issued to another client.
    InvalidGrant,

    /// The authenticated client is not authorized to use this authorization grant type.
    UnauthorizedClient,

    /// The authorization grant type is not supported by the authorization server.
    UnsupportedGrantType,

    /// The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the
    /// resource owner.
    InvalidScope,
}

impl AccessTokenErrorType {
    fn description(self) -> &'static str {
        match self {
            AccessTokenErrorType::InvalidRequest => "invalid_request",
            AccessTokenErrorType::InvalidClient => "invalid_client",
            AccessTokenErrorType::InvalidGrant => "invalid_grant",
            AccessTokenErrorType::UnauthorizedClient => "unauthorized_client",
            AccessTokenErrorType::UnsupportedGrantType => "unsupported_grant_type",
            AccessTokenErrorType::InvalidScope => "invalid_scope",
        }
    }
}

/// Represents parameters of an error in an [Issuing Error Response][Issuing Error].
///
/// This is used for both access token requests, and [token refresh requests] as they use the same
/// internal error representations in the RFC as well.
///
/// [Issuing Error]: https://tools.ietf.org/html/rfc6749#section-5.2
/// [token refresh requests]: https://tools.ietf.org/html/rfc6749#section-7
#[derive(Clone, Debug)]
pub struct AccessTokenError {
    error: AccessTokenErrorType,
    description: Option<Cow<'static, str>>,
    uri: Option<Cow<'static, str>>,
}

impl AccessTokenError {
    pub(crate) fn new(error: AccessTokenErrorType) -> Self {
        AccessTokenError {
            error,
            description: None,
            uri: None,
        }
    }

    /// Set error type
    pub fn set_type(&mut self, new_type: AccessTokenErrorType) {
        self.error = new_type;
    }

    /// Get the formal kind of error.
    ///
    /// This can not currently be changed as to uphold the inner invariants for RFC compliance.
    pub fn kind(&mut self) -> AccessTokenErrorType {
        self.error
    }

    /// Provide a short text explanation for the error.
    pub fn explain<D: Into<Cow<'static, str>>>(&mut self, description: D) {
        self.description = Some(description.into())
    }

    /// A uri identifying a resource explaining the error in detail.
    pub fn explain_uri(&mut self, uri: Url) {
        self.uri = Some(String::from(uri).into())
    }

    /// Iterate over the key value pairs that describe this error.
    ///
    /// These pairs must be added to the detailed description of an error. The pairs will be
    /// encoded in the json body of the Bad Request response.
    pub fn iter(&self) -> <Self as IntoIterator>::IntoIter {
        self.into_iter()
    }
}

impl Default for AuthorizationError {
    /// Construct a `AuthorizationError` with no extra information.
    ///
    /// Will produce a generic `InvalidRequest` error without any description or error uri which
    /// would provide additional information for the client.
    fn default() -> Self {
        AuthorizationError {
            error: AuthorizationErrorType::InvalidRequest,
            description: None,
            uri: None,
        }
    }
}

impl AsRef<str> for AuthorizationErrorType {
    fn as_ref(&self) -> &str {
        self.description()
    }
}

impl fmt::Display for AuthorizationErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl Default for AccessTokenError {
    /// Construct a `AccessTokenError` with no extra information.
    ///
    /// Will produce a generic `InvalidRequest` error without any description or error uri which
    /// would provide additional information for the client.
    fn default() -> Self {
        AccessTokenError {
            error: AccessTokenErrorType::InvalidRequest,
            description: None,
            uri: None,
        }
    }
}

impl AsRef<str> for AccessTokenErrorType {
    fn as_ref(&self) -> &str {
        self.description()
    }
}

impl fmt::Display for AccessTokenErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

/// The error as key-value pairs.
impl IntoIterator for AuthorizationError {
    type Item = (&'static str, Cow<'static, str>);
    type IntoIter = vec::IntoIter<(&'static str, Cow<'static, str>)>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = vec![("error", Cow::Borrowed(self.error.description()))];
        if let Some(description) = self.description {
            vec.push(("description", description));
        }
        if let Some(uri) = self.uri {
            vec.push(("uri", uri));
        }
        vec.into_iter()
    }
}

impl IntoIterator for &'_ AuthorizationError {
    type Item = (&'static str, Cow<'static, str>);
    type IntoIter = vec::IntoIter<(&'static str, Cow<'static, str>)>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = vec![("error", Cow::Borrowed(self.error.description()))];
        if let Some(description) = &self.description {
            vec.push(("description", description.clone()));
        }
        if let Some(uri) = &self.uri {
            vec.push(("uri", uri.clone()));
        }
        vec.into_iter()
    }
}

/// The error as key-value pairs.
impl IntoIterator for AccessTokenError {
    type Item = (&'static str, Cow<'static, str>);
    type IntoIter = vec::IntoIter<(&'static str, Cow<'static, str>)>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = vec![("error", Cow::Borrowed(self.error.description()))];
        if let Some(description) = self.description {
            vec.push(("description", description));
        }
        if let Some(uri) = self.uri {
            vec.push(("uri", uri));
        }
        vec.into_iter()
    }
}

impl IntoIterator for &'_ AccessTokenError {
    type Item = (&'static str, Cow<'static, str>);
    type IntoIter = vec::IntoIter<(&'static str, Cow<'static, str>)>;

    fn into_iter(self) -> Self::IntoIter {
        let mut vec = vec![("error", Cow::Borrowed(self.error.description()))];
        if let Some(description) = &self.description {
            vec.push(("description", description.clone()));
        }
        if let Some(uri) = &self.uri {
            vec.push(("uri", uri.clone()));
        }
        vec.into_iter()
    }
}
