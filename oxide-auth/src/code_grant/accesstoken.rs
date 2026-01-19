//! Provides the handling for Access Token Requests
use std::mem;
use std::borrow::Cow;
use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::code_grant::error::{AccessTokenError, AccessTokenErrorType};
use crate::primitives::authorizer::Authorizer;
use crate::primitives::issuer::{IssuedToken, Issuer};
use crate::primitives::grant::{Extensions, Grant};
use crate::primitives::registrar::{Registrar, RegistrarError};
use crate::primitives::scope::Scope;

/// Token Response
#[derive(Deserialize, Serialize)]
pub struct TokenResponse {
    /// The access token issued by the authorization server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    /// The refresh token, which can be used to obtain new access tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// The type of the token issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// The lifetime in seconds of the access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,

    /// The scope, which limits the permissions on the access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Error code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Authorization information from the request
#[non_exhaustive]
pub enum Authorization<'a> {
    /// None present
    None,
    /// Only a username
    Username(Cow<'a, str>),
    /// Username and password combination
    UsernamePassword(Cow<'a, str>, Cow<'a, [u8]>),
}

/// Trait based retrieval of parameters necessary for access token request handling.
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// The authorization code grant for which an access token is wanted.
    fn code(&self) -> Option<Cow<str>>;

    /// User:password of a basic authorization header.
    fn authorization(&self) -> Authorization;

    /// The client_id, optional parameter for public clients.
    fn client_id(&self) -> Option<Cow<str>>;

    /// Valid request have the redirect url used to request the authorization code grant.
    fn redirect_uri(&self) -> Option<Cow<str>>;

    /// Valid requests have this set to "authorization_code"
    fn grant_type(&self) -> Option<Cow<str>>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<str>>;

    /// Credentials in body should only be enabled if use of HTTP Basic is not possible.
    ///
    /// Allows the request body to contain the `client_secret` as a form parameter. This is NOT
    /// RECOMMENDED and need not be supported. The parameters MUST NOT appear in the request URI
    /// itself.
    ///
    /// Under these considerations, support must be explicitely enabled.
    fn allow_credentials_in_body(&self) -> bool {
        false
    }
}

/// A system of addons provided additional data.
///
/// An endpoint not having any extension may use `&mut ()` as the result of system.
pub trait Extension {
    /// Inspect the request and extension data to produce extension data.
    ///
    /// The input data comes from the extension data produced in the handling of the
    /// authorization code request.
    fn extend(&mut self, request: &dyn Request, data: Extensions)
        -> std::result::Result<Extensions, ()>;
}

impl Extension for () {
    fn extend(&mut self, _: &dyn Request, _: Extensions) -> std::result::Result<Extensions, ()> {
        Ok(Extensions::new())
    }
}

/// Required functionality to respond to access token requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// Get the client corresponding to some id.
    fn registrar(&self) -> &dyn Registrar;

    /// Get the authorizer from which we can recover the authorization.
    fn authorizer(&mut self) -> &mut dyn Authorizer;

    /// Return the issuer instance to create the access token.
    fn issuer(&mut self) -> &mut dyn Issuer;

    /// The system of used extension, extending responses.
    ///
    /// It is possible to use `&mut ()`.
    fn extension(&mut self) -> &mut dyn Extension;
}

enum Credentials<'a> {
    /// No credentials were offered.
    None,
    /// One set of credentials was offered.
    Authenticated {
        client_id: &'a str,
        passphrase: &'a [u8],
    },
    /// No password but name was offered.
    ///
    /// This must happen only when the credentials were part of the request body but used to
    /// indicate the name of a public client.
    Unauthenticated { client_id: &'a str },
    /// Multiple possible credentials were offered.
    ///
    /// This is a security issue, only one attempt must be made per request.
    Duplicate,
}

/// Access token issuing process
///
/// This state machine will go through four phases. On creation, the request will be validated and
/// parameters for the first step will be extracted from it. It will pose some requests in the form
/// of [`Output`] which should be satisfied with the next [`Input`] data. This will eventually
/// produce a [`BearerToken`] or an [`Error`]. Note that the executing environment will need to use
/// a [`Registrar`], an [`Authorizer`], an optionnal [`Extension`] and an [`Issuer`] to which some
/// requests should be forwarded.
///
/// [`Input`]: struct.Input.html
/// [`Output`]: struct.Output.html
/// [`BearerToken`]: struct.BearerToken.html
/// [`Error`]: struct.Error.html
/// [`Issuer`] ../primitives/issuer/trait.Issuer.html
/// [`Registrar`] ../primitives/registrar/trait.Registrar.html
/// [`Authorizer`] ../primitives/authorizer/trait.Authorizer.html
/// [`Extension`] trait.Extension.html
///
/// A rough sketch of the operational phases:
///
/// 1. Ensure the request is valid based on the basic requirements (includes required parameters)
/// 2. Try to produce a new token
///     2.1. Authenticate the client
///     2.2. If there was no authentication, assert token does not require authentication
///     2.3. Recover the current grant corresponding to the `code`
///     2.4. Check the intrinsic validity (scope)
/// 3. Query the backend for a new (bearer) token
pub struct AccessToken {
    state: AccessTokenState,
}

/// Inner state machine for access token
enum AccessTokenState {
    /// State after the request has been validated.
    Authenticate {
        client: String,
        passdata: Option<Vec<u8>>,
        code: String,
        // TODO: parsing here is unnecessary if we compare a string representation.
        redirect_uri: url::Url,
    },
    Recover {
        client: String,
        code: String,
        redirect_uri: url::Url,
    },
    Extend {
        saved_params: Box<Grant>,
        extensions: Extensions,
    },
    Issue {
        grant: Box<Grant>,
    },
    Err(Error),
}

/// Input injected by the executor into the state machine.
pub enum Input<'req> {
    /// The request to be processed.
    Request(&'req dyn Request),
    /// Positively answer an authentication query.
    Authenticated,
    /// Provide the queried refresh token.
    Recovered(Option<Box<Grant>>),
    /// Provide extensions
    Extended {
        /// The grant extension
        access_extensions: Extensions,
    },
    /// The token produced by the backend
    Issued(IssuedToken),
    /// Advance without input as far as possible, or just retrieve the output again.
    None,
}

/// A request by the statemachine to the executor.
///
/// Each variant is fulfilled by certain variants of the next inputs as an argument to
/// `AccessToken::advance`. The output of most states is simply repeated if `Input::None` is
/// provided instead but note that the successful bearer token response is **not** repeated.
pub enum Output<'machine> {
    /// The registrar should authenticate a client.
    ///
    /// Fulfilled by `Input::Authenticated`. In an unsuccessful case, the executor should not
    /// continue and discard the flow.
    Authenticate {
        /// The to-be-authenticated client.
        client: &'machine str,
        /// The supplied passdata/password.
        passdata: Option<&'machine [u8]>,
    },
    /// The issuer should try to recover the grant for this `code`
    ///
    /// Fulfilled by `Input::Recovered`.
    Recover {
        /// The `code` from current request
        code: &'machine str,
    },
    /// The extension (if any) should provide the extensions
    ///
    /// Fullfilled by `Input::Extended`
    Extend {
        /// The grant extensions if any
        extensions: &'machine mut Extensions,
    },
    /// The issue should issue a new access token
    ///
    /// Fullfilled by `Input::Issued`
    Issue {
        /// The grant to be used in the token generation
        grant: &'machine Grant,
    },
    /// The state machine finished and a new bearer token was generated
    ///
    /// This output **can not** be requested repeatedly, any future `Input` will yield a primitive
    /// error instead.
    Ok(BearerToken),
    /// The state machine finished in an error.
    ///
    /// The error will be repeated on *any* following input.
    Err(Box<Error>),
}

impl AccessToken {
    /// Create the state machine. validating the request in the process
    pub fn new(request: &dyn Request) -> Self {
        AccessToken {
            state: Self::validate(request).unwrap_or_else(AccessTokenState::Err),
        }
    }

    /// Go to next state
    pub fn advance(&mut self, input: Input) -> Output<'_> {
        self.state = match (self.take(), input) {
            (current, Input::None) => current,
            (
                AccessTokenState::Authenticate {
                    client,
                    code,
                    redirect_uri,
                    ..
                },
                Input::Authenticated,
            ) => Self::authenticated(client, code, redirect_uri),
            (
                AccessTokenState::Recover {
                    client, redirect_uri, ..
                },
                Input::Recovered(grant),
            ) => Self::recovered(client, redirect_uri, grant).unwrap_or_else(AccessTokenState::Err),
            (AccessTokenState::Extend { saved_params, .. }, Input::Extended { access_extensions }) => {
                Self::issue(saved_params, access_extensions)
            }
            (AccessTokenState::Issue { grant }, Input::Issued(token)) => {
                return Output::Ok(Self::finish(grant, token));
            }
            (AccessTokenState::Err(err), _) => AccessTokenState::Err(err),
            (_, _) => AccessTokenState::Err(Error::Primitive(Box::new(PrimitiveError::empty()))),
        };

        self.output()
    }

    fn output(&mut self) -> Output<'_> {
        match &mut self.state {
            AccessTokenState::Err(err) => Output::Err(Box::new(err.clone())),
            AccessTokenState::Authenticate { client, passdata, .. } => Output::Authenticate {
                client,
                passdata: passdata.as_ref().map(Vec::as_slice),
            },
            AccessTokenState::Recover { code, .. } => Output::Recover { code },
            AccessTokenState::Extend { extensions, .. } => Output::Extend { extensions },
            AccessTokenState::Issue { grant } => Output::Issue { grant },
        }
    }

    fn take(&mut self) -> AccessTokenState {
        mem::replace(
            &mut self.state,
            AccessTokenState::Err(Error::Primitive(Box::new(PrimitiveError::empty()))),
        )
    }

    fn validate(request: &dyn Request) -> Result<AccessTokenState> {
        if !request.valid() {
            return Err(Error::invalid());
        }

        let authorization = request.authorization();
        let client_id = request.client_id();
        let client_secret = request.extension("client_secret");

        let mut credentials = Credentials::None;

        match &authorization {
            Authorization::None => {}
            Authorization::Username(username) => credentials.unauthenticated(username),
            Authorization::UsernamePassword(username, password) => {
                credentials.authenticate(username, password)
            }
        }

        if let Some(client_id) = &client_id {
            match &client_secret {
                Some(auth) if request.allow_credentials_in_body() => {
                    credentials.authenticate(client_id.as_ref(), auth.as_ref().as_bytes())
                }
                // Ignore parameter if not allowed.
                Some(_) | None => credentials.unauthenticated(client_id.as_ref()),
            }
        }

        match request.grant_type() {
            Some(ref cow) if cow == "authorization_code" => (),
            None => return Err(Error::invalid()),
            Some(_) => return Err(Error::invalid_with(AccessTokenErrorType::UnsupportedGrantType)),
        };

        let (client_id, passdata) = credentials.into_client().ok_or_else(Error::invalid)?;

        let redirect_uri = request
            .redirect_uri()
            .ok_or_else(Error::invalid)?
            .parse()
            .map_err(|_| Error::invalid())?;

        let code = request.code().ok_or_else(Error::invalid)?;

        Ok(AccessTokenState::Authenticate {
            client: client_id.to_string(),
            passdata: passdata.map(Vec::from),
            redirect_uri,
            code: code.into_owned(),
        })
    }

    fn authenticated(client: String, code: String, redirect_uri: url::Url) -> AccessTokenState {
        AccessTokenState::Recover {
            client,
            code,
            redirect_uri,
        }
    }

    fn recovered(
        client_id: String, redirect_uri: url::Url, grant: Option<Box<Grant>>,
    ) -> Result<AccessTokenState> {
        let mut saved_params = match grant {
            None => return Err(Error::invalid()),
            Some(v) => v,
        };

        if (saved_params.client_id.as_str(), &saved_params.redirect_uri) != (&client_id, &redirect_uri) {
            return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant));
        }

        if saved_params.until < Utc::now() {
            return Err(Error::invalid_with(AccessTokenErrorType::InvalidGrant));
        }

        let extensions = mem::take(&mut saved_params.extensions);
        Ok(AccessTokenState::Extend {
            saved_params,
            extensions,
        })
    }

    fn issue(grant: Box<Grant>, extensions: Extensions) -> AccessTokenState {
        AccessTokenState::Issue {
            grant: Box::new(Grant { extensions, ..*grant }),
        }
    }

    fn finish(grant: Box<Grant>, token: IssuedToken) -> BearerToken {
        BearerToken(token, grant.scope.clone())
    }
}

// FiXME: use state machine instead
/// Try to redeem an authorization code.
pub fn access_token(handler: &mut dyn Endpoint, request: &dyn Request) -> Result<BearerToken> {
    enum Requested<'a> {
        None,
        Authenticate {
            client: &'a str,
            passdata: Option<&'a [u8]>,
        },
        Recover(&'a str),
        Extend {
            extensions: &'a mut Extensions,
        },
        Issue {
            grant: &'a Grant,
        },
    }

    let mut access_token = AccessToken::new(request);
    let mut requested = Requested::None;

    loop {
        let input = match requested {
            Requested::None => Input::None,
            Requested::Authenticate { client, passdata } => {
                handler
                    .registrar()
                    .check(client, passdata)
                    .map_err(|err| match err {
                        RegistrarError::Unspecified => Error::unauthorized("basic"),
                        RegistrarError::PrimitiveError => Error::Primitive(Box::new(PrimitiveError {
                            grant: None,
                            extensions: None,
                        })),
                    })?;
                Input::Authenticated
            }
            Requested::Recover(code) => {
                let opt_grant = handler.authorizer().extract(code).map_err(|_| {
                    Error::Primitive(Box::new(PrimitiveError {
                        grant: None,
                        extensions: None,
                    }))
                })?;
                Input::Recovered(opt_grant.map(Box::new))
            }
            Requested::Extend { extensions } => {
                let access_extensions = handler
                    .extension()
                    .extend(request, extensions.clone())
                    .map_err(|_| Error::invalid())?;
                Input::Extended { access_extensions }
            }
            Requested::Issue { grant } => {
                let token = handler.issuer().issue(grant.clone()).map_err(|_| {
                    Error::Primitive(Box::new(PrimitiveError {
                        // FIXME: endpoint should get and handle these.
                        grant: None,
                        extensions: None,
                    }))
                })?;
                Input::Issued(token)
            }
        };

        requested = match access_token.advance(input) {
            Output::Authenticate { client, passdata } => Requested::Authenticate { client, passdata },
            Output::Recover { code } => Requested::Recover(code),
            Output::Extend { extensions } => Requested::Extend { extensions },
            Output::Issue { grant } => Requested::Issue { grant },
            Output::Ok(token) => return Ok(token),
            Output::Err(e) => return Err(*e),
        };
    }
}

impl<'a> Credentials<'a> {
    pub fn authenticate(&mut self, client_id: &'a str, passphrase: &'a [u8]) {
        self.add(Credentials::Authenticated {
            client_id,
            passphrase,
        })
    }

    pub fn unauthenticated(&mut self, client_id: &'a str) {
        self.add(Credentials::Unauthenticated { client_id })
    }

    pub fn into_client(self) -> Option<(&'a str, Option<&'a [u8]>)> {
        match self {
            Credentials::Authenticated {
                client_id,
                passphrase,
            } => Some((client_id, Some(passphrase))),
            Credentials::Unauthenticated { client_id } => Some((client_id, None)),
            _ => None,
        }
    }

    fn add(&mut self, new: Self) {
        *self = match self {
            Credentials::None => new,
            _ => Credentials::Duplicate,
        };
    }
}

/// Defines actions for the response to an access token request.
#[derive(Clone)]
pub enum Error {
    /// The token did not represent a valid token.
    Invalid(ErrorDescription),

    /// The client did not properly authorize itself.
    Unauthorized(ErrorDescription, String),

    /// An underlying primitive operation did not complete successfully.
    ///
    /// This is expected to occur with some endpoints. See `PrimitiveError` for
    /// more details on when this is returned.
    Primitive(Box<PrimitiveError>),
}

/// The endpoint should have enough control over its primitives to find
/// out what has gone wrong, e.g. they may externall supply error
/// information.
///
/// In this case, all previous results returned by the primitives are
/// included in the return value. Through this mechanism, one can
/// accomodate async handlers by implementing a sync-based result cache
/// that is filled with these partial values. In case only parts of the
/// outstanding futures, invoked during internal calls, are ready the
/// cache can be refilled through the error eliminating polls to already
/// sucessful futures.
///
/// Note that `token` is not included in this list, since the handler
/// can never fail after supplying a token to the backend.
#[derive(Clone)]
pub struct PrimitiveError {
    /// The already extracted grant.
    ///
    /// You may reuse this, or more precisely you must to fulfill this exact request in case of
    /// an error recovery attempt.
    pub grant: Option<Grant>,

    /// The extensions that were computed.
    pub extensions: Option<Extensions>,
}

/// Simple wrapper around AccessTokenError to imbue the type with addtional json functionality. In
/// addition this enforces backend specific behaviour for obtaining or handling the access error.
#[derive(Clone)]
pub struct ErrorDescription {
    pub(crate) error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

/// Represents an access token, a refresh token and the associated scope for serialization.
pub struct BearerToken(pub(crate) IssuedToken, pub(crate) Scope);

impl Error {
    /// Create invalid error type
    pub fn invalid() -> Self {
        Error::Invalid(ErrorDescription {
            error: AccessTokenError::default(),
        })
    }

    pub(crate) fn invalid_with(with_type: AccessTokenErrorType) -> Self {
        Error::Invalid(ErrorDescription {
            error: {
                let mut error = AccessTokenError::default();
                error.set_type(with_type);
                error
            },
        })
    }

    /// Create unauthorized error type
    pub fn unauthorized(authtype: &str) -> Error {
        Error::Unauthorized(
            ErrorDescription {
                error: {
                    let mut error = AccessTokenError::default();
                    error.set_type(AccessTokenErrorType::InvalidClient);
                    error
                },
            },
            authtype.to_string(),
        )
    }

    /// Get a handle to the description the client will receive.
    ///
    /// Some types of this error don't return any description which is represented by a `None`
    /// result.
    pub fn description(&mut self) -> Option<&mut AccessTokenError> {
        match self {
            Error::Invalid(description) => Some(description.description()),
            Error::Unauthorized(description, _) => Some(description.description()),
            Error::Primitive(_) => None,
        }
    }
}

impl PrimitiveError {
    /// Create a default empty error
    pub fn empty() -> Self {
        PrimitiveError {
            grant: None,
            extensions: None,
        }
    }
}

impl ErrorDescription {
    /// Create this from an access token error
    pub fn new(error: AccessTokenError) -> Self {
        Self { error }
    }

    /// Convert the error into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(&self) -> String {
        let asmap = self
            .error
            .iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect::<HashMap<String, String>>();
        serde_json::to_string(&asmap).unwrap()
    }

    /// Get a handle to the description the client will receive.
    pub fn description(&mut self) -> &mut AccessTokenError {
        &mut self.error
    }
}

impl BearerToken {
    /// Convert the token into a json string, viable for being sent over a network with
    /// `application/json` encoding.
    pub fn to_json(&self) -> String {
        let remaining = self.0.until.signed_duration_since(Utc::now());
        let token_response = TokenResponse {
            access_token: Some(self.0.token.clone()),
            refresh_token: self.0.refresh.clone(),
            token_type: Some("bearer".to_owned()),
            expires_in: Some(remaining.num_seconds()),
            scope: Some(self.1.to_string()),
            error: None,
        };

        serde_json::to_string(&token_response).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::issuer::TokenType;

    #[test]
    fn bearer_token_encoding() {
        let token = BearerToken(
            IssuedToken {
                token: "access".into(),
                refresh: Some("refresh".into()),
                until: Utc::now(),
                token_type: TokenType::Bearer,
            },
            "scope".parse().unwrap(),
        );

        let json = token.to_json();
        let token = serde_json::from_str::<TokenResponse>(&json).unwrap();

        assert_eq!(token.access_token, Some("access".to_owned()));
        assert_eq!(token.refresh_token, Some("refresh".to_owned()));
        assert_eq!(token.scope, Some("scope".to_owned()));
        assert_eq!(token.token_type, Some("bearer".to_owned()));
        assert!(token.expires_in.is_some());
    }

    #[test]
    fn no_refresh_encoding() {
        let token = BearerToken(
            IssuedToken::without_refresh("access".into(), Utc::now()),
            "scope".parse().unwrap(),
        );

        let json = token.to_json();
        let token = serde_json::from_str::<TokenResponse>(&json).unwrap();

        assert_eq!(token.access_token, Some("access".to_owned()));
        assert_eq!(token.refresh_token, None);
        assert_eq!(token.scope, Some("scope".to_owned()));
        assert_eq!(token.token_type, Some("bearer".to_owned()));
        assert!(token.expires_in.is_some());
    }
}
