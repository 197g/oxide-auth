//! Retrieve a refreshed access token.
use std::borrow::Cow;
use std::collections::HashMap;

use chrono::{Duration, Utc};

use crate::{
    OAuthOpaqueError,
    code_grant::{
        accesstoken::TokenResponse,
        error::{AccessTokenError, AccessTokenErrorType},
    },
};
use crate::primitives::grant::Grant;
use crate::primitives::issuer::{RefreshedToken, Issuer};
use crate::primitives::registrar::{Registrar, RegistrarError};

/// Required content of a refresh request.
///
/// See [Refreshing an Access Token] in the rfc.
///
/// [Refreshing an Access Token]: https://tools.ietf.org/html/rfc6749#section-6
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// The refresh token with which to refresh.
    fn refresh_token(&self) -> Option<Cow<'_, str>>;

    /// Optionally specifies the requested scope
    fn scope(&self) -> Option<Cow<'_, str>>;

    /// Valid requests have this set to "refresh_token"
    fn grant_type(&self) -> Option<Cow<'_, str>>;

    /// User:password of a basic authorization header.
    fn authorization(&self) -> Option<(Cow<'_, str>, Cow<'_, [u8]>)>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<'_, str>>;
}

/// The specific endpoint trait for refreshing.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
///
/// This is the utility trait used by [`refresh`] to provide a simple loop around the [`Refresh`]
/// state machine, the trait objects returned are used to fulfill the input requests.
///
/// [`refresh`]: method.refresh.html
/// [`Refresh`]: struct.Refresh.html
pub trait Endpoint {
    /// Authenticate the requesting confidential client.
    fn registrar(&self) -> &dyn Registrar;

    /// Recover and test the provided refresh token then issue new tokens.
    fn issuer(&mut self) -> &mut dyn Issuer;
}

/// Represents a bearer token, optional refresh token and the associated scope for serialization.
#[derive(Debug)]
pub struct BearerToken(RefreshedToken, String);

/// An ongoing refresh request.
///
/// This is a rather linear Mealy machine with four basic phases. It will pose some requests in the
/// form of [`Output`] which should be satisfied with the next [`Input`] data. This will eventually
/// produce a refreshed [`BearerToken`] or an [`Error`]. Note that the executing environment will
/// need to use a [`Registrar`] and an [`Issuer`] to which some requests should be forwarded.
///
/// [`Input`]: struct.Input.html
/// [`Output`]: struct.Output.html
/// [`BearerToken`]: struct.BearerToken.html
/// [`Error`]: struct.Error.html
/// [`Issuer`] ../primitives/issuer/trait.Issuer.html
/// [`Registrar`] ../primitives/registrar/trait.Registrar.html
///
/// A rough sketch of the operational phases:
///
/// 1. Ensure the request is valid based on the basic requirements (includes required parameters)
/// 2. Check any included authentication
/// 3. Try to recover the refresh token
///    3.1. Check that it belongs to the authenticated client
///    3.2. If there was no authentication, assert token does not require authentication
///    3.3. Check the intrinsic validity (timestamp, scope)
/// 4. Query the backend for a renewed (bearer) token
#[derive(Debug)]
pub struct Refresh {
    state: RefreshState,
}

/// Inner state machine for refreshing.
#[derive(Debug)]
enum RefreshState {
    /// State we reach after the request has been validated.
    ///
    /// Next, the registrar must verify the authentication (authorization header).
    Authenticating {
        client: String,
        passdata: Option<Vec<u8>>,
        token: String,
    },
    /// State after authorization has passed, waiting on recovering the refresh token.
    Recovering {
        /// The user the registrar verified.
        authenticated: Option<String>,
        token: String,
    },
    /// State after the token has been determined but no authenticated client was used. Need to
    /// potentially wait on grant-to-authorized-user-correspondence matching.
    CoAuthenticating {
        /// The restored grant.
        grant: Box<Grant>,
        /// The refresh token of the grant.
        token: String,
    },
    /// State when we await the issuing of a refreshed token.
    Issuing {
        /// The grant with the parameter set.
        grant: Box<Grant>,
        /// The refresh token of the grant.
        token: String,
    },
    /// State after an error occurred.
    Err(Error),
}

/// An input injected by the executor into the state machine.
#[derive(Clone)]
pub enum Input<'req> {
    /// Positively answer an authentication query.
    Authenticated {
        /// The required scope to access the resource.
        scope: Option<Cow<'req, str>>,
    },
    /// Provide the queried refresh token.
    Recovered {
        /// The required scope to access the resource.
        scope: Option<Cow<'req, str>>,
        /// The grant
        grant: Option<Box<Grant>>,
    },
    /// The refreshed token.
    Refreshed(RefreshedToken),
    /// Advance without input as far as possible, or just retrieve the output again.
    None,
}

/// A request by the statemachine to the executor.
///
/// Each variant is fulfilled by certain variants of the next inputs as an argument to
/// `Refresh::next`. The output of most states is simply repeated if `Input::None` is provided
/// instead but note that the successful bearer token response is **not** repeated.
///
/// This borrows data from the underlying state machine, so you need to drop it before advancing it
/// with newly provided input.
#[derive(Debug)]
pub enum Output<'a> {
    /// The registrar should authenticate a client.
    ///
    /// Fulfilled by `Input::Authenticated`. In an unsuccessful case, the executor should not
    /// continue and discard the flow.
    Unauthenticated {
        /// The to-be-authenticated client.
        client: &'a str,
        /// The supplied passdata/password.
        pass: Option<&'a [u8]>,
    },
    /// The issuer should try to recover the grant of a refresh token.
    ///
    /// Fulfilled by `Input::Recovered`.
    RecoverRefresh {
        /// The token supplied by the client.
        token: &'a str,
    },
    /// The issuer should issue a refreshed code grant token.
    ///
    /// Fulfilled by `Input::Refreshed`.
    Refresh {
        /// The refresh token that has been used.
        token: &'a str,
        /// The grant that should be issued as determined.
        grant: Box<Grant>,
    },
    /// The state machine finished and a new bearer token was generated.
    ///
    /// This output **can not** be requested repeatedly, any future `Input` will yield a primitive
    /// error instead.
    Ok(BearerToken),
    /// The state machine finished in an error.
    ///
    /// The error will be repeated on *any* following input.
    Err(Error),
}

/// Defines actions for the response to an access token request.
#[derive(Clone, Debug)]
pub enum Error {
    /// The token did not represent a valid token.
    Invalid(ErrorDescription),

    /// The client did not properly authorize itself.
    Unauthorized(ErrorDescription, String),

    /// An underlying primitive operation did not complete successfully.
    ///
    /// This is expected to occur with some endpoints. See `PrimitiveError` for
    /// more details on when this is returned.
    Primitive,
}

/// Simple wrapper around RefreshError.
///
/// Enables additional json functionality to generate a properly formatted response in the user of
/// this module.
#[derive(Clone, Debug)]
pub struct ErrorDescription {
    pub(crate) error: AccessTokenError,
}

type Result<T> = std::result::Result<T, Error>;

impl Refresh {
    /// Construct a new refresh state machine.
    ///
    /// This borrows the request for the duration of the request execution to ensure consistency of
    /// all client input.
    pub fn new(request: &dyn Request) -> Self {
        Refresh {
            state: initialize(request).unwrap_or_else(RefreshState::Err),
        }
    }

    /// Advance the state machine.
    ///
    /// The provided `Input` needs to fulfill the *previous* `Output` request. See their
    /// documentation for more information.
    pub fn advance<'req>(&mut self, input: Input<'req>) -> Output<'_> {
        // Run the next state transition if we got the right input. Errors that happen will be
        // stored as a inescapable error state.
        match (self.take(), input) {
            (RefreshState::Err(error), _) => {
                self.state = RefreshState::Err(error.clone());
                Output::Err(error)
            }
            (
                RefreshState::Authenticating {
                    client,
                    passdata: _,
                    token,
                },
                Input::Authenticated { .. },
            ) => {
                self.state = authenticated(client, token);
                self.output()
            }
            (RefreshState::Recovering { authenticated, token }, Input::Recovered { scope, grant }) => {
                self.state = recovered_refresh(scope, authenticated, grant, token)
                    .unwrap_or_else(RefreshState::Err);
                self.output()
            }
            (RefreshState::CoAuthenticating { grant, token }, Input::Authenticated { scope }) => {
                self.state = co_authenticated(scope, grant, token).unwrap_or_else(RefreshState::Err);
                self.output()
            }
            (RefreshState::Issuing { grant, token: _ }, Input::Refreshed(token)) => {
                // Ensure that this result is not duplicated.
                self.state = RefreshState::Err(Error::Primitive);
                Output::Ok(issued(grant, token))
            }
            (current, Input::None) => {
                match current {
                    RefreshState::Authenticating { .. } => self.state = current,
                    RefreshState::Recovering { .. } => self.state = current,
                    RefreshState::CoAuthenticating { .. } => (),
                    RefreshState::Issuing { .. } => (),
                    RefreshState::Err(_) => (),
                }
                self.output()
            }
            (_, _) => {
                self.state = RefreshState::Err(Error::Primitive);
                self.output()
            }
        }
    }

    fn take(&mut self) -> RefreshState {
        core::mem::replace(&mut self.state, RefreshState::Err(Error::Primitive))
    }

    fn output(&self) -> Output<'_> {
        match &self.state {
            RefreshState::Authenticating { client, passdata, .. } => Output::Unauthenticated {
                client,
                pass: passdata.as_ref().map(|vec| vec.as_slice()),
            },
            RefreshState::CoAuthenticating { grant, .. } => Output::Unauthenticated {
                client: &grant.client_id,
                pass: None,
            },
            RefreshState::Recovering { token, .. } => Output::RecoverRefresh { token },
            RefreshState::Issuing { token, grant, .. } => Output::Refresh {
                token,
                grant: grant.clone(),
            },
            RefreshState::Err(error) => Output::Err(error.clone()),
        }
    }
}

impl<'req> Input<'req> {
    /// Take the current value of Input and replace it with `Input::None`
    pub fn take(&mut self) -> Self {
        core::mem::replace(self, Input::None)
    }
}

/// Try to get a refreshed access token.
///
/// This has four basic phases:
/// 1. Ensure the request is valid based on the basic requirements (includes required parameters)
/// 2. Check any included authentication
/// 3. Try to recover the refresh token
///    3.1. Check that it belongs to the authenticated client
///    3.2. If there was no authentication, assert token does not require authentication
///    3.3. Check the intrinsic validity (timestamp, scope)
/// 4. Query the backend for a renewed (bearer) token
pub fn refresh(handler: &mut dyn Endpoint, request: &dyn Request) -> Result<BearerToken> {
    enum Requested {
        None,
        Refresh { token: String, grant: Box<Grant> },
        RecoverRefresh { token: String },
        Authenticate { client: String, pass: Option<Vec<u8>> },
    }
    let mut refresh = Refresh::new(request);
    let mut requested = Requested::None;
    loop {
        let input = match requested {
            Requested::None => Input::None,
            Requested::Refresh { token, grant } => {
                let refreshed = handler
                    .issuer()
                    .refresh(&token, *grant)
                    .map_err(|OAuthOpaqueError| Error::Primitive)?;
                Input::Refreshed(refreshed)
            }
            Requested::RecoverRefresh { token } => {
                let recovered = handler
                    .issuer()
                    .recover_refresh(&token)
                    .map_err(|OAuthOpaqueError| Error::Primitive)?;
                Input::Recovered {
                    scope: request.scope(),
                    grant: recovered.map(Box::new),
                }
            }
            Requested::Authenticate { client, pass } => {
                let _: () =
                    handler
                        .registrar()
                        .check(&client, pass.as_deref())
                        .map_err(|err| match err {
                            RegistrarError::PrimitiveError => Error::Primitive,
                            RegistrarError::Unspecified => Error::unauthorized("basic"),
                        })?;
                Input::Authenticated {
                    scope: request.scope(),
                }
            }
        };

        requested = match refresh.advance(input) {
            Output::Err(error) => return Err(error),
            Output::Ok(token) => return Ok(token),
            Output::Refresh { token, grant } => Requested::Refresh {
                token: token.to_string(),
                grant,
            },
            Output::RecoverRefresh { token } => Requested::RecoverRefresh {
                token: token.to_string(),
            },
            Output::Unauthenticated { client, pass } => Requested::Authenticate {
                client: client.to_string(),
                pass: pass.map(|p| p.to_vec()),
            },
        };
    }
}

fn initialize(request: &dyn Request) -> Result<RefreshState> {
    if !request.valid() {
        return Err(Error::invalid(AccessTokenErrorType::InvalidRequest));
    }

    // REQUIRED, so not having it makes it an invalid request.
    let token = request.refresh_token();
    let token = token.ok_or_else(|| Error::invalid(AccessTokenErrorType::InvalidRequest))?;

    // REQUIRED, otherwise invalid request.
    match request.grant_type() {
        Some(ref cow) if cow == "refresh_token" => (),
        None => return Err(Error::invalid(AccessTokenErrorType::InvalidRequest)),
        Some(_) => return Err(Error::invalid(AccessTokenErrorType::UnsupportedGrantType)),
    };

    match request.authorization() {
        Some((client, passdata)) => Ok(RefreshState::Authenticating {
            client: client.into_owned(),
            passdata: Some(passdata.to_vec()),
            token: token.into_owned(),
        }),
        None => Ok(RefreshState::Recovering {
            token: token.into_owned(),
            authenticated: None,
        }),
    }
}

fn authenticated(client: String, token: String) -> RefreshState {
    // Trivial, simply advance to recovering the token.
    RefreshState::Recovering {
        token,
        authenticated: Some(client),
    }
}

fn recovered_refresh(
    scope: Option<Cow<str>>, authenticated: Option<String>, grant: Option<Box<Grant>>, token: String,
) -> Result<RefreshState> {
    let grant = grant
        // ... is invalid, ... (Section 5.2)
        .ok_or_else(|| Error::invalid(AccessTokenErrorType::InvalidGrant))?;

    // ... MUST ensure that the refresh token was issued to the authenticated client.
    match authenticated {
        Some(client) => {
            if grant.client_id.as_str() != client {
                // ... or was issued to another client (Section 5.2)
                // importantly, the client authentication itself was okay, so we don't respond with
                // Unauthorized but with BadRequest.
                Err(Error::invalid(AccessTokenErrorType::InvalidGrant))
            } else {
                validate(scope, grant, token)
            }
        }

        // ... MUST require client authentication for confidential clients.
        //
        // We'll see if this was confidential by trying to auth with no passdata. If that fails,
        // then the client should have authenticated with header information.
        None => Ok(RefreshState::CoAuthenticating { grant, token }),
    }
}

fn co_authenticated(scope: Option<Cow<str>>, grant: Box<Grant>, token: String) -> Result<RefreshState> {
    validate(scope, grant, token)
}

fn validate(scope: Option<Cow<str>>, grant: Box<Grant>, token: String) -> Result<RefreshState> {
    // .. is expired, revoked, ... (Section 5.2)
    if grant.until <= Utc::now() {
        return Err(Error::invalid(AccessTokenErrorType::InvalidGrant));
    }

    let scope = match scope {
        // ... is invalid, unknown, malformed (Section 5.2)
        Some(scope) => Some(
            scope
                .parse()
                .map_err(|_| Error::invalid(AccessTokenErrorType::InvalidScope))?,
        ),
        None => None,
    };

    let scope = match scope {
        Some(scope) => {
            // ... MUST NOT include any scope not originally granted.
            if !grant.scope.priviledged_to(&scope) {
                // ... or exceeds the scope grant (Section 5.2)
                return Err(Error::invalid(AccessTokenErrorType::InvalidScope));
            }
            scope
        }
        // ... if omitted is treated as equal to the scope originally granted
        None => grant.scope.clone(),
    };

    // Update the grant with the derived data.
    let mut grant = grant;
    grant.scope = scope;
    grant.until = Utc::now() + Duration::hours(1);

    Ok(RefreshState::Issuing { grant, token })
}

fn issued(grant: Box<Grant>, token: RefreshedToken) -> BearerToken {
    BearerToken(token, grant.scope.to_string())
}

impl Error {
    fn invalid(kind: AccessTokenErrorType) -> Self {
        Error::Invalid(ErrorDescription {
            error: AccessTokenError::new(kind),
        })
    }

    /// Create unauthorized error type
    pub fn unauthorized(authtype: &str) -> Self {
        Error::Unauthorized(
            ErrorDescription {
                // ... authentication failed (Section 5.2)
                error: AccessTokenError::new(AccessTokenErrorType::InvalidClient),
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
            Error::Primitive => None,
        }
    }
}

impl ErrorDescription {
    /// Get a handle to the description the client will receive.
    pub fn description(&mut self) -> &mut AccessTokenError {
        &mut self.error
    }

    /// Convert the error into a json string.
    ///
    /// The string may be the content of an `application/json` body for example.
    pub fn to_json(&self) -> String {
        let asmap = self
            .error
            .iter()
            .map(|(k, v)| (k.to_string(), v.into_owned()))
            .collect::<HashMap<String, String>>();
        serde_json::to_string(&asmap).unwrap()
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
            scope: Some(self.1.clone()),
            error: None,
        };

        serde_json::to_string(&token_response).unwrap()
    }
}
