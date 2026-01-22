//! Provides the handling for Resource Requests.
use std::{fmt, mem};
use std::borrow::Cow;

use chrono::Utc;

use crate::primitives::issuer::Issuer;
use crate::primitives::grant::Grant;
use crate::primitives::scope::Scope;

/// Gives additional information about the reason for an access failure.
///
/// According to [rfc6750], this should not be returned if the client has not provided any
/// authentication information.
///
/// [rfc6750]: https://tools.ietf.org/html/rfc6750#section-3.1
#[derive(Clone, Debug)]
pub struct AccessFailure {
    /// The standard error code representation.
    pub code: Option<ErrorCode>,
}

/// Indicates the reason for access failure.
#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    /// The request did not have enough authorization data or was otherwise malformed.
    InvalidRequest,

    /// The provided authorization did not grant sufficient priviledges.
    InsufficientScope,

    /// The token is expired, revoked, malformed or otherwise does not meet expectations.
    InvalidToken,
}

/// Additional information provided for the WWW-Authenticate header.
#[derive(Clone, Debug)]
pub struct Authenticate {
    /// Information about which realm the credentials correspond to.
    pub realm: Option<String>,

    /// The required scope to access the resource.
    pub scope: Option<Scope>,
}

/// An error signalling the resource access was not permitted.
#[derive(Clone, Debug)]
pub enum Error {
    /// The client tried to access a resource but was not able to.
    AccessDenied {
        /// A specific cause for denying access.
        failure: AccessFailure,

        /// Information for the `Authenticate` header in the error response.
        authenticate: Authenticate,
    },

    /// The client did not provide any bearer authentication.
    NoAuthentication {
        /// Information for the `Authenticate` header in the error response.
        authenticate: Authenticate,
    },

    /// The request itself was malformed.
    InvalidRequest {
        /// Information for the `Authenticate` header in the error response.
        authenticate: Authenticate,
    },

    /// Some part of the endpoint failed, defer to endpoint for handling.
    PrimitiveError,
}

const BEARER_START: &str = "Bearer ";

type Result<T> = std::result::Result<T, Error>;

/// Required request methods for deciding on the rights to access a protected resource.
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// The authorization used in the request.
    ///
    /// Expects the complete `Authorization` HTTP-header, including the qualification as `Bearer`.
    /// In case the client included multiple forms of authorization, this method MUST return None
    /// and the request SHOULD be marked as invalid.
    fn token(&self) -> Option<Cow<'_, str>>;
}

/// Required functionality to respond to resource requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// The list of possible scopes required by the resource endpoint.
    fn scopes(&mut self) -> &[Scope];

    /// Issuer which provides the tokens used for authorization by the client.
    fn issuer(&mut self) -> &dyn Issuer;
}

/// The result will indicate whether the resource access should be allowed or not.
pub struct Resource {
    state: ResourceState,
}

enum ResourceState {
    /// The initial state.
    New,
    /// State after request has been validated.
    Internalized { token: String },
    /// State after scopes have been determined.
    Recovering { token: String, scopes: Vec<Scope> },
    /// State after an error occurred.
    Err(Error),
}

/// An input injected by the executor into the state machine.
#[derive(Clone)]
pub enum Input<'req> {
    /// Provide the queried (bearer) token.
    Recovered(Option<Grant>),
    /// Determine the scopes of requested resource.
    Scopes(&'req [Scope]),
    /// Provides simply the original request.
    Request {
        /// The request
        request: &'req dyn Request,
    },
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
#[derive(Clone, Debug)]
pub enum Output<'machine> {
    /// The state requires some information from the request to advance.
    GetRequest,
    /// The issuer should try to recover the grant of a bearer token.
    ///
    /// Fulfilled by `Input::Recovered`.
    Recover {
        /// The token supplied by the client.
        token: &'machine str,
    },
    /// The executor must determine the scopes applying to the resource.
    ///
    /// Fulfilled by `Input::Scopes`.
    DetermineScopes,
    /// The state machine finished and access was allowed.
    ///
    /// Returns the grant with which access was granted in case a detailed inspection or logging is
    /// required.
    ///
    /// This output **can not** be requested repeatedly, any future `Input` will yield a primitive
    /// error instead.
    Ok(Box<Grant>),
    /// The state machine finished in an error.
    ///
    /// The error will be repeated on *any* following input.
    Err(Error),
}

impl Resource {
    /// Create a Resource state machine at `ResourceState::New` state
    pub fn new() -> Self {
        Resource {
            state: ResourceState::New,
        }
    }

    /// Progress the state machine to next step, taking in needed `Input` parameters
    pub fn advance(&mut self, input: Input) -> Output<'_> {
        self.state = match (self.take(), input) {
            (any, Input::None) => any,
            (ResourceState::New, Input::Request { request }) => {
                validate(request).unwrap_or_else(ResourceState::Err)
            }
            (ResourceState::Internalized { token }, Input::Scopes(scopes)) => get_scopes(token, scopes),
            (ResourceState::Recovering { token: _, scopes }, Input::Recovered(grant)) => {
                match recovered(grant, scopes) {
                    Ok(grant) => return Output::Ok(Box::new(grant)),
                    Err(err) => ResourceState::Err(err),
                }
            }
            _ => return Output::Err(Error::PrimitiveError),
        };

        self.output()
    }

    fn output(&self) -> Output<'_> {
        match &self.state {
            ResourceState::New => Output::GetRequest,
            ResourceState::Internalized { .. } => Output::DetermineScopes,
            ResourceState::Recovering { token, .. } => Output::Recover { token },
            ResourceState::Err(error) => Output::Err(error.clone()),
        }
    }

    fn take(&mut self) -> ResourceState {
        mem::replace(&mut self.state, ResourceState::Err(Error::PrimitiveError))
    }
}

impl Default for Resource {
    fn default() -> Self {
        Self::new()
    }
}

/// Do needed verification before granting access to the resource
pub fn protect(handler: &mut dyn Endpoint, req: &dyn Request) -> Result<Grant> {
    enum Requested {
        None,
        Request,
        Scopes,
        Grant(String),
    }

    let mut resource = Resource::new();
    let mut requested = Requested::None;
    loop {
        let input = match requested {
            Requested::None => Input::None,
            Requested::Request => Input::Request { request: req },
            Requested::Scopes => Input::Scopes(handler.scopes()),
            Requested::Grant(token) => {
                let grant = handler
                    .issuer()
                    .recover_token(&token)
                    .map_err(|_| Error::PrimitiveError)?;
                Input::Recovered(grant)
            }
        };

        requested = match resource.advance(input) {
            Output::Err(error) => return Err(error),
            Output::Ok(grant) => return Ok(*grant),
            Output::GetRequest => Requested::Request,
            Output::DetermineScopes => Requested::Scopes,
            Output::Recover { token } => Requested::Grant(token.to_string()),
        };
    }
}

fn validate(request: &'_ dyn Request) -> Result<ResourceState> {
    if !request.valid() {
        return Err(Error::InvalidRequest {
            authenticate: Authenticate::empty(),
        });
    }

    let client_token = match request.token() {
        Some(token) => token,
        None => {
            return Err(Error::NoAuthentication {
                authenticate: Authenticate::empty(),
            })
        }
    };

    if !client_token
        .to_uppercase()
        .starts_with(&BEARER_START.to_uppercase())
    {
        return Err(Error::InvalidRequest {
            authenticate: Authenticate::empty(),
        });
    }

    let token = match client_token {
        Cow::Borrowed(token) => token[BEARER_START.len()..].to_string(),
        Cow::Owned(mut token) => token.split_off(BEARER_START.len()),
    };

    Ok(ResourceState::Internalized { token })
}

fn get_scopes(token: String, scopes: &'_ [Scope]) -> ResourceState {
    ResourceState::Recovering {
        token,
        scopes: scopes.to_owned(),
    }
}

fn recovered(grant: Option<Grant>, mut scopes: Vec<Scope>) -> Result<Grant> {
    let grant = match grant {
        Some(grant) => grant,
        None => {
            return Err(Error::AccessDenied {
                failure: AccessFailure {
                    code: Some(ErrorCode::InvalidRequest),
                },
                authenticate: Authenticate {
                    realm: None,
                    // TODO. Don't drop the other scopes?
                    scope: scopes.drain(..).next(),
                },
            });
        }
    };

    if grant.until < Utc::now() {
        return Err(Error::AccessDenied {
            failure: AccessFailure {
                code: Some(ErrorCode::InvalidToken),
            },
            authenticate: Authenticate::empty(),
        });
    }

    let allowing = scopes
        .iter()
        .find(|resource_scope| resource_scope.allow_access(&grant.scope));

    if allowing.is_none() {
        return Err(Error::AccessDenied {
            failure: AccessFailure {
                code: Some(ErrorCode::InsufficientScope),
            },
            authenticate: Authenticate {
                realm: None,
                scope: scopes.drain(..).next(),
            },
        });
    }

    // TODO: should we return the allowing scope?
    Ok(grant)
}

impl ErrorCode {
    fn description(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "invalid_request",
            ErrorCode::InsufficientScope => "insufficient_scope",
            ErrorCode::InvalidToken => "invalid_token",
        }
    }
}

struct BearerHeader {
    content: String,
    first_option: bool,
}

impl BearerHeader {
    fn new() -> Self {
        BearerHeader {
            content: "Bearer".to_string(),
            first_option: true,
        }
    }

    fn add_option(&mut self, args: fmt::Arguments) {
        if self.first_option {
            self.content.push(' ');
        } else {
            self.content.push(',');
        }
        fmt::write(&mut self.content, args).unwrap();
    }

    fn add_kvp(&mut self, key: &'static str, value: Option<impl fmt::Display>) {
        if let Some(value) = value {
            self.add_option(format_args!("{}=\"{}\"", key, value));
        }
    }

    fn finalize(self) -> String {
        self.content
    }
}

impl Authenticate {
    fn empty() -> Self {
        Authenticate {
            realm: None,
            scope: None,
        }
    }

    fn extend_header(self, header: &mut BearerHeader) {
        header.add_kvp("realm", self.realm);
        header.add_kvp("scope", self.scope);
    }
}

impl AccessFailure {
    fn extend_header(self, header: &mut BearerHeader) {
        header.add_kvp("error", self.code.map(ErrorCode::description));
    }
}

impl Error {
    /// Convert the guard error into the content used in an WWW-Authenticate header.
    pub fn www_authenticate(self) -> String {
        let mut header = BearerHeader::new();
        match self {
            Error::AccessDenied {
                failure,
                authenticate,
            } => {
                failure.extend_header(&mut header);
                authenticate.extend_header(&mut header);
            }
            Error::NoAuthentication { authenticate } => {
                authenticate.extend_header(&mut header);
            }
            Error::InvalidRequest { authenticate } => {
                authenticate.extend_header(&mut header);
            }
            Error::PrimitiveError => (),
        }
        header.finalize()
    }
}
