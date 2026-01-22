//! Provides the handling for Access Token Requests
use std::mem;
use std::borrow::Cow;

use chrono::{Utc, Duration};

use crate::code_grant::accesstoken::BearerToken;
use crate::code_grant::error::{AccessTokenError, AccessTokenErrorType};
use crate::endpoint::{Scope, Solicitation};
use crate::primitives::issuer::Issuer;
use crate::primitives::grant::{Extensions, Grant};
use crate::primitives::registrar::{Registrar, RegistrarError, BoundClient, PreGrant, ClientUrl};

use super::accesstoken::{ErrorDescription, PrimitiveError};

/// Required content of a client credentials request.
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// User:password of a basic authorization header.
    fn authorization(&self) -> Option<(Cow<'_, str>, Cow<'_, [u8]>)>;

    /// Optionally specifies the requested scope
    fn scope(&self) -> Option<Cow<'_, str>>;

    /// Valid requests have this set to "client_credentials"
    fn grant_type(&self) -> Option<Cow<'_, str>>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<'_, str>>;

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
    fn allow_refresh_token(&self) -> bool {
        false
    }
}

/// A system of addons provided additional data.
///
/// An endpoint not having any extension may use `&mut ()` as the result of system.
pub trait Extension {
    /// Inspect the request to produce extension data.
    fn extend(&mut self, request: &dyn Request) -> std::result::Result<Extensions, ()>;
}

impl Extension for () {
    fn extend(&mut self, _: &dyn Request) -> std::result::Result<Extensions, ()> {
        Ok(Extensions::new())
    }
}

/// Required functionality to respond to client credentials requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// Get the client corresponding to some id.
    fn registrar(&self) -> &dyn Registrar;

    /// Return the issuer instance to create the client credentials.
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
    /// As the client credentials may not be used for public clients, this is
    /// actually an error.
    Unauthenticated,
    /// Multiple possible credentials were offered.
    ///
    /// This is a security issue, only one attempt must be made per request.
    Duplicate,
}

/// Client credentials token issuing process
///
/// This state machine will go through four phases. On creation, the request will be validated and
/// parameters for the first step will be extracted from it. It will pose some requests in the form
/// of [`Output`] which should be satisfied with the next [`Input`] data. This will eventually
/// produce a [`BearerToken`] or an [`Error`]. Note that the executing environment will need to use
/// a [`Registrar`], an optional [`Extension`] and an [`Issuer`] to which some requests should be forwarded.
///
/// [`Input`]: struct.Input.html
/// [`Output`]: struct.Output.html
/// [`BearerToken`]: struct.BearerToken.html
/// [`Error`]: struct.Error.html
/// [`Issuer`] ../primitives/issuer/trait.Issuer.html
/// [`Registrar`] ../primitives/registrar/trait.Registrar.html
/// [`Extension`] trait.Extension.html
///
/// A rough sketch of the operational phases:
///
/// 1. Ensure the request is valid based on the basic requirements (includes required parameters)
/// 2. Try to produce a new token
///    2.1. Authenticate the client
///    2.2. Construct a grant based on the request
///    2.3. Check the intrinsic validity (scope)
/// 3. Query the backend for a new (bearer) token
pub struct ClientCredentials {
    state: ClientCredentialsState,
    scope: Option<Scope>,
}

/// Inner state machine for client credentials
enum ClientCredentialsState {
    Authenticate {
        client: String,
        passdata: Vec<u8>,
    },
    Binding {
        client_id: String,
    },
    Extend {
        bound_client: BoundClient<'static>,
    },
    Negotiating {
        bound_client: BoundClient<'static>,
        extensions: Extensions,
    },
    Issue {
        pre_grant: PreGrant,
        extensions: Extensions,
    },
    Err(Error),
}

/// Input injected by the executor into the state machine.
pub enum Input {
    /// Positively answer an authentication query.
    Authenticated,
    /// Binding of the client succeeded
    Bound {
        /// The bound client
        bound_client: BoundClient<'static>,
    },
    /// Provide extensions
    Extended {
        /// The grant extension
        extensions: Extensions,
    },
    /// Negotiation done
    Negotiated {
        /// The pre grant from the negotiation
        pre_grant: PreGrant,
    },
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
        passdata: &'machine [u8],
    },
    /// Ask registrar to bind the client. There is no redirect URI provided from the request,
    /// so the registrar will have to pick one arbitrarily (or return an invalid one). Ths
    /// redirect URL will not be followed.
    ///
    /// Fulfilled by `Input::Bound`
    Binding {
        /// The client to bind
        client_id: &'machine str,
    },
    /// The extension (if any) should provide the extensions
    ///
    /// Fullfilled by `Input::Extended`
    Extend,
    /// Ask registrar to negotiate.
    ///
    /// Fulfilled by `Input::Negotiated`
    Negotiate {
        /// The current bound client
        bound_client: &'machine BoundClient<'static>,
        /// The scope, if any
        scope: Option<Scope>,
    },
    /// The state machine finished and the frontend should assign an owner ID and then
    /// issue the token.
    ///
    /// Fullfilled by `Input::Issued`
    Ok {
        /// The grant to be used in the token generation
        pre_grant: &'machine PreGrant,
        /// The extensions to include
        extensions: &'machine Extensions,
    },
    /// The state machine finished in an error.
    ///
    /// The error will be repeated on *any* following input.
    Err(Box<Error>),
}

impl ClientCredentials {
    /// Create the state machine. validating the request in the process
    pub fn new(request: &dyn Request) -> Self {
        let (state, scope) =
            Self::validate(request).unwrap_or_else(|err| (ClientCredentialsState::Err(err), None));
        ClientCredentials { state, scope }
    }

    /// Go to next state
    pub fn advance(&mut self, input: Input) -> Output<'_> {
        self.state = match (self.take(), input) {
            (current, Input::None) => current,
            (ClientCredentialsState::Authenticate { client, .. }, Input::Authenticated) => {
                Self::authenticated(client)
            }
            (ClientCredentialsState::Binding { .. }, Input::Bound { bound_client }) => {
                Self::bound(bound_client)
            }
            (ClientCredentialsState::Extend { bound_client }, Input::Extended { extensions }) => {
                Self::extended(bound_client, extensions)
            }
            (
                ClientCredentialsState::Negotiating { extensions, .. },
                Input::Negotiated { pre_grant },
            ) => Self::negotiated(pre_grant, extensions),
            (ClientCredentialsState::Err(err), _) => ClientCredentialsState::Err(err),
            (_, _) => ClientCredentialsState::Err(Error::Primitive(Box::new(PrimitiveError::empty()))),
        };

        self.output()
    }

    fn output(&self) -> Output<'_> {
        match &self.state {
            ClientCredentialsState::Err(err) => Output::Err(Box::new(err.clone())),
            ClientCredentialsState::Authenticate { client, passdata, .. } => Output::Authenticate {
                client,
                passdata: passdata.as_slice(),
            },
            ClientCredentialsState::Binding { client_id } => Output::Binding { client_id },
            ClientCredentialsState::Extend { .. } => Output::Extend,
            ClientCredentialsState::Negotiating { bound_client, .. } => Output::Negotiate {
                bound_client,
                scope: self.scope.clone(),
            },
            ClientCredentialsState::Issue {
                pre_grant,
                extensions,
            } => Output::Ok {
                pre_grant,
                extensions,
            },
        }
    }

    fn take(&mut self) -> ClientCredentialsState {
        mem::replace(
            &mut self.state,
            ClientCredentialsState::Err(Error::Primitive(Box::new(PrimitiveError::empty()))),
        )
    }

    fn validate(request: &dyn Request) -> Result<(ClientCredentialsState, Option<Scope>)> {
        if !request.valid() {
            return Err(Error::invalid());
        }

        let authorization = request.authorization();
        let client_id = request.extension("client_id");
        let client_secret = request.extension("client_secret");

        let mut credentials = Credentials::None;
        if let Some((client_id, auth)) = &authorization {
            credentials.authenticate(client_id.as_ref(), auth.as_ref());
        }

        match (&client_id, &client_secret) {
            (Some(client_id), Some(client_secret)) if request.allow_credentials_in_body() => {
                credentials.authenticate(client_id.as_ref(), client_secret.as_ref().as_bytes())
            }
            (None, None) => {}
            _ => credentials.unauthenticated(),
        }

        let scope = match request.scope().map(|scope| scope.as_ref().parse()) {
            None => None,
            Some(Err(_)) => return Err(Error::invalid()),
            Some(Ok(scope)) => Some(scope),
        };

        match request.grant_type() {
            Some(ref cow) if cow == "client_credentials" => (),
            None => return Err(Error::invalid()),
            Some(_) => return Err(Error::invalid_with(AccessTokenErrorType::UnsupportedGrantType)),
        };

        let (client_id, passdata) = credentials.into_client().ok_or_else(Error::invalid)?;

        Ok((
            ClientCredentialsState::Authenticate {
                client: client_id.to_string(),
                passdata: Vec::from(passdata),
            },
            scope,
        ))
    }

    fn authenticated(client_id: String) -> ClientCredentialsState {
        ClientCredentialsState::Binding { client_id }
    }

    fn bound(bound_client: BoundClient<'static>) -> ClientCredentialsState {
        ClientCredentialsState::Extend { bound_client }
    }

    fn extended(bound_client: BoundClient<'static>, extensions: Extensions) -> ClientCredentialsState {
        ClientCredentialsState::Negotiating {
            bound_client,
            extensions,
        }
    }

    fn negotiated(pre_grant: PreGrant, extensions: Extensions) -> ClientCredentialsState {
        ClientCredentialsState::Issue {
            pre_grant,
            extensions,
        }
    }
}

/// Represents a valid, currently pending client credentials not bound to an owner.
///
/// This will be passed along to the solicitor to obtain the owner ID, and then
/// a token will be issued. Since this is the client credentials flow, a pending
/// response is considered an internal error.
// Don't ever implement `Clone` here. It's to make it very
// hard for the user to accidentally respond to a request in two conflicting ways. This has
// potential security impact if it could be both denied and authorized.
pub struct Pending {
    pre_grant: PreGrant,
    extensions: Extensions,
}

impl Pending {
    /// Reference this pending state as a solicitation.
    pub fn as_solicitation(&self) -> Solicitation<'_> {
        Solicitation {
            grant: Cow::Borrowed(&self.pre_grant),
            state: None,
        }
    }

    /// Inform the backend about consent from a resource owner.
    ///
    /// Use negotiated parameters to authorize a client for an owner. The endpoint SHOULD be the
    /// same endpoint as was used to create the pending request.
    pub fn issue(
        self, handler: &mut dyn Endpoint, owner_id: String, allow_refresh_token: bool,
    ) -> Result<BearerToken> {
        let mut token = handler
            .issuer()
            .issue(Grant {
                owner_id,
                client_id: self.pre_grant.client_id,
                redirect_uri: self.pre_grant.redirect_uri.into_url(),
                scope: self.pre_grant.scope.clone(),
                until: Utc::now() + Duration::minutes(10),
                extensions: self.extensions,
            })
            .map_err(|()| Error::Primitive(Box::new(PrimitiveError::empty())))?;

        if !allow_refresh_token {
            token.refresh = None;
        }

        Ok(BearerToken(token, self.pre_grant.scope.clone()))
    }
}

// FiXME: use state machine instead
/// Try to get client credentials.
pub fn client_credentials(handler: &mut dyn Endpoint, request: &dyn Request) -> Result<Pending> {
    enum Requested {
        None,
        Authenticate {
            client: String,
            passdata: Vec<u8>,
        },
        Bind {
            client_id: String,
        },
        Extend,
        Negotiate {
            bound_client: BoundClient<'static>,
            scope: Option<Scope>,
        },
    }

    let mut client_credentials = ClientCredentials::new(request);
    let mut requested = Requested::None;

    loop {
        let input = match requested {
            Requested::None => Input::None,
            Requested::Authenticate { client, passdata } => {
                handler
                    .registrar()
                    .check(&client, Some(passdata.as_slice()))
                    .map_err(|err| match err {
                        RegistrarError::Unspecified => Error::unauthorized("basic"),
                        RegistrarError::PrimitiveError => Error::Primitive(Box::new(PrimitiveError {
                            grant: None,
                            extensions: None,
                        })),
                    })?;
                Input::Authenticated
            }
            Requested::Bind { client_id } => {
                let client_url = ClientUrl {
                    client_id: Cow::Owned(client_id),
                    redirect_uri: None,
                };
                let bound_client = match handler.registrar().bound_redirect(client_url) {
                    Err(RegistrarError::Unspecified) => return Err(Error::Ignore),
                    Err(RegistrarError::PrimitiveError) => {
                        return Err(Error::Primitive(Box::new(PrimitiveError {
                            grant: None,
                            extensions: None,
                        })));
                    }
                    Ok(pre_grant) => pre_grant,
                };
                Input::Bound { bound_client }
            }
            Requested::Extend => {
                let extensions = handler
                    .extension()
                    .extend(request)
                    .map_err(|_| Error::invalid())?;
                Input::Extended { extensions }
            }
            Requested::Negotiate { bound_client, scope } => {
                let pre_grant = handler
                    .registrar()
                    .negotiate(bound_client.clone(), scope.clone())
                    .map_err(|err| match err {
                        RegistrarError::PrimitiveError => Error::Primitive(Box::new(PrimitiveError {
                            grant: None,
                            extensions: None,
                        })),
                        RegistrarError::Unspecified => Error::Ignore,
                    })?;
                Input::Negotiated { pre_grant }
            }
        };

        requested = match client_credentials.advance(input) {
            Output::Authenticate { client, passdata } => Requested::Authenticate {
                client: client.to_owned(),
                passdata: passdata.to_vec(),
            },
            Output::Binding { client_id } => Requested::Bind {
                client_id: client_id.to_owned(),
            },
            Output::Extend => Requested::Extend,
            Output::Negotiate { bound_client, scope } => Requested::Negotiate {
                bound_client: bound_client.clone(),
                scope,
            },
            Output::Ok {
                pre_grant,
                extensions,
            } => {
                return Ok(Pending {
                    pre_grant: pre_grant.clone(),
                    extensions: extensions.clone(),
                })
            }
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

    pub fn unauthenticated(&mut self) {
        self.add(Credentials::Unauthenticated)
    }

    pub fn into_client(self) -> Option<(&'a str, &'a [u8])> {
        match self {
            Credentials::Authenticated {
                client_id,
                passphrase,
            } => Some((client_id, passphrase)),
            Credentials::Unauthenticated { .. } => None,
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

/// Defines actions for the response to a client credentials request.
#[derive(Clone)]
pub enum Error {
    /// Ignore the request entirely
    Ignore,

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

type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Create invalid error type
    pub fn invalid() -> Self {
        Error::Invalid(ErrorDescription {
            error: AccessTokenError::default(),
        })
    }

    fn invalid_with(with_type: AccessTokenErrorType) -> Self {
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
            Error::Ignore => None,
            Error::Invalid(description) => Some(description.description()),
            Error::Unauthorized(description, _) => Some(description.description()),
            Error::Primitive(_) => None,
        }
    }
}
