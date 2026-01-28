//! Provides the handling for Authorization Code Requests
use std::borrow::Cow;
use std::result::Result as StdResult;

use url::Url;
use chrono::{Duration, Utc};

use crate::OAuthOpaqueError;
use crate::code_grant::error::{AuthorizationError, AuthorizationErrorType};
use crate::primitives::authorizer::Authorizer;
use crate::primitives::registrar::{ClientUrl, ExactUrl, Registrar, RegistrarError, PreGrant};
use crate::primitives::grant::{Extensions, Grant};
use crate::{endpoint::Scope, endpoint::Solicitation, primitives::registrar::BoundClient};

/// Interface required from a request to determine the handling in the backend.
pub trait Request {
    /// Received request might not be encoded correctly. This method gives implementors the chance
    /// to signal that a request was received but its encoding was generally malformed. If this is
    /// the case, then no other attribute will be queried. This method exists mainly to make
    /// frontends straightforward by not having them handle special cases for malformed requests.
    fn valid(&self) -> bool;

    /// Identity of the client trying to gain an oauth token.
    fn client_id(&self) -> Option<Cow<'_, str>>;

    /// Optionally specifies the requested scope
    fn scope(&self) -> Option<Cow<'_, str>>;

    /// Valid request have (one of) the registered redirect urls for this client.
    fn redirect_uri(&self) -> Option<Cow<'_, str>>;

    /// Optional parameter the client can use to identify the redirected user-agent.
    fn state(&self) -> Option<Cow<'_, str>>;

    /// The method requested, valid requests MUST return `code`
    fn response_type(&self) -> Option<Cow<'_, str>>;

    /// Retrieve an additional parameter used in an extension
    fn extension(&self, key: &str) -> Option<Cow<'_, str>>;
}

/// A system of addons provided additional data.
///
/// An endpoint not having any extension may use `&mut ()` as the result of system.
pub trait Extension {
    /// Inspect the request to produce extension data.
    fn extend(&mut self, request: &dyn Request) -> std::result::Result<Extensions, OAuthOpaqueError>;
}

impl Extension for () {
    fn extend(&mut self, _: &dyn Request) -> std::result::Result<Extensions, OAuthOpaqueError> {
        Ok(Extensions::new())
    }
}

/// Required functionality to respond to authorization code requests.
///
/// Each method will only be invoked exactly once when processing a correct and authorized request,
/// and potentially less than once when the request is faulty.  These methods should be implemented
/// by internally using `primitives`, as it is implemented in the `frontend` module.
pub trait Endpoint {
    /// 'Bind' a client and redirect uri from a request to internally approved parameters.
    fn registrar(&self) -> &dyn Registrar;

    /// Generate an authorization code for a given grant.
    fn authorizer(&mut self) -> &mut dyn Authorizer;

    /// An extension implementation of this endpoint.
    ///
    /// It is possible to use `&mut ()`.
    fn extension(&mut self) -> &mut dyn Extension;
}

/// The result will indicate wether the authorization succeed or not.
pub struct Authorization {
    state: AuthorizationState,
    extensions: Option<Extensions>,
    scope: Option<Scope>,
}

enum AuthorizationState {
    /// State after request is validated
    Binding {
        client_id: String,
        redirect_uri: Option<ExactUrl>,
    },
    Extending {
        bound_client: BoundClient<'static>,
    },
    Negotiating {
        bound_client: BoundClient<'static>,
    },
    Pending {
        pre_grant: PreGrant,
        state: Option<String>,
        extensions: Extensions,
    },
    Err(Error),
}

/// Input injected by the executor into the state machine.
pub enum Input<'machine> {
    /// Binding of the client succeeded
    Bound {
        /// Request is given again to make some additional check that need bound client to run
        request: &'machine dyn Request,
        /// The bound client
        bound_client: BoundClient<'static>,
    },
    /// Extension succeeded
    Extended(Extensions),
    /// Negotiation done
    Negotiated {
        /// The pre grant from the negotiation
        pre_grant: PreGrant,
        /// State from the request
        state: Option<String>,
    },
    /// We're done
    Finished,
    /// Advance without input as far as possible, or just retrieve the output again.
    None,
}

/// A request by the statemachine to the executor.
///
/// Each variant is fulfilled by certain variants of the next inputs as an argument to
/// `Authorization::advance`. The output of most states is simply repeated if `Input::None` is
/// provided instead.
pub enum Output<'machine> {
    /// Ask registrar to bind the client and checks its redirect_uri
    Bind {
        /// The to-be-bound client.
        client_id: String,
        /// The redirect_uri to check if any
        redirect_uri: Option<ExactUrl>,
    },
    /// Ask for extensions if any
    Extend,
    /// Ask registrar to negotiate
    Negotiate {
        /// The current bound client
        bound_client: &'machine BoundClient<'static>,
        /// The scope, if any
        scope: Option<Scope>,
    },
    /// State machine is finished, provides parameters to construct a `Pending` (sync or async
    /// version)
    Ok {
        /// The grant
        pre_grant: PreGrant,
        /// The state
        state: Option<String>,
        /// The extensions
        extensions: Extensions,
    },
    /// The state machine finished in an error.
    ///
    /// The error will be repeated on *any* following input.
    Err(Error),
}

impl Authorization {
    /// Create state machine and validate request
    pub fn new(request: &dyn Request) -> Self {
        Authorization {
            state: Self::validate(request).unwrap_or_else(AuthorizationState::Err),
            extensions: None,
            scope: None,
        }
    }

    /// Go to next state
    pub fn advance<'req>(&mut self, input: Input<'req>) -> Output<'_> {
        self.state = match (self.take(), input) {
            (current, Input::None) => current,
            (
                AuthorizationState::Binding { .. },
                Input::Bound {
                    request,
                    bound_client,
                },
            ) => self
                .bound(request, bound_client)
                .unwrap_or_else(AuthorizationState::Err),
            (AuthorizationState::Extending { bound_client }, Input::Extended(grant_extension)) => {
                self.extended(grant_extension, bound_client)
            }
            (AuthorizationState::Negotiating { .. }, Input::Negotiated { pre_grant, state }) => {
                self.negotiated(state, pre_grant)
            }
            (AuthorizationState::Err(err), _) => AuthorizationState::Err(err),
            (_, _) => AuthorizationState::Err(Error::PrimitiveError),
        };

        self.output()
    }

    fn output(&self) -> Output<'_> {
        match &self.state {
            AuthorizationState::Err(err) => Output::Err(err.clone()),
            AuthorizationState::Binding {
                client_id,
                redirect_uri,
            } => Output::Bind {
                client_id: client_id.to_string(),
                redirect_uri: (*redirect_uri).clone(),
            },
            AuthorizationState::Extending { .. } => Output::Extend,
            AuthorizationState::Negotiating { bound_client } => Output::Negotiate {
                bound_client,
                scope: self.scope.clone(),
            },
            AuthorizationState::Pending {
                pre_grant,
                state,
                extensions,
            } => Output::Ok {
                pre_grant: pre_grant.clone(),
                state: state.clone(),
                extensions: extensions.clone(),
            },
        }
    }

    fn bound(
        &mut self, request: &dyn Request, bound_client: BoundClient<'static>,
    ) -> Result<AuthorizationState> {
        // It's done here rather than in `validate` because we need bound_client to be sure
        // `redirect_uri` has a value
        match request.response_type() {
            Some(ref method) if method.as_ref() == "code" => (),
            _ => {
                let prepared_error = ErrorUrl::with_request(
                    request,
                    (*bound_client.redirect_uri).to_url(),
                    AuthorizationErrorType::UnsupportedResponseType,
                );
                return Err(Error::Redirect(prepared_error));
            }
        }

        // Extract additional parameters from request to be used in negotiating
        // It's done here rather than in `validate` because we need bound_client to be sure
        // `redirect_uri` has a value
        let scope = request.scope();
        self.scope = match scope.map(|scope| scope.as_ref().parse()) {
            None => None,
            Some(Err(_)) => {
                let prepared_error = ErrorUrl::with_request(
                    request,
                    (*bound_client.redirect_uri).to_url(),
                    AuthorizationErrorType::InvalidScope,
                );
                return Err(Error::Redirect(prepared_error));
            }
            Some(Ok(scope)) => Some(scope),
        };

        Ok(AuthorizationState::Extending { bound_client })
    }

    fn extended(
        &mut self, grant_extension: Extensions, bound_client: BoundClient<'static>,
    ) -> AuthorizationState {
        self.extensions = Some(grant_extension);
        AuthorizationState::Negotiating { bound_client }
    }

    fn negotiated(&mut self, state: Option<String>, pre_grant: PreGrant) -> AuthorizationState {
        AuthorizationState::Pending {
            pre_grant,
            state,
            extensions: self.extensions.clone().expect("Should have extensions by now"),
        }
    }

    fn take(&mut self) -> AuthorizationState {
        std::mem::replace(&mut self.state, AuthorizationState::Err(Error::PrimitiveError))
    }

    fn validate(request: &dyn Request) -> Result<AuthorizationState> {
        if !request.valid() {
            return Err(Error::Ignore);
        };

        // Check preconditions
        let client_id = request.client_id().ok_or(Error::Ignore)?;
        let redirect_uri: Option<Cow<ExactUrl>> = match request.redirect_uri() {
            None => None,
            Some(ref uri) => {
                let parsed = uri.parse().map_err(|_| Error::Ignore)?;
                Some(Cow::Owned(parsed))
            }
        };

        Ok(AuthorizationState::Binding {
            client_id: client_id.into_owned(),
            redirect_uri: redirect_uri.map(|uri| uri.into_owned()),
        })
    }
}

/// Retrieve allowed scope and redirect url from the registrar.
///
/// Checks the validity of any given input as the registrar instance communicates the registrated
/// parameters. The registrar can also set or override the requested (default) scope of the client.
/// This will result in a tuple of negotiated parameters which can be used further to authorize
/// the client by the owner or, in case of errors, in an action to be taken.
/// If the client is not registered, the request will otherwise be ignored, if the request has
/// some other syntactical error, the client is contacted at its redirect url with an error
/// response.
pub fn authorization_code(handler: &mut dyn Endpoint, request: &dyn Request) -> self::Result<Pending> {
    enum Requested {
        None,
        Bind {
            client_id: String,
            redirect_uri: Option<ExactUrl>,
        },
        Extend,
        Negotiate {
            client_id: String,
            redirect_uri: Url,
            scope: Option<Scope>,
        },
    }

    let mut authorization = Authorization::new(request);
    let mut requested = Requested::None;
    let mut the_redirect_uri = None;

    loop {
        let input = match requested {
            Requested::None => Input::None,
            Requested::Bind {
                client_id,
                redirect_uri,
            } => {
                let client_url = ClientUrl {
                    client_id: Cow::Owned(client_id),
                    redirect_uri: redirect_uri.map(Cow::Owned),
                };
                let bound_client = match handler.registrar().bound_redirect(client_url) {
                    Err(RegistrarError::Unspecified) => return Err(Error::Ignore),
                    Err(RegistrarError::PrimitiveError) => return Err(Error::PrimitiveError),
                    Ok(pre_grant) => pre_grant,
                };
                the_redirect_uri = Some(bound_client.redirect_uri.clone().into_owned());
                Input::Bound {
                    request,
                    bound_client,
                }
            }
            Requested::Extend => {
                let grant_extension = match handler.extension().extend(request) {
                    Ok(extension_data) => extension_data,
                    Err(OAuthOpaqueError) => {
                        let prepared_error = ErrorUrl::with_request(
                            request,
                            the_redirect_uri.unwrap().into(),
                            AuthorizationErrorType::InvalidRequest,
                        );
                        return Err(Error::Redirect(prepared_error));
                    }
                };
                Input::Extended(grant_extension)
            }
            Requested::Negotiate {
                client_id,
                redirect_uri,
                scope,
            } => {
                let bound_client = BoundClient {
                    client_id: Cow::Owned(client_id),
                    redirect_uri: Cow::Owned(redirect_uri.clone().into()),
                };
                let pre_grant = handler
                    .registrar()
                    .negotiate(bound_client, scope)
                    .map_err(|err| match err {
                        RegistrarError::PrimitiveError => Error::PrimitiveError,
                        RegistrarError::Unspecified => {
                            let prepared_error = ErrorUrl::with_request(
                                request,
                                redirect_uri,
                                AuthorizationErrorType::InvalidScope,
                            );
                            Error::Redirect(prepared_error)
                        }
                    })?;
                Input::Negotiated {
                    pre_grant,
                    state: request.state().map(|s| s.into_owned()),
                }
            }
        };

        requested = match authorization.advance(input) {
            Output::Bind {
                client_id,
                redirect_uri,
            } => Requested::Bind {
                client_id,
                redirect_uri,
            },
            Output::Extend => Requested::Extend,
            Output::Negotiate { bound_client, scope } => Requested::Negotiate {
                client_id: bound_client.client_id.clone().into_owned(),
                redirect_uri: bound_client.redirect_uri.to_url(),
                scope,
            },
            Output::Ok {
                pre_grant,
                state,
                extensions,
            } => {
                return Ok(Pending {
                    pre_grant,
                    state,
                    extensions,
                })
            }
            Output::Err(e) => return Err(e),
        };
    }
}

/// Represents a valid, currently pending authorization request not bound to an owner. The frontend
/// can signal a reponse using this object.
// Don't ever implement `Clone` here. It's to make it very
// hard for the user toaccidentally respond to a request in two conflicting ways. This has
// potential security impact if it could be both denied and authorized.
pub struct Pending {
    pre_grant: PreGrant,
    state: Option<String>,
    extensions: Extensions,
}

impl Pending {
    /// Reference this pending state as a solicitation.
    pub fn as_solicitation(&self) -> Solicitation<'_> {
        Solicitation {
            grant: Cow::Borrowed(&self.pre_grant),
            state: self.state.as_ref().map(|s| Cow::Borrowed(&**s)),
        }
    }

    /// Denies the request, which redirects to the client for which the request originated.
    pub fn deny(self) -> Result<Url> {
        let url = self.pre_grant.redirect_uri;
        let mut error = AuthorizationError::default();
        error.set_type(AuthorizationErrorType::AccessDenied);
        let error = ErrorUrl::new_generic(url.into_url(), self.state, error);
        Err(Error::Redirect(error))
    }

    /// Inform the backend about consent from a resource owner.
    ///
    /// Use negotiated parameters to authorize a client for an owner. The endpoint SHOULD be the
    /// same endpoint as was used to create the pending request.
    pub fn authorize(self, handler: &mut dyn Endpoint, owner_id: Cow<str>) -> Result<Url> {
        let mut url = self.pre_grant.redirect_uri.to_url();

        let grant = handler
            .authorizer()
            .authorize(Grant {
                owner_id: owner_id.into_owned(),
                client_id: self.pre_grant.client_id,
                redirect_uri: self.pre_grant.redirect_uri.into_url(),
                scope: self.pre_grant.scope,
                until: Utc::now() + Duration::minutes(10),
                extensions: self.extensions,
            })
            .map_err(|OAuthOpaqueError| Error::PrimitiveError)?;

        url.query_pairs_mut()
            .append_pair("code", grant.as_str())
            .extend_pairs(self.state.map(|v| ("state", v)))
            .finish();
        Ok(url)
    }

    /// Retrieve a reference to the negotiated parameters (e.g. scope). These should be displayed
    /// to the resource owner when asking for his authorization.
    pub fn pre_grant(&self) -> &PreGrant {
        &self.pre_grant
    }
}

/// Defines the correct treatment of the error.
/// Not all errors are signalled to the requesting party, especially when impersonation is possible
/// it is integral for security to resolve the error internally instead of redirecting the user
/// agent to a possibly crafted and malicious target.
#[derive(Clone)]
pub enum Error {
    /// Ignore the request entirely
    Ignore,

    /// Redirect to the given url
    Redirect(ErrorUrl),

    /// Something happened in one of the primitives.
    ///
    /// The endpoint should decide how to handle this and if this is temporary.
    PrimitiveError,
}

/// Encapsulates a redirect to a valid redirect_uri with an error response. The implementation
/// makes it possible to alter the contained error, for example to provide additional optional
/// information. The error type should not be altered by the frontend but the specificalities
/// of this should be enforced by the frontend instead.
#[derive(Clone)]
pub struct ErrorUrl {
    base_uri: Url,
    error: AuthorizationError,
}

type Result<T> = StdResult<T, Error>;

impl ErrorUrl {
    /// Construct a new error, already fixing the state parameter if it exists.
    fn new_generic<S>(mut url: Url, state: Option<S>, error: AuthorizationError) -> ErrorUrl
    where
        S: AsRef<str>,
    {
        url.query_pairs_mut()
            .extend_pairs(state.as_ref().map(|st| ("state", st.as_ref())));
        ErrorUrl { base_uri: url, error }
    }

    /// Construct a new error, already fixing the state parameter if it exists.
    pub fn new(url: Url, state: Option<&str>, error: AuthorizationError) -> ErrorUrl {
        ErrorUrl::new_generic(url, state, error)
    }

    /// Construct a new error with a request to provide `state` and an error type
    pub fn with_request(
        request: &dyn Request, redirect_uri: Url, err_type: AuthorizationErrorType,
    ) -> ErrorUrl {
        let mut err = ErrorUrl::new(
            redirect_uri,
            request.state().as_deref(),
            AuthorizationError::default(),
        );
        err.description().set_type(err_type);
        err
    }

    /// Get a handle to the description the client will receive.
    pub fn description(&mut self) -> &mut AuthorizationError {
        &mut self.error
    }
}

impl Error {
    /// Get a handle to the description the client will receive.
    ///
    /// Some types of this error don't return any description which is represented by a `None`
    /// result.
    pub fn description(&mut self) -> Option<&mut AuthorizationError> {
        match self {
            Error::Ignore => None,
            Error::Redirect(inner) => Some(inner.description()),
            Error::PrimitiveError => None,
        }
    }
}

impl From<ErrorUrl> for Url {
    /// Finalize the error url by saving its parameters in the query part of the redirect_uri
    fn from(val: ErrorUrl) -> Self {
        let mut url = val.base_uri;
        url.query_pairs_mut().extend_pairs(val.error);
        url
    }
}
