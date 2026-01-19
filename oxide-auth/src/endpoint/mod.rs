//! Polymorphic HTTP wrappers for code grant authorization and other flows.
//!
//! An endpoint is concerned with executing the abstract behaviours given by the backend in terms
//! of the actions of the endpoint types. This means translating Redirect errors to the correct
//! Redirect http response for example or optionally sending internal errors to loggers. The
//! frontends, which are the bindings to particular server libraries, can instantiate the endpoint
//! api or simple reuse existing types.
//!
//! To ensure the adherence to the oauth2 rfc and the improve general implementations, some control
//! flow of incoming packets is specified here instead of the frontend implementations.  Instead,
//! traits are offered to make this compatible with other endpoints. In theory, this makes
//! endpoints pluggable which could improve testing.
//!
//! Custom endpoint
//! ---------------
//! In order to not place restrictions on the web server library in use, it is possible to
//! implement an endpoint completely with user defined types.
//!
//! This requires custom, related implementations of [`WebRequest`] and [`WebResponse`].
//! _WARNING_: Custom endpoints MUST ensure a secure communication layer with confidential clients.
//! This means using TLS for communication over https.
//!
//! After receiving an authorization grant, access token or access request, initiate the respective
//! flow by collecting the [`Authorizer`], [`Issuer`], and [`Registrar`] instances. For example:
//!
//! [`WebRequest`]: trait.WebRequest.html
//! [`WebResponse`]: trait.WebResponse.html
//! [`Authorizer`]: ../../primitives/authorizer/trait.Authorizer.html
//! [`Issuer`]: ../../primitives/issuer/trait.Issuer.html
//! [`Registrar`]: ../../primitives/registrar/trait.Registrar.html
mod authorization;
mod accesstoken;
mod client_credentials;
mod error;
mod refresh;
mod resource;
mod query;

#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::marker::PhantomData;

pub use crate::primitives::authorizer::Authorizer;
pub use crate::primitives::issuer::Issuer;
pub use crate::primitives::registrar::Registrar;
pub use crate::primitives::scope::Scope;

use crate::code_grant::resource::{Error as ResourceError};
use crate::code_grant::error::{AuthorizationError, AccessTokenError};

use url::Url;

// Re-export the extension traits under prefixed names.
pub use crate::code_grant::authorization::Extension as AuthorizationExtension;
pub use crate::code_grant::accesstoken::Extension as AccessTokenExtension;
pub use crate::code_grant::client_credentials::Extension as ClientCredentialsExtension;

pub use crate::primitives::registrar::PreGrant;
pub use self::authorization::*;
pub use self::accesstoken::*;
pub use self::client_credentials::ClientCredentialsFlow;
pub use self::error::OAuthError;
pub use self::refresh::RefreshFlow;
pub use self::resource::*;
pub use self::query::*;

/// Answer from OwnerAuthorizer to indicate the owners choice.
pub enum OwnerConsent<Response: WebResponse> {
    /// The owner did not authorize the client.
    Denied,

    /// The owner has not yet decided, i.e. the returned page is a form for the user.
    InProgress(Response),

    /// Authorization was granted by the specified user.
    Authorized(String),

    /// An error occurred while checking authorization.
    Error(Response::Error),
}

/// Modifiable reason for creating a response to the client.
///
/// Not all responses indicate failure. A redirect will also occur in the a regular of providing an
/// access token to the third party client. When an error is present (see several methods) it is
/// mostly possible to customize it. This hook provides advanced endpoints with the opportunity to
/// set additional parameters and informational messages before they are encoded.
///
/// See the provided methods for more information and examples.
#[derive(Debug)]
pub struct Template<'a> {
    inner: InnerTemplate<'a>,
}

/// The general manner of the response.
///
/// These are parallels for HTTP status codes of the same name.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseStatus {
    /// The response is issued because the requesting party was not authorized.
    Unauthorized,

    /// The response redirects in the code grant flow.
    Redirect,

    /// The request was malformed.
    BadRequest,

    /// This response is normal and expected.
    Ok,
}

/// Encapsulated different types of responses reasons.
///
/// Each variant contains some form of context information about the response. This can be used either
/// purely informational or in some cases provides additional customization points. The addition of
/// fields to some variant context can occur in any major release until `1.0`. It is discouraged to
/// exhaustively match the fields directly. Since some context could not permit cloning, the enum will
/// not derive this until this has shown unlikely but strongly requested. Please open an issue if you
/// think the pros or cons should be evaluated differently.
#[derive(Debug)]
#[non_exhaustive]
enum InnerTemplate<'a> {
    /// Authorization to access the resource has not been granted.
    Unauthorized {
        /// The underlying cause for denying access.
        ///
        /// The http authorization header is to be set according to this field.
        #[allow(dead_code)]
        error: Option<ResourceError>,

        /// Information on an access token error.
        ///
        /// Endpoints may modify this description to add additional explanatory text or a reference
        /// uri for clients seeking explanation.
        access_token_error: Option<&'a mut AccessTokenError>,
    },

    /// Redirect the user-agent to another url.
    ///
    /// The endpoint has the opportunity to inspect and modify error information to some extent.
    /// For example to log an error rate or to provide a pointer to a custom human readable
    /// explanation page. The response will generally not contain a body.
    Redirect {
        /// Information on an authorization error.
        ///
        /// Endpoints may modify this description to add additional explanatory text or a reference
        /// uri for clients or resource owners seeking explanation.
        authorization_error: Option<&'a mut AuthorizationError>,
    },

    /// The request did not conform to specification or was otheriwse invalid.
    ///
    /// As such, it was not handled further. Some processes still warrant a response body to be
    /// set in the case of an invalid request, containing additional information for the client.
    /// For example, an authorized client sending a malformed but authenticated request for an
    /// access token will receive additional hints on the cause of his mistake.
    BadRequest {
        /// Information on an invalid-access-token-request error.
        ///
        /// Endpoints may modify this description to add additional explanatory text or a reference
        /// uri for clients seeking explanation.
        access_token_error: Option<&'a mut AccessTokenError>,
    },

    /// An expected, normal response.
    ///
    /// The content of the response may require precise semantics to be standard compliant,
    /// therefore it is constructed using the `WebResponse` trait methods. Try not to tamper with
    /// the format too much, such as unsetting a body etc. after the flow has finished.
    Ok,
}

/// A pending solicitation to a resource owner.
///
/// This encapsulates the information available to an [`OwnerSolicitor`] when querying consent
/// information.
///
/// [`OwnerSolicitor`]: trait.OwnerSolicitor.html
pub struct Solicitation<'flow> {
    pub(crate) grant: Cow<'flow, PreGrant>,
    pub(crate) state: Option<Cow<'flow, str>>,
}

impl<'flow> Solicitation<'flow> {
    /// Clone the solicitation into an owned structure.
    ///
    /// This mainly helps with sending it across threads.
    pub fn into_owned(self) -> Solicitation<'static> {
        Solicitation {
            grant: Cow::Owned(self.grant.into_owned()),
            state: self.state.map(|state| Cow::Owned(state.into_owned())),
        }
    }

    /// Return the pre-grant associated with the request.
    ///
    /// The information in the `PreGrant` is the authoritative information on the client and scopes
    /// associated with the request. It has already been validated against those settings and
    /// restrictions that were applied when registering the client.
    pub fn pre_grant(&self) -> &PreGrant {
        self.grant.as_ref()
    }

    /// The state provided by the client request.
    ///
    /// This will need to be provided to the response back to the client so it must be preserved
    /// across a redirect or a consent screen presented by the user agent.
    pub fn state(&self) -> Option<&str> {
        self.state.as_ref().map(|x| x as _)
    }

    /// Create a new solicitation request from a pre grant.
    ///
    /// You usually wouldn't need to call this manually as it is called by the endpoint's flow and
    /// then handed with all available information to the solicitor.
    pub fn new(grant: &'flow PreGrant) -> Self {
        Solicitation {
            grant: Cow::Borrowed(grant),
            state: None,
        }
    }

    /// Add a client state to the solicitation.
    pub fn with_state(self, state: &'flow str) -> Self {
        Solicitation {
            state: Some(Cow::Borrowed(state)),
            ..self
        }
    }
}

/// Checks consent with the owner of a resource, identified in a request.
///
/// See [`frontends::simple`] for an implementation that permits arbitrary functions.
///
/// [`frontends::simple`]: ../frontends/simple/endpoint/struct.FnSolicitor.html
pub trait OwnerSolicitor<Request: WebRequest> {
    /// Ensure that a user (resource owner) is currently authenticated (for example via a session
    /// cookie) and determine if he has agreed to the presented grants.
    fn check_consent(&mut self, _: &mut Request, _: Solicitation) -> OwnerConsent<Request::Response>;
}

/// Determine the scopes applying to a request of a resource.
///
/// It is possible to use a slice of [`Scope`]s as an implementation of this trait. You can inspect
/// the request that was used to access the resource for which the scopes are to be determined but
/// should generally avoid doing so. Sometimes the scope depends on external parameters and this is
/// unavoidable, e.g. if the scope is created dynamically from the path of the resource.
///
/// ## Example
///
/// Here's a possible new implementation that allows you to update your scope list at runtime:
///
/// ```
/// # use oxide_auth::endpoint::Scopes;
/// # use oxide_auth::endpoint::WebRequest;
/// use oxide_auth::primitives::scope::Scope;
/// use std::sync::{Arc, RwLock};
///
/// struct MyScopes {
///     update: RwLock<Arc<[Scope]>>,
///     current: Arc<[Scope]>,
/// };
///
/// impl<R: WebRequest> Scopes<R> for MyScopes {
///     fn scopes(&mut self, _: &mut R) -> &[Scope] {
///         let update = self.update.read().unwrap();
///         if !Arc::ptr_eq(&update, &self.current) {
///             self.current = update.clone();
///         }
///         &self.current
///     }
/// }
/// ```
///
/// [`Scope`]: ../primitives/scope/struct.Scope.html
pub trait Scopes<Request: WebRequest> {
    /// A list of alternative scopes.
    ///
    /// One of the scopes needs to be fulfilled by the access token in the request to grant access.
    /// A scope is fulfilled if the set of its part is a subset of the parts in the grant. If the
    /// slice is empty, then no scope can be fulfilled and the request is always blocked.
    fn scopes(&mut self, request: &mut Request) -> &[Scope];
}

/// Abstraction of web requests with several different abstractions and constructors needed by an
/// endpoint. It is assumed to originate from an HTTP request, as defined in the scope of the rfc,
/// but theoretically other requests are possible.
pub trait WebRequest {
    /// The error generated from access of malformed or invalid requests.
    type Error;

    /// The corresponding type of Responses returned from this module.
    type Response: WebResponse<Error = Self::Error>;

    /// Retrieve a parsed version of the url query.
    ///
    /// An Err return value indicates a malformed query or an otherwise malformed WebRequest. Note
    /// that an empty query should result in `Ok(HashMap::new())` instead of an Err.
    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error>;

    /// Retrieve the parsed `application/x-form-urlencoded` body of the request.
    ///
    /// An Err value / indicates a malformed body or a different Content-Type.
    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error>;

    /// Contents of the authorization header or none if none exists. An Err value indicates a
    /// malformed header or request.
    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error>;
}

/// Response representation into which the Request is transformed by the code_grant types.
///
/// At most one of the methods `body_text`, `body_json` will be called. Some flows will
/// however not call any of those methods.
pub trait WebResponse {
    /// The error generated when trying to construct an unhandled or invalid response.
    type Error;

    /// Set the response status to 200.
    fn ok(&mut self) -> Result<(), Self::Error>;

    /// A response which will redirect the user-agent to which the response is issued.
    fn redirect(&mut self, url: Url) -> Result<(), Self::Error>;

    /// Set the response status to 400.
    fn client_error(&mut self) -> Result<(), Self::Error>;

    /// Set the response status to 401 and add a `WWW-Authenticate` header.
    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error>;

    /// A pure text response with no special media type set.
    fn body_text(&mut self, text: &str) -> Result<(), Self::Error>;

    /// Json repsonse data, with media type `aplication/json.
    fn body_json(&mut self, data: &str) -> Result<(), Self::Error>;
}

/// Intermediate trait to flow specific extensions.
///
/// The existence of this 1) promotes writing of extensions so that they can be reused independent
/// of endpoint and request types; 2) makes it possible to provide some of these in this library.
///
/// Note that all methods will by default return `None` so that adding to other flows is possible
/// without affecting existing implementations.
pub trait Extension {
    /// The handler for authorization code extensions.
    fn authorization(&mut self) -> Option<&mut dyn AuthorizationExtension> {
        None
    }

    /// The handler for access token extensions.
    fn access_token(&mut self) -> Option<&mut dyn AccessTokenExtension> {
        None
    }

    /// The handler for client credentials extensions.
    fn client_credentials(&mut self) -> Option<&mut dyn ClientCredentialsExtension> {
        None
    }
}

/// Fuses requests and primitives into a coherent system to give a response.
///
/// There are multiple different valid ways to produce responses and react to internal errors for a
/// single request type. This trait should provide those mechanisms, including trying to recover
/// from primitive errors where appropriate.
///
/// To reduce the number of necessary impls and provide a single interface to a single trait, this
/// trait defines accessor methods for all possibly needed primitives. Note that not all flows
/// actually access all primitives. Thus, an implementation does not necessarily have to return
/// something in `registrar`, `authorizer`, `issuer_mut` but failing to do so will also fail flows
/// that try to use them.
///
/// # Panics
///
/// It is expected that the endpoint primitive functions are consistent, i.e. they don't begin
/// returning `None` after having returned `Some(registrar)` previously for example. This ensures
/// that the checks executed by the flow preparation methods catch missing primitives. When this
/// contract is violated, the execution of a flow may lead to a panic.
pub trait Endpoint<Request: WebRequest> {
    /// The error typed used as the error representation of each flow.
    type Error;

    /// A registrar if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires a registrar but does not
    /// have any effect on flows that do not require one.
    fn registrar(&self) -> Option<&dyn Registrar>;

    /// An authorizer if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires an authorizer but does not
    /// have any effect on flows that do not require one.
    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer>;

    /// An issuer if this endpoint can access one.
    ///
    /// Returning `None` will implicate failing any flow that requires an issuer but does not have
    /// any effect on flows that do not require one.
    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer>;

    /// Return the system that checks owner consent.
    ///
    /// Returning `None` will implicated failing the authorization code flow but does have any
    /// effect on other flows.
    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<Request>>;

    /// Determine the required scopes for a request.
    ///
    /// The client must fulfill any one scope, so returning an empty slice will always deny the
    /// request.
    fn scopes(&mut self) -> Option<&mut dyn Scopes<Request>>;

    /// Generate a prototype response.
    ///
    /// The endpoint can rely on this being called at most once for each flow, if it wants
    /// to preallocate the response or return a handle on an existing prototype.
    fn response(
        &mut self, request: &mut Request, kind: Template,
    ) -> Result<Request::Response, Self::Error>;

    /// Wrap an error.
    fn error(&mut self, err: OAuthError) -> Self::Error;

    /// Wrap an error in the request/response types.
    fn web_error(&mut self, err: Request::Error) -> Self::Error;

    /// Get the central extension instance this endpoint.
    ///
    /// Returning `None` is the default implementation and acts as simply providing any extensions.
    fn extension(&mut self) -> Option<&mut dyn Extension> {
        None
    }
}

impl<'a> Template<'a> {
    /// Create an OK template
    pub fn new_ok() -> Self {
        InnerTemplate::Ok.into()
    }

    /// Create a bad request template
    pub fn new_bad(access_token_error: Option<&'a mut AccessTokenError>) -> Self {
        InnerTemplate::BadRequest { access_token_error }.into()
    }

    /// Create an unauthorized template
    pub fn new_unauthorized(
        error: Option<ResourceError>, access_token_error: Option<&'a mut AccessTokenError>,
    ) -> Self {
        InnerTemplate::Unauthorized {
            error,
            access_token_error,
        }
        .into()
    }

    /// Create a redirect template
    pub fn new_redirect(authorization_error: Option<&'a mut AuthorizationError>) -> Self {
        InnerTemplate::Redirect { authorization_error }.into()
    }

    /// The corresponding status code.
    pub fn status(&self) -> ResponseStatus {
        match self.inner {
            InnerTemplate::Unauthorized { .. } => ResponseStatus::Unauthorized,
            InnerTemplate::Redirect { .. } => ResponseStatus::Redirect,
            InnerTemplate::BadRequest { .. } => ResponseStatus::BadRequest,
            InnerTemplate::Ok => ResponseStatus::Ok,
        }
    }

    /// Supplementary information about an error in the authorization code flow.
    ///
    /// The referenced object can be inspected and manipulated to provided additional information
    /// that is specific to this server or endpoint. Such information could be an error page with
    /// explanatory information or a customized message.
    ///
    /// ```
    /// # use oxide_auth::endpoint::Template;
    /// fn explain(mut template: Template) {
    ///     if let Some(error) = template.authorization_error() {
    ///         eprintln!("[authorization] An error occurred: {:?}", error.kind());
    ///         error.explain("This server is still in its infancy. Sorry.");
    ///         error.explain_uri("/authorization_error.html".parse().unwrap());
    ///     }
    /// }
    /// ```
    pub fn authorization_error(&mut self) -> Option<&mut AuthorizationError> {
        match &mut self.inner {
            InnerTemplate::Redirect {
                authorization_error, ..
            } => reborrow(authorization_error),
            _ => None,
        }
    }

    /// Supplementary information about an error in the access token flow.
    ///
    /// The referenced object can be inspected and manipulated to provided additional information
    /// that is specific to this server or endpoint. Such information could be an error page with
    /// explanatory information or a customized message.
    ///
    /// ```
    /// # use oxide_auth::endpoint::Template;
    /// fn explain(mut template: Template) {
    ///     if let Some(error) = template.access_token_error() {
    ///         eprintln!("[access_code] An error occurred: {:?}", error.kind());
    ///         error.explain("This server is still in its infancy. Sorry.");
    ///         error.explain_uri("/access_token_error.html".parse().unwrap());
    ///     }
    /// }
    /// ```
    pub fn access_token_error(&mut self) -> Option<&mut AccessTokenError> {
        match &mut self.inner {
            InnerTemplate::Unauthorized {
                access_token_error, ..
            } => reborrow(access_token_error),
            InnerTemplate::BadRequest {
                access_token_error, ..
            } => reborrow(access_token_error),
            _ => None,
        }
    }
}

/// Reborrow contained optional reference.
///
/// Slightly tweaked from an `Into`, there is `Option<&'a mut T>` from `&'a mut Option<T>`.
fn reborrow<'a, T>(opt: &'a mut Option<&mut T>) -> Option<&'a mut T> {
    match opt {
        // Magically does correct lifetime coercision.
        Some(inner) => Some(inner),
        None => None,
    }
}

impl<'a, W: WebRequest> WebRequest for &'a mut W {
    type Error = W::Error;
    type Response = W::Response;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        (**self).query()
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        (**self).urlbody()
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        (**self).authheader()
    }
}

impl<'a, R: WebRequest, E: Endpoint<R>> Endpoint<R> for &'a mut E {
    type Error = E::Error;

    fn registrar(&self) -> Option<&dyn Registrar> {
        (**self).registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer> {
        (**self).authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer> {
        (**self).issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<R>> {
        (**self).owner_solicitor()
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<R>> {
        (**self).scopes()
    }

    fn response(&mut self, request: &mut R, kind: Template) -> Result<R::Response, Self::Error> {
        (**self).response(request, kind)
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        (**self).error(err)
    }

    fn web_error(&mut self, err: R::Error) -> Self::Error {
        (**self).web_error(err)
    }

    fn extension(&mut self) -> Option<&mut dyn Extension> {
        (**self).extension()
    }
}

impl<R: WebRequest, E: Endpoint<R>> Endpoint<R> for Box<E> {
    type Error = E::Error;

    fn registrar(&self) -> Option<&dyn Registrar> {
        (**self).registrar()
    }

    fn authorizer_mut(&mut self) -> Option<&mut dyn Authorizer> {
        (**self).authorizer_mut()
    }

    fn issuer_mut(&mut self) -> Option<&mut dyn Issuer> {
        (**self).issuer_mut()
    }

    fn owner_solicitor(&mut self) -> Option<&mut dyn OwnerSolicitor<R>> {
        (**self).owner_solicitor()
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<R>> {
        (**self).scopes()
    }

    fn response(&mut self, request: &mut R, kind: Template) -> Result<R::Response, Self::Error> {
        (**self).response(request, kind)
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        (**self).error(err)
    }

    fn web_error(&mut self, err: R::Error) -> Self::Error {
        (**self).web_error(err)
    }

    fn extension(&mut self) -> Option<&mut dyn Extension> {
        (**self).extension()
    }
}

impl Extension for () {}

impl<'a, W: WebRequest, S: OwnerSolicitor<W> + 'a + ?Sized> OwnerSolicitor<W> for &'a mut S {
    fn check_consent(
        &mut self, request: &mut W, solicitation: Solicitation,
    ) -> OwnerConsent<W::Response> {
        (**self).check_consent(request, solicitation)
    }
}

impl<W: WebRequest, S: OwnerSolicitor<W> + ?Sized> OwnerSolicitor<W> for Box<S> {
    fn check_consent(
        &mut self, request: &mut W, solicitation: Solicitation,
    ) -> OwnerConsent<W::Response> {
        (**self).check_consent(request, solicitation)
    }
}

impl<W: WebRequest> Scopes<W> for [Scope] {
    fn scopes(&mut self, _: &mut W) -> &[Scope] {
        self
    }
}

impl<W: WebRequest> Scopes<W> for Vec<Scope> {
    fn scopes(&mut self, _: &mut W) -> &[Scope] {
        self.as_slice()
    }
}

impl<'a, W: WebRequest> Scopes<W> for &'a [Scope] {
    fn scopes(&mut self, _: &mut W) -> &[Scope] {
        self
    }
}

impl<'a, W: WebRequest, S: Scopes<W> + 'a + ?Sized> Scopes<W> for &'a mut S {
    fn scopes(&mut self, request: &mut W) -> &[Scope] {
        (**self).scopes(request)
    }
}

impl<W: WebRequest, S: Scopes<W> + ?Sized> Scopes<W> for Box<S> {
    fn scopes(&mut self, request: &mut W) -> &[Scope] {
        (**self).scopes(request)
    }
}

impl<'a> From<InnerTemplate<'a>> for Template<'a> {
    fn from(inner: InnerTemplate<'a>) -> Self {
        Template { inner }
    }
}

/// Check if the header is an authorization method
pub fn is_authorization_method<'h>(header: &'h str, method: &'static str) -> Option<&'h str> {
    let header_method = header.get(..method.len())?;
    if header_method.eq_ignore_ascii_case(method) {
        Some(&header[method.len()..])
    } else {
        None
    }
}
