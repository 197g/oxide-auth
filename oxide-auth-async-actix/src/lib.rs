//! Bindings and utilities for creating an oauth endpoint with actix.
//!
//! Use the provided methods to use code grant methods in an asynchronous fashion, or use an
//! `AsActor<_>` to create an actor implementing endpoint functionality via messages.
#![warn(missing_docs)]

use actix::{MailboxError, Message};
use actix_web::{
    body::BoxBody,
    dev::Payload,
    http::{
        header::{self, HeaderMap, InvalidHeaderValue},
        StatusCode,
    },
    web::Form,
    web::Query,
    FromRequest, HttpRequest, HttpResponse, HttpResponseBuilder, Responder, ResponseError,
};
use async_trait::async_trait;
use futures::future::{self, FutureExt, LocalBoxFuture, Ready};
use oxide_auth::{
    endpoint::{NormalizedParameter, OAuthError, QueryParameter, WebRequest, WebResponse},
    frontends::simple::endpoint::Error,
};
use oxide_auth_async::{
    endpoint::{Endpoint},
    primitives::{Authorizer},
};
use std::{borrow::Cow, convert::TryFrom, error, fmt};
use url::Url;

mod operations;

pub use operations::{Authorize, Refresh, Resource, Token};

/// Describes an operation that can be performed in the presence of an `Endpoint`
///
/// This trait can be implemented by any type, but is very useful in Actor scenarios, where an
/// Actor can provide an endpoint to an operation sent as a message.
///
/// Here's how any Endpoint type can be turned into an Actor that responds to OAuthMessages:
/// ```rust,ignore
/// use actix::{Actor, Context, Handler};
/// use oxide_auth::endpoint::Endpoint;
/// use oxide_auth_actix::OAuthOperation;
///
/// pub struct MyEndpoint {
///     // Define your endpoint...
/// }
///
/// impl Endpoint<OAuthRequest> for MyEndpoint {
///     // Implement your endpoint...
/// }
///
/// // Implement Actor
/// impl Actor for MyEndpoint {
///     type Context = Context<Self>;
/// }
///
/// // Handle incoming OAuthMessages
/// impl<Op, Ext> Handler<OAuthMessage<Op, Ext>> for MyEndpoint
/// where
///     Op: OAuthOperation,
/// {
///     type Result = Result<Op::Item, Op::Error>;
///
///     fn handle(&mut self, msg: OAuthMessage<Op, Ext>, _: &mut Self::Context) -> Self::Result {
///         let (op, _) = msg.into_inner();
///
///         op.run(self)
///     }
/// }
/// ```
///
/// By additionally specifying a type for Extras, more advanced patterns can be used
/// ```rust,ignore
/// type Ext = Option<MyCustomSolicitor>;
///
/// // Handle incoming OAuthMessages
/// impl<Op> Handler<OAuthMessage<Op, Ext>> for MyEndpoint
/// where
///     Op: OAuthOperation,
/// {
///     type Result = Result<Op::Item, Op::Error>;
///
///     fn handle(&mut self, msg: OAuthMessage<Op, Ext>, _: &mut Self::Context) -> Self::Result {
///         let (op, ext) = msg.into_inner();
///
///         op.run(self.with_my_custom_solicitor(ext))
///     }
/// }
/// ```
#[async_trait]
pub trait OAuthOperation: Sized + 'static {
    /// The success-type produced by an OAuthOperation
    type Item: 'static;

    /// The error type produced by an OAuthOperation
    type Error: fmt::Debug + 'static;

    /// Performs the oxide operation with the provided endpoint
    async fn run<E>(self, endpoint: E) -> Result<Self::Item, Self::Error>
    where
        E: Endpoint<OAuthRequest> + Send + Sync,
        E::Error: Send,
        WebError: From<E::Error>;

    /// Turn an OAuthOperation into a Message to send to an actor
    fn wrap<Extras>(self, extras: Extras) -> OAuthMessage<Self, Extras> {
        OAuthMessage(self, extras)
    }
}

/// A message type to easily send `OAuthOperation`s to an actor
pub struct OAuthMessage<Operation, Extras>(Operation, Extras);

#[derive(Clone, Debug)]
/// Type implementing `WebRequest` as well as `FromRequest` for use in route handlers
///
/// This type consumes the body of the HttpRequest upon extraction, so be careful not to use it in
/// places you also expect an application payload
pub struct OAuthRequest {
    auth: Option<String>,
    query: Option<NormalizedParameter>,
    body: Option<NormalizedParameter>,
}

impl OAuthResponse {
    /// Get the headers from `OAuthResponse`
    pub fn get_headers(&self) -> HeaderMap {
        self.headers.clone()
    }

    /// Get the body from `OAuthResponse`
    pub fn get_body(&self) -> Option<String> {
        self.body.clone()
    }
}

/// Type implementing `WebRequest` as well as `FromRequest` for use in guarding resources
///
/// This is useful over [OAuthRequest] since [OAuthResource] doesn't consume the body of the
/// request upon extraction
pub struct OAuthResource {
    auth: Option<String>,
}

#[derive(Clone, Debug)]
/// Type implementing `WebResponse` and `Responder` for use in route handlers
pub struct OAuthResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Option<String>,
}

#[derive(Debug)]
/// The error type for Oxide Auth operations
pub enum WebError {
    /// Errors occuring in Endpoint operations
    Endpoint(OAuthError),

    /// Errors occuring when producing Headers
    Header(InvalidHeaderValue),

    /// Errors with the request encoding
    Encoding,

    /// Request body could not be parsed as a form
    Form,

    /// Request query was absent or could not be parsed
    Query,

    /// Request was missing a body
    Body,

    /// The Authorization header was invalid
    Authorization,

    /// Processing part of the request was canceled
    Canceled,

    /// An actor's mailbox was full
    Mailbox,

    /// General internal server error
    InternalError(Option<String>),
}

impl OAuthRequest {
    /// Create a new OAuthRequest from an HttpRequest and Payload
    pub async fn new(req: HttpRequest, mut payload: Payload) -> Result<Self, WebError> {
        let query = Query::extract(&req)
            .await
            .ok()
            .map(|q: Query<NormalizedParameter>| q.into_inner());
        let body = Form::from_request(&req, &mut payload)
            .await
            .ok()
            .map(|b: Form<NormalizedParameter>| b.into_inner());

        let mut all_auth = req.headers().get_all(header::AUTHORIZATION);
        let optional = all_auth.next();

        let auth = if all_auth.next().is_some() {
            return Err(WebError::Authorization);
        } else {
            optional.and_then(|hv| hv.to_str().ok().map(str::to_owned))
        };

        Ok(OAuthRequest { auth, query, body })
    }

    /// Fetch the authorization header from the request
    pub fn authorization_header(&self) -> Option<&str> {
        self.auth.as_deref()
    }

    /// Fetch the query for this request
    pub fn query(&self) -> Option<&NormalizedParameter> {
        self.query.as_ref()
    }

    /// Fetch the query mutably
    pub fn query_mut(&mut self) -> Option<&mut NormalizedParameter> {
        self.query.as_mut()
    }

    /// Fetch the body of the request
    pub fn body(&self) -> Option<&NormalizedParameter> {
        self.body.as_ref()
    }
}

impl OAuthResource {
    /// Create a new OAuthResource from an HttpRequest
    pub fn new(req: &HttpRequest) -> Result<Self, WebError> {
        let mut all_auth = req.headers().get_all(header::AUTHORIZATION);
        let optional = all_auth.next();

        let auth = if all_auth.next().is_some() {
            return Err(WebError::Authorization);
        } else {
            optional.and_then(|hv| hv.to_str().ok().map(str::to_owned))
        };

        Ok(OAuthResource { auth })
    }

    /// Turn this OAuthResource into an OAuthRequest for processing
    pub fn into_request(self) -> OAuthRequest {
        OAuthRequest {
            query: None,
            body: None,
            auth: self.auth,
        }
    }
}

impl OAuthResponse {
    /// Create a simple response with no body and a '200 OK' HTTP Status
    pub fn ok() -> Self {
        OAuthResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    /// Set the `ContentType` header on a response
    pub fn content_type(mut self, content_type: &str) -> Result<Self, WebError> {
        self.headers
            .insert(header::CONTENT_TYPE, TryFrom::try_from(content_type)?);
        Ok(self)
    }

    /// Set the bodyfor the response
    pub fn body(mut self, body: &str) -> Self {
        self.body = Some(body.to_owned());
        self
    }
}

impl<Operation, Extras> OAuthMessage<Operation, Extras> {
    /// Produce an OAuthOperation from a wrapping OAuthMessage
    pub fn into_inner(self) -> (Operation, Extras) {
        (self.0, self.1)
    }
}

impl WebRequest for OAuthRequest {
    type Error = WebError;
    type Response = OAuthResponse;

    fn query(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        self.query
            .as_ref()
            .map(|q| Cow::Borrowed(q as &dyn QueryParameter))
            .ok_or(WebError::Query)
    }

    fn urlbody(&mut self) -> Result<Cow<dyn QueryParameter + 'static>, Self::Error> {
        self.body
            .as_ref()
            .map(|b| Cow::Borrowed(b as &dyn QueryParameter))
            .ok_or(WebError::Body)
    }

    fn authheader(&mut self) -> Result<Option<Cow<str>>, Self::Error> {
        Ok(self.auth.as_deref().map(Cow::Borrowed))
    }
}

impl WebResponse for OAuthResponse {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.status = StatusCode::OK;
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.status = StatusCode::FOUND;
        let location = String::from(url);
        self.headers
            .insert(header::LOCATION, TryFrom::try_from(location)?);
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = StatusCode::BAD_REQUEST;
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.status = StatusCode::UNAUTHORIZED;
        self.headers
            .insert(header::WWW_AUTHENTICATE, TryFrom::try_from(kind)?);
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.body = Some(text.to_owned());
        self.headers
            .insert(header::CONTENT_TYPE, TryFrom::try_from("text/plain")?);
        Ok(())
    }

    fn body_json(&mut self, json: &str) -> Result<(), Self::Error> {
        self.body = Some(json.to_owned());
        self.headers
            .insert(header::CONTENT_TYPE, TryFrom::try_from("application/json")?);
        Ok(())
    }
}

impl<Operation, Extras> Message for OAuthMessage<Operation, Extras>
where
    Operation: OAuthOperation + 'static,
{
    type Result = Result<Operation::Item, Operation::Error>;
}

impl FromRequest for OAuthRequest {
    type Error = WebError;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        Self::new(req.clone(), payload.take()).boxed_local()
    }
}

impl FromRequest for OAuthResource {
    type Error = WebError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        future::ready(Self::new(req))
    }
}

impl Responder for OAuthResponse {
    type Body = BoxBody;

    fn respond_to(self, _: &HttpRequest) -> HttpResponse {
        let mut builder = HttpResponseBuilder::new(self.status);
        for (k, v) in self.headers.into_iter() {
            builder.insert_header((k, v.to_owned()));
        }

        if let Some(body) = self.body {
            builder.body(body)
        } else {
            builder.finish()
        }
    }
}

impl From<OAuthResource> for OAuthRequest {
    fn from(o: OAuthResource) -> Self {
        o.into_request()
    }
}

impl Default for OAuthResponse {
    fn default() -> Self {
        OAuthResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: None,
        }
    }
}

impl From<Error<OAuthRequest>> for WebError {
    fn from(e: Error<OAuthRequest>) -> Self {
        match e {
            Error::Web(e) => e,
            Error::OAuth(e) => e.into(),
        }
    }
}

impl From<InvalidHeaderValue> for WebError {
    fn from(e: InvalidHeaderValue) -> Self {
        WebError::Header(e)
    }
}

impl From<MailboxError> for WebError {
    fn from(e: MailboxError) -> Self {
        match e {
            MailboxError::Closed => WebError::Mailbox,
            MailboxError::Timeout => WebError::Canceled,
        }
    }
}

impl From<OAuthError> for WebError {
    fn from(e: OAuthError) -> Self {
        WebError::Endpoint(e)
    }
}

impl fmt::Display for WebError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WebError::Endpoint(ref e) => write!(f, "Endpoint, {}", e),
            WebError::Header(ref e) => write!(f, "Couldn't set header, {}", e),
            WebError::Encoding => write!(f, "Error decoding request"),
            WebError::Form => write!(f, "Request is not a form"),
            WebError::Query => write!(f, "No query present"),
            WebError::Body => write!(f, "No body present"),
            WebError::Authorization => write!(f, "Request has invalid Authorization headers"),
            WebError::Canceled => write!(f, "Operation canceled"),
            WebError::Mailbox => write!(f, "An actor's mailbox was full"),
            WebError::InternalError(None) => write!(f, "An internal server error occured"),
            WebError::InternalError(Some(ref e)) => write!(f, "An internal server error occured: {}", e),
        }
    }
}

impl error::Error for WebError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            WebError::Endpoint(ref e) => e.source(),
            WebError::Header(ref e) => e.source(),
            WebError::Encoding
            | WebError::Form
            | WebError::Authorization
            | WebError::Query
            | WebError::Body
            | WebError::Canceled
            | WebError::Mailbox
            | WebError::InternalError(_) => None,
        }
    }
}

impl ResponseError for WebError {
    // Default to 500 for now
}
