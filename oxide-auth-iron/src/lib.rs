//! Offers bindings for the code_grant module with iron servers.
//!
//! ## Hello world
//!
#![warn(missing_docs)]

use std::borrow::Cow;

use oxide_auth::endpoint::{OAuthError as EndpointError, QueryParameter, WebRequest, WebResponse};
use oxide_auth::frontends::simple::endpoint::Error as SimpleError;

use iron::{Request, Response};
use iron::error::IronError;
use iron::headers;
use iron::status::Status;
use url::Url;

/// Errors while decoding requests.
pub enum Error {
    /// Generally describes a malformed request.
    BadRequest,
}

#[derive(Debug)]
/// Request type that can be derived from an `iron::Request`.
///
/// For now this is a shim around an `&mut iron::Request`, but in the future the implementation
/// could change.
pub struct OAuthRequest<'a, 'b, 'c: 'b>(&'a mut Request<'b, 'c>);

#[derive(Debug)]
/// Response type that can be coerced into an `iron::Response`.
///
/// For now this is a shim around an `iron::Response`, but in the future the implementation
/// could change.
pub struct OAuthResponse(Response);

#[derive(Debug)]
/// Generic error type produced by Oxide Auth operations that can be coerced into an `IronError`
pub struct OAuthError(IronError);

impl<'a, 'b, 'c: 'b> OAuthRequest<'a, 'b, 'c> {
    /// Coerce an `iron::Request` into an OAuthRequest.
    pub fn from_request(request: &'a mut Request<'b, 'c>) -> Self {
        OAuthRequest(request)
    }

    /// Fetch the URL accessed for this request
    pub fn url(&self) -> &iron::url::Url {
        self.0.url.as_ref()
    }

    /// Fetch the query string from the request, returning an empty string if none was present.
    pub fn query_string(&self) -> &str {
        self.0.url.query().unwrap_or("")
    }

    /// Returns whether the request was sent with the correct ContentType header.
    pub fn is_form_url_encoded(&self) -> bool {
        self.0
            .headers
            .get::<headers::ContentType>()
            .map(|ct| ct == &headers::ContentType::form_url_encoded())
            .unwrap_or(false)
    }

    /// Fetch authorization header
    pub fn authorization_header(&self) -> Option<Cow<'_, str>> {
        // Get the raw header.
        self.0
            .headers
            .get::<headers::Authorization<String>>()
            .map(|h| Cow::Borrowed(h.0.as_ref()))
    }
}

impl OAuthResponse {
    /// Create a new, empty OAuthResponse
    pub fn new() -> Self {
        OAuthResponse(Response::new())
    }

    /// Createa a new OAuthResponse from an existing `iron::Response`
    pub fn from_response(response: Response) -> Self {
        OAuthResponse(response)
    }

    /// Set the HTTP Status for the OAuthResponse
    pub fn set_status(&mut self, status: Status) {
        self.0.status = Some(status);
    }

    /// Set a header on the OAuthResponse
    pub fn set_header<H>(&mut self, header: H)
    where
        H: headers::HeaderFormat + headers::Header,
    {
        self.0.headers.set(header);
    }

    /// Set a header on the OAuthResponse via name and value directly
    pub fn set_raw_header(&mut self, name: Cow<'static, str>, values: Vec<Vec<u8>>) {
        self.0.headers.set_raw(name, values);
    }

    /// Set the body on the OAuthResponse to the provided string
    pub fn set_body(&mut self, body: &str) {
        self.0.body = Some(Box::new(body.to_string()));
    }
}

impl Default for OAuthResponse {
    fn default() -> Self {
        OAuthResponse::new()
    }
}

/// Requests are handed as mutable reference to the underlying object.
impl<'a, 'b, 'c: 'b> WebRequest for OAuthRequest<'a, 'b, 'c> {
    type Response = OAuthResponse;
    type Error = Error;

    fn query(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        serde_urlencoded::from_str(self.query_string())
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn urlbody(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        let formatted = self.is_form_url_encoded();
        if !formatted {
            return Err(Error::BadRequest);
        }

        serde_urlencoded::from_reader(&mut self.0.body)
            .map_err(|_| Error::BadRequest)
            .map(Cow::Owned)
    }

    fn authheader(&mut self) -> Result<Option<Cow<'_, str>>, Self::Error> {
        Ok(self.authorization_header())
    }
}

impl WebResponse for OAuthResponse {
    type Error = Error;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.set_status(Status::Ok);
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.set_status(Status::Found);
        self.set_header(headers::Location(url.into()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.set_status(Status::BadRequest);
        Ok(())
    }

    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> {
        self.set_status(Status::Unauthorized);
        let value_owned = header_value.as_bytes().to_vec();
        self.set_raw_header("WWW-Authenticate".into(), vec![value_owned]);
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.set_header(headers::ContentType::plaintext());
        self.set_body(text);
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.set_header(headers::ContentType::json());
        self.set_body(data);
        Ok(())
    }
}

impl<'a, 'b, 'c: 'b> From<&'a mut Request<'b, 'c>> for OAuthRequest<'a, 'b, 'c> {
    fn from(r: &'a mut Request<'b, 'c>) -> Self {
        OAuthRequest::from_request(r)
    }
}

impl<'a, 'b, 'c: 'b> From<OAuthRequest<'a, 'b, 'c>> for &'a mut Request<'b, 'c> {
    fn from(val: OAuthRequest<'a, 'b, 'c>) -> &'a mut Request<'b, 'c> {
        val.0
    }
}

impl From<Response> for OAuthResponse {
    fn from(r: Response) -> Self {
        OAuthResponse::from_response(r)
    }
}

impl From<OAuthResponse> for Response {
    fn from(val: OAuthResponse) -> Response {
        val.0
    }
}

impl<'a, 'b, 'c: 'b> From<SimpleError<OAuthRequest<'a, 'b, 'c>>> for OAuthError {
    fn from(error: SimpleError<OAuthRequest<'a, 'b, 'c>>) -> Self {
        let as_oauth = match error {
            SimpleError::Web(Error::BadRequest) => EndpointError::BadRequest,
            SimpleError::OAuth(oauth) => oauth,
        };

        let status = match as_oauth {
            EndpointError::BadRequest => Status::BadRequest,
            EndpointError::DenySilently => Status::BadRequest,
            EndpointError::PrimitiveError => Status::InternalServerError,
        };

        OAuthError(IronError::new(as_oauth, status))
    }
}

impl From<IronError> for OAuthError {
    fn from(e: IronError) -> Self {
        OAuthError(e)
    }
}

impl From<OAuthError> for IronError {
    fn from(val: OAuthError) -> Self {
        val.0
    }
}
