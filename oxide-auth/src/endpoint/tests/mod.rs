use crate::{OAuthOpaqueError, endpoint::*};
use crate::primitives::generator::TagGrant;
use crate::primitives::grant::Grant;

use std::borrow::Cow;
use std::collections::HashMap;

use url::Url;

/// Open and simple implementation of `WebRequest`.
#[derive(Clone, Debug, Default)]
struct CraftedRequest {
    /// The key-value pairs in the url query component.
    pub query: Option<HashMap<String, Vec<String>>>,

    /// The key-value pairs of a `x-www-form-urlencoded` body.
    pub urlbody: Option<HashMap<String, Vec<String>>>,

    /// Provided authorization header.
    pub auth: Option<String>,
}

/// Open and simple implementation of `WebResponse`.
#[derive(Debug, Default)]
struct CraftedResponse {
    /// HTTP status code.
    pub status: Status,

    /// A location header, for example for redirects.
    pub location: Option<Url>,

    /// Indicates how the client should have authenticated.
    ///
    /// Only set with `Unauthorized` status.
    pub www_authenticate: Option<String>,

    /// Encoded body of the response.
    ///
    /// One variant for each possible encoding type.
    pub body: Option<Body>,
}

/// An enum containing the necessary HTTP status codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
enum Status {
    /// Http status code 200.
    #[default]
    Ok,

    /// Http status code 302.
    Redirect,

    /// Http status code 400.
    BadRequest,

    /// Http status code 401.
    Unauthorized,
}

/// Models the necessary body contents.
///
/// Real HTTP protocols should set a content type header for each of the body variants.
#[derive(Clone, Debug)]
enum Body {
    /// A json encoded body, `application/json`.
    Json(String),
}

#[derive(Debug)]
enum CraftedError {
    Crafted,
}

impl WebRequest for CraftedRequest {
    type Response = CraftedResponse;
    type Error = CraftedError;

    fn query(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        self.query
            .as_ref()
            .map(|hm| Cow::Borrowed(hm as &dyn QueryParameter))
            .ok_or(CraftedError::Crafted)
    }

    fn urlbody(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        self.urlbody
            .as_ref()
            .map(|hm| Cow::Borrowed(hm as &dyn QueryParameter))
            .ok_or(CraftedError::Crafted)
    }

    fn authheader(&mut self) -> Result<Option<Cow<'_, str>>, Self::Error> {
        Ok(self.auth.as_ref().map(|bearer| bearer.as_str().into()))
    }
}

impl WebResponse for CraftedResponse {
    type Error = CraftedError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.status = Status::Ok;
        self.location = None;
        self.www_authenticate = None;
        Ok(())
    }

    /// A response which will redirect the user-agent to which the response is issued.
    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.status = Status::Redirect;
        self.location = Some(url);
        self.www_authenticate = None;
        Ok(())
    }

    /// Set the response status to 400.
    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.status = Status::BadRequest;
        self.location = None;
        self.www_authenticate = None;
        Ok(())
    }

    /// Set the response status to 401 and add a `WWW-Authenticate` header.
    fn unauthorized(&mut self, header_value: &str) -> Result<(), Self::Error> {
        self.status = Status::Unauthorized;
        self.location = None;
        self.www_authenticate = Some(header_value.to_owned());
        Ok(())
    }

    /// A pure text response with no special media type set.
    fn body_text(&mut self, _: &str) -> Result<(), Self::Error> {
        unimplemented!()
    }

    /// Json repsonse data, with media type `aplication/json.
    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.body = Some(Body::Json(data.to_owned()));
        Ok(())
    }
}

struct TestGenerator(String);

impl TagGrant for TestGenerator {
    fn tag(&mut self, _: u64, _grant: &Grant) -> Result<String, OAuthOpaqueError> {
        Ok(self.0.clone())
    }
}

struct Allow(String);
struct Deny;

impl OwnerSolicitor<CraftedRequest> for Allow {
    fn check_consent(
        &mut self, _: &mut CraftedRequest, _: Solicitation,
    ) -> OwnerConsent<CraftedResponse> {
        OwnerConsent::Authorized(self.0.clone())
    }
}

impl OwnerSolicitor<CraftedRequest> for Deny {
    fn check_consent(
        &mut self, _: &mut CraftedRequest, _: Solicitation,
    ) -> OwnerConsent<CraftedResponse> {
        OwnerConsent::Denied
    }
}

impl OwnerSolicitor<CraftedRequest> for &Allow {
    fn check_consent(
        &mut self, _: &mut CraftedRequest, _: Solicitation,
    ) -> OwnerConsent<CraftedResponse> {
        OwnerConsent::Authorized(self.0.clone())
    }
}

impl OwnerSolicitor<CraftedRequest> for &Deny {
    fn check_consent(
        &mut self, _: &mut CraftedRequest, _: Solicitation,
    ) -> OwnerConsent<CraftedResponse> {
        OwnerConsent::Denied
    }
}

trait ToSingleValueQuery {
    fn to_single_value_query(self) -> HashMap<String, Vec<String>>;
}

impl<'r, I, K, V> ToSingleValueQuery for I
where
    I: Iterator<Item = &'r (K, V)>,
    K: AsRef<str> + 'r,
    V: AsRef<str> + 'r,
{
    fn to_single_value_query(self) -> HashMap<String, Vec<String>> {
        self.map(|(k, v)| (k.as_ref().to_string(), vec![v.as_ref().to_string()]))
            .collect()
    }
}

pub mod defaults {
    pub const EXAMPLE_CLIENT_ID: &str = "ClientId";
    pub const EXAMPLE_OWNER_ID: &str = "Owner";
    pub const EXAMPLE_PASSPHRASE: &str = "VGhpcyBpcyBhIHZlcnkgc2VjdXJlIHBhc3NwaHJhc2UK";
    pub const EXAMPLE_REDIRECT_URI: &str = "https://client.example/endpoint";
    pub const EXAMPLE_SCOPE: &str = "example default";
}

mod authorization;
mod access_token;
mod client_credentials;
mod resource;
mod refresh;
mod pkce;
