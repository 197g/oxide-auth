use oxide_auth::frontends::dev::{NormalizedParameter, QueryParameter, WebRequest};
use axum::{
    extract::{Query, Form, FromRequest, FromRequestParts, Request},
    http::{header, request::Parts},
};
use crate::{OAuthResponse, WebError};
use std::borrow::Cow;

#[derive(Clone, Debug, Default)]
/// Type implementing `WebRequest` as well as `FromRequest` for use in route handlers
///
/// This type consumes the body of the Request upon extraction, so be careful not to use it in
/// places you also expect an application payload
pub struct OAuthRequest {
    auth: Option<String>,
    query: Option<NormalizedParameter>,
    body: Option<NormalizedParameter>,
}

/// Type implementing `WebRequest` as well as `FromRequest` for use in guarding resources
///
/// This is useful over [OAuthRequest] since [OAuthResource] doesn't consume the body of the
/// request upon extraction
pub struct OAuthResource {
    auth: Option<String>,
}

impl OAuthRequest {
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

impl From<OAuthResource> for OAuthRequest {
    fn from(r: OAuthResource) -> OAuthRequest {
        OAuthRequest {
            auth: r.auth,
            ..Default::default()
        }
    }
}

impl WebRequest for OAuthRequest {
    type Error = WebError;
    type Response = OAuthResponse;

    fn query(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        self.query
            .as_ref()
            .map(|q| Cow::Borrowed(q as &dyn QueryParameter))
            .ok_or(WebError::Query)
    }

    fn urlbody(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        self.body
            .as_ref()
            .map(|b| Cow::Borrowed(b as &dyn QueryParameter))
            .ok_or(WebError::Body)
    }

    fn authheader(&mut self) -> Result<Option<Cow<'_, str>>, Self::Error> {
        Ok(self.auth.as_deref().map(Cow::Borrowed))
    }
}

impl<S> FromRequest<S> for OAuthRequest
where
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let mut all_auth = req.headers().get_all(header::AUTHORIZATION).iter();
        let optional = all_auth.next();

        let auth = if all_auth.next().is_some() {
            return Err(WebError::Authorization);
        } else {
            optional.and_then(|hv| hv.to_str().ok().map(str::to_owned))
        };

        let (mut parts, body) = req.into_parts();
        let query = Query::from_request_parts(&mut parts, state)
            .await
            .ok()
            .map(|q: Query<NormalizedParameter>| q.0);

        let req = Request::from_parts(parts, body);
        let body = Form::from_request(req, state)
            .await
            .ok()
            .map(|b: Form<NormalizedParameter>| b.0);

        Ok(Self { auth, query, body })
    }
}

impl<S> FromRequestParts<S> for OAuthResource
where
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let mut all_auth = parts.headers.get_all(header::AUTHORIZATION).iter();
        let optional = all_auth.next();

        let auth = if all_auth.next().is_some() {
            return Err(WebError::Authorization);
        } else {
            optional.and_then(|hv| hv.to_str().ok().map(str::to_owned))
        };

        Ok(Self { auth })
    }
}

impl OAuthResource {
    /// Fetch the authorization header from the request
    pub fn authorization_header(&self) -> Option<&str> {
        self.auth.as_deref()
    }
}
