//! Offers bindings for the code_grant module with rouille servers.
//!
//! Following the simplistic and minimal style of rouille, this module defines only the
//! implementations for `WebRequest` and `WebResponse` and re-exports the available flows.
#![warn(missing_docs)]

use core::ops::Deref;
use std::borrow::Cow;

use oxide_auth::endpoint::{QueryParameter, WebRequest, WebResponse};

use rouille;
use url::Url;

// In the spirit of simplicity, this module does not implement any wrapper structures.  In order to
// allow efficient and intuitive usage, we simply re-export common structures.
pub use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic as GenericEndpoint, Vacant};

/// Something went wrong with the rouille http request or response.
#[derive(Debug)]
pub enum WebError {
    /// A parameter was encoded incorrectly.
    ///
    /// This may happen for example due to a query parameter that is not valid utf8 when the query
    /// parameters are necessary for OAuth processing.
    Encoding,
}

#[derive(Debug)]
/// The Request type used by Oxide Auth to extract required information
pub struct Request<'a> {
    inner: &'a rouille::Request,
}

#[derive(Debug)]
/// The type Oxide Auth provides in response to a request.
pub struct Response {
    inner: rouille::Response,
}

impl<'a> Request<'a> {
    /// Create a new Request from a `rouille::Request`
    pub fn new(inner: &'a rouille::Request) -> Self {
        Request { inner }
    }
}

impl Response {
    /// Produce a `rouille::Response` from a `Response`
    pub fn into_inner(self) -> rouille::Response {
        self.inner
    }
}

impl From<rouille::Response> for Response {
    fn from(inner: rouille::Response) -> Self {
        Response { inner }
    }
}

impl From<Response> for rouille::Response {
    fn from(response: Response) -> Self {
        response.inner
    }
}

impl<'a> WebRequest for Request<'a> {
    type Error = WebError;
    type Response = Response;

    fn query(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        let query = self.inner.raw_query_string();
        let data = serde_urlencoded::from_str(query).map_err(|_| WebError::Encoding)?;
        Ok(Cow::Owned(data))
    }

    fn urlbody(&mut self) -> Result<Cow<'_, dyn QueryParameter + 'static>, Self::Error> {
        match self.inner.header("Content-Type") {
            None | Some("application/x-www-form-urlencoded") => (),
            _ => return Err(WebError::Encoding),
        }

        let body = self.inner.data().ok_or(WebError::Encoding)?;
        let data = serde_urlencoded::from_reader(body).map_err(|_| WebError::Encoding)?;
        Ok(Cow::Owned(data))
    }

    fn authheader(&mut self) -> Result<Option<Cow<'_, str>>, Self::Error> {
        Ok(self.inner.header("Authorization").map(|st| st.into()))
    }
}

impl WebResponse for Response {
    type Error = WebError;

    fn ok(&mut self) -> Result<(), Self::Error> {
        self.inner.status_code = 200;
        Ok(())
    }

    fn redirect(&mut self, url: Url) -> Result<(), Self::Error> {
        self.inner.status_code = 302;
        self.inner
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("Location"));
        self.inner
            .headers
            .push(("Location".into(), String::from(url).into()));
        Ok(())
    }

    fn client_error(&mut self) -> Result<(), Self::Error> {
        self.inner.status_code = 400;
        Ok(())
    }

    fn unauthorized(&mut self, kind: &str) -> Result<(), Self::Error> {
        self.inner.status_code = 401;
        self.inner
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("www-authenticate"));
        self.inner
            .headers
            .push(("WWW-Authenticate".into(), kind.to_string().into()));
        Ok(())
    }

    fn body_text(&mut self, text: &str) -> Result<(), Self::Error> {
        self.inner
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("Content-Type"));
        self.inner
            .headers
            .push(("Content-Type".into(), "text/plain".into()));
        self.inner.data = rouille::ResponseBody::from_string(text);
        Ok(())
    }

    fn body_json(&mut self, data: &str) -> Result<(), Self::Error> {
        self.inner
            .headers
            .retain(|header| !header.0.eq_ignore_ascii_case("Content-Type"));
        self.inner
            .headers
            .push(("Content-Type".into(), "application/json".into()));
        self.inner.data = rouille::ResponseBody::from_string(data);
        Ok(())
    }
}

impl Deref for Request<'_> {
    type Target = rouille::Request;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_query() {
        let request =
            &rouille::Request::fake_http("GET", "/authorize?fine=val&param=a&param=b", vec![], vec![]);
        let mut request = Request::new(request);
        let query = WebRequest::query(&mut request).unwrap();

        assert_eq!(Some(Cow::Borrowed("val")), query.unique_value("fine"));
        assert_eq!(None, query.unique_value("param"));
    }
}
