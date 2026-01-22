extern crate iron;
extern crate oxide_auth;
extern crate oxide_auth_iron;
extern crate router;

use std::sync::{Arc, Mutex};
use std::thread::spawn;

use iron::{Iron, IronError, Request, Response};
use iron::headers::ContentType;
use iron::status::Status;
use iron::middleware::Handler;

use oxide_auth::endpoint::{OwnerConsent, Solicitation};
use oxide_auth::frontends::simple::endpoint::{FnSolicitor, Generic, Vacant};
use oxide_auth::primitives::prelude::*;
use oxide_auth_iron::{OAuthRequest, OAuthResponse, OAuthError};

#[rustfmt::skip]
#[path = "../../examples/support/iron.rs"]
mod support;

struct EndpointState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenSigner>,
}

fn main_router() -> impl Handler + 'static {
    let state = Arc::new(EndpointState::preconfigured());

    // One clone for each of the move-closures below.
    let (auth_get_state, auth_post_state, token_state, get_state) =
        (state.clone(), state.clone(), state.clone(), state.clone());
    let mut router = router::Router::new();
    router.get(
        "/authorize",
        move |request: &mut Request| {
            let state = auth_get_state.clone();
            let response = state
                .endpoint()
                .with_solicitor(FnSolicitor(consent_form))
                .authorization_flow()
                .execute(request.into())
                .map_err(|e| {
                    let e: OAuthError = e.into();
                    IronError::from(e)
                })?;
            Ok(response.into())
        },
        "authorization_get",
    );
    router.post(
        "/authorize",
        move |request: &mut Request| {
            let state = auth_post_state.clone();
            let response = state
                .endpoint()
                .with_solicitor(FnSolicitor(consent_decision))
                .authorization_flow()
                .execute(request.into())
                .map_err(|e| {
                    let e: OAuthError = e.into();
                    IronError::from(e)
                })?;
            Ok(response.into())
        },
        "authorization_post",
    );
    router.post(
        "/token",
        move |request: &mut Request| {
            let state = token_state.clone();
            let response = state
                .endpoint()
                .access_token_flow()
                .execute(request.into())
                .map_err(|e| {
                    let e: OAuthError = e.into();
                    IronError::from(e)
                })?;
            Ok(response.into())
        },
        "token",
    );
    router.get(
        "/",
        move |request: &mut Request| {
            let oauth_request: OAuthRequest = request.into();

            let state = get_state.clone();
            let protect = state
                .endpoint()
                .with_scopes(vec!["default-scope".parse().unwrap()])
                .resource_flow()
                .execute(oauth_request);

            let _grant = match protect {
                Ok(grant) => grant,
                Err(Ok(mut response)) => {
                    response.set_header(ContentType::html());
                    response.set_body(EndpointState::DENY_TEXT);
                    return Ok(response.into());
                }
                Err(Err(error)) => {
                    let error: OAuthError = error.into();
                    return Err(error.into());
                }
            };

            Ok(Response::with((Status::Ok, "Hello, world!")))
        },
        "protected",
    );

    router
}

fn main() {
    let server = spawn(|| {
        Iron::new(main_router())
            .http("127.0.0.1:8020")
            .expect("Failed to launch authorization server");
    });

    let client = spawn(|| {
        Iron::new(support::dummy_client())
            .http("127.0.0.1:8021")
            .expect("Failed to launch client");
    });

    support::open_in_browser(8020);

    server.join().unwrap();
    client.join().unwrap();
}

impl EndpointState {
    const DENY_TEXT: &'static str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

    fn preconfigured() -> Self {
        EndpointState {
            registrar: Mutex::new(
                vec![Client::public(
                    "LocalClient",
                    "http://localhost:8021/endpoint"
                        .parse::<url::Url>()
                        .unwrap()
                        .into(),
                    "default-scope".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
            ),
            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),
            issuer: Mutex::new(TokenSigner::ephemeral()),
        }
    }

    /// In larger app, you'd likey wrap it in your own Endpoint instead of `Generic`.
    pub fn endpoint(
        &self,
    ) -> Generic<
        impl Registrar + '_,
        impl Authorizer + '_,
        impl Issuer + '_,
        Vacant,
        Vacant,
        fn() -> OAuthResponse,
    > {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            // Solicitor configured later.
            solicitor: Vacant,
            // Scope configured later.
            scopes: Vacant,
            // `iron::Response` is not `Default`, so we choose a constructor.
            response: OAuthResponse::new,
        }
    }
}

fn consent_form(_: &mut OAuthRequest, solication: Solicitation) -> OwnerConsent<OAuthResponse> {
    let mut response = OAuthResponse::new();
    response.set_status(Status::Ok);
    response.set_header(ContentType::html());
    response.set_body(&support::consent_page_html("/authorize", solication));
    OwnerConsent::InProgress(response)
}

fn consent_decision(request: &mut OAuthRequest, _: Solicitation) -> OwnerConsent<OAuthResponse> {
    // Authenticate the request better in a real app!
    let allowed = request.url().query_pairs().any(|(key, _)| key == "allow");
    if allowed {
        OwnerConsent::Authorized("dummy user".into())
    } else {
        OwnerConsent::Denied
    }
}
