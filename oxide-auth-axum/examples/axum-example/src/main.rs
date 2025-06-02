mod support;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Router,
};
use oxide_auth::{
    endpoint::{AccessTokenFlow, AuthorizationFlow, Authorizer, Issuer, OwnerConsent, QueryParameter, RefreshFlow, Registrar, ResourceFlow, Solicitation},
    frontends::simple::endpoint::{FnSolicitor, Generic, Vacant},
    primitives::{grant::Grant, prelude::{AuthMap, Client, ClientMap, RandomGenerator, Scope, TokenMap}},
};
use oxide_auth_axum::{OAuthRequest, OAuthResource, OAuthResponse, WebError};
use std::{collections::HashMap, iter::FromIterator, sync::Arc};
use std::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use oxide_auth::frontends::dev::WebResponse;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

fn ok_response() -> OAuthResponse {
    let mut response = OAuthResponse::default();
    response.ok().unwrap();
    response
}

struct OAuthState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenMap<RandomGenerator>>,
}

impl OAuthState {
    pub fn preconfigured() -> Self {
        let client_map = ClientMap::from_iter(
            vec![Client::confidential(
                "LocalClient",
                "http://localhost:8021/endpoint"
                    .parse::<url::Url>()
                    .unwrap()
                    .into(),
                "default-scope".parse().unwrap(),
                "SecretSecret".as_bytes(),
            )]
        );
        OAuthState {
            registrar: Mutex::new(client_map),
            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),
            issuer: Mutex::new(TokenMap::new(RandomGenerator::new(16))),
        }
    }

    /// In larger app, you'd likey wrap it in your own Endpoint instead of `Generic`.
    pub fn endpoint(&self) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_, Vacant, Vec<Scope>> {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            // Solicitor configured later.
            solicitor: Vacant,
            scopes: vec!["default-scope".parse().unwrap()],
            // OAuthResponse is Default
            response: Vacant,
        }
    }
}

type SharedState = Arc<OAuthState>;



#[axum::debug_handler]
async fn get_authorize(
    State(state): State<SharedState>,
    req: OAuthRequest,
) -> Result<Response, WebError> {
    let solicitor = FnSolicitor(move |_: &mut OAuthRequest, pre_grant: Solicitation| {
        // This will display a page to the user asking for his permission to proceed. The submitted form
        // will then trigger the other authorization handler which actually completes the flow.
        OwnerConsent::InProgress(
            ok_response()
                .content_type("text/html")
                .unwrap()
                .body(&crate::support::consent_page_html("/authorize".into(), pre_grant))
        )
    });
    let endpoint = state.endpoint().with_solicitor(solicitor);

    AuthorizationFlow::prepare(endpoint)
        .expect("Failed to prepare authorization flow")
        .execute(req)
        .map(|resp| resp.into_response())
        .map_err(WebError::from)
}

#[axum::debug_handler]
async fn post_authorize(
    State(state): State<SharedState>,
    Query(params): Query<HashMap<String, String>>,
    req: OAuthRequest,
) -> Result<Response, WebError> {
    let allow = params.get("allow").is_some();
    let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
        if allow {
            // TODO: change this from dummy user to the actual user
            OwnerConsent::Authorized("dummy user".to_owned())
        } else {
            OwnerConsent::Denied
        }
    });
    let endpoint = state.endpoint().with_solicitor(solicitor);

    AuthorizationFlow::prepare(endpoint)
        .expect("Failed to prepare authorization flow")
        .execute(req)
        .map(|resp| resp.into_response())
        .map_err(WebError::from)
}

#[axum::debug_handler]
async fn token(
    State(state): State<SharedState>,
    req: OAuthRequest,
) -> Result<Response, WebError> {
    let grant_type = req.body().and_then(|body| body.unique_value("grant_type"));
    
    // Different grant types determine which flow to perform.
    match grant_type.as_deref() {
        Some("client_credentials") => {
            let solicitor = FnSolicitor(move |_: &mut OAuthRequest, solicitation: Solicitation| {
                // For the client credentials flow, the solicitor is consulted
                // to ensure that the resulting access token is issued to the
                // correct owner. This may be the client itself, if clients
                // and resource owners are from the same set of entities, but
                // may be distinct if that is not the case.
                OwnerConsent::Authorized(solicitation.pre_grant().client_id.clone())
            });
            let endpoint = state.endpoint().with_solicitor(solicitor);

            AccessTokenFlow::prepare(endpoint)
                .expect("Failed to prepare access token flow")
                .execute(req)
                .map(|resp| resp.into_response())
                .map_err(WebError::from)
        }
        // Each flow will validate the grant_type again, so we can let one case handle
        // any incorrect or unsupported options.
        _ => {
            let endpoint = state.endpoint();
            AccessTokenFlow::prepare(endpoint)
            .expect("Failed to prepare access token flow")
            .execute(req)
            .map(|resp| resp.into_response())
            .map_err(WebError::from)
        }
    }
}

#[axum::debug_handler]
async fn refresh(
    State(state): State<SharedState>,
    req: OAuthRequest,
) -> Result<Response, WebError> {
    RefreshFlow::prepare(state.endpoint())?
        .execute(req)
        .map(|resp| resp.into_response())
        .map_err(WebError::from)
}

fn resource_flow(endpoint: Generic<impl Registrar, impl Authorizer, impl Issuer, Vacant, Vec<Scope>>, req: OAuthResource) -> Result<Grant, Result<OAuthResponse, WebError>> {
    ResourceFlow::prepare(endpoint)
    .expect("Failed to prepare resource flow")
    .execute(req.into())
    .map_err(|r| r.map_err(WebError::from))
}

#[axum::debug_handler]
async fn index(
    State(state): State<SharedState>,
    req: OAuthResource,
) -> Result<Response, StatusCode> {
    let endpoint = state.endpoint();
    match resource_flow(endpoint, req) {
        Ok(_grant) => Ok("Hello world!".into_response()),
        Err(_) => Ok(Html(DENY_TEXT).into_response()), // TODO: we still have a Result<OAuthResponse, WebError> here
    }
}

async fn start_browser() {
    let _ = tokio::spawn(async { support::open_in_browser(8020) });
}

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> std::io::Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "axum_example=info,tower_http=info",
    );
    tracing_subscriber::fmt::init();

    // Start, then open in browser, don't care about this finishing.
    tokio::spawn(start_browser());

    let state = Arc::new(OAuthState::preconfigured());

    // Create the main server instance
    let app = Router::new()
        .route("/", get(index))
        .route("/authorize", get(get_authorize).post(post_authorize))
        .route("/token", post(token))
        .route("/refresh", post(refresh))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("localhost:8020")
        .await
        .expect("Failed to bind to socket");

    println!("Server running on http://localhost:8020");

    let server = axum::serve(listener, app);
    let client = support::dummy_client();

    tokio::select! {
        result = server => result.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
        result = client => result,
    }

    Ok(())
}