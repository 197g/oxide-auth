mod support;

use actix::{Actor, Addr, Context, Handler};
use actix_web::{
    middleware::{Logger, NormalizePath, TrailingSlash},
    web::{self, Data},
    App, HttpRequest, HttpServer, rt,
};
use oxide_auth::{
    endpoint::{Endpoint, OwnerConsent, OwnerSolicitor, Solicitation, QueryParameter},
    frontends::simple::endpoint::{ErrorInto, FnSolicitor, Generic, Vacant},
    primitives::prelude::{AuthMap, Client, ClientMap, RandomGenerator, Scope, TokenMap},
};
use oxide_auth_actix::{
    Authorize, OAuthMessage, OAuthOperation, OAuthRequest, OAuthResource, OAuthResponse, Refresh,
    Resource, Token, WebError, ClientCredentials,
};
use std::thread;

static DENY_TEXT: &str = "<html>
This page should be accessed via an oauth token from the client in the example. Click
<a href=\"http://localhost:8020/authorize?response_type=code&client_id=LocalClient\">
here</a> to begin the authorization process.
</html>
";

struct State {
    endpoint: Generic<
        ClientMap,
        AuthMap<RandomGenerator>,
        TokenMap<RandomGenerator>,
        Vacant,
        Vec<Scope>,
        fn() -> OAuthResponse,
    >,
}

enum Extras {
    AuthGet,
    AuthPost(String),
    ClientCredentials,
    Nothing,
}

async fn get_authorize(
    (req, state): (OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    // GET requests should not mutate server state and are extremely
    // vulnerable accidental repetition as well as Cross-Site Request
    // Forgery (CSRF).
    state.send(Authorize(req).wrap(Extras::AuthGet)).await?
}

async fn post_authorize(
    (r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    // Some authentication should be performed here in production cases
    state
        .send(Authorize(req).wrap(Extras::AuthPost(r.query_string().to_owned())))
        .await?
}

async fn token((req, state): (OAuthRequest, web::Data<Addr<State>>)) -> Result<OAuthResponse, WebError> {
    let grant_type = req.body().and_then(|body| body.unique_value("grant_type"));
    // Different grant types determine which flow to perform.
    match grant_type.as_deref() {
        Some("client_credentials") => {
            state
                .send(ClientCredentials(req).wrap(Extras::ClientCredentials))
                .await?
        }
        // Each flow will validate the grant_type again, so we can let one case handle
        // any incorrect or unsupported options.
        _ => state.send(Token(req).wrap(Extras::Nothing)).await?,
    }
}

async fn refresh(
    (req, state): (OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    state.send(Refresh(req).wrap(Extras::Nothing)).await?
}

async fn index(
    (req, state): (OAuthResource, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    match state
        .send(Resource(req.into_request()).wrap(Extras::Nothing))
        .await?
    {
        Ok(_grant) => Ok(OAuthResponse::ok()
            .content_type("text/plain")?
            .body("Hello world!")),
        Err(Ok(e)) => Ok(e.body(DENY_TEXT)),
        Err(Err(e)) => Err(e),
    }
}

async fn start_browser() -> () {
    let _ = thread::spawn(|| support::open_in_browser(8020));
}

// Example of a main function of an actix-web server supporting oauth.
#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
    std::env::set_var(
        "RUST_LOG",
        "actix_example=info,actix_web=info,actix_http=info,actix_service=info",
    );
    env_logger::init();

    // Start, then open in browser, don't care about this finishing.
    rt::spawn(start_browser());

    let state = State::preconfigured().start();

    // Create the main server instance
    let server = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()))
            .wrap(NormalizePath::new(TrailingSlash::Trim))
            .wrap(Logger::default())
            .service(
                web::resource("/authorize")
                    .route(web::get().to(get_authorize))
                    .route(web::post().to(post_authorize)),
            )
            .route("/token", web::post().to(token))
            .route("/refresh", web::post().to(refresh))
            .route("/", web::get().to(index))
    })
    .bind("localhost:8020")
    .expect("Failed to bind to socket")
    .run();

    let client = support::dummy_client();

    futures::try_join!(server, client).map(|_| ())
}

impl State {
    pub fn preconfigured() -> Self {
        State {
            endpoint: Generic {
                // A registrar with one pre-registered client
                registrar: vec![Client::confidential(
                    "LocalClient",
                    "http://localhost:8021/endpoint"
                        .parse::<url::Url>()
                        .unwrap()
                        .into(),
                    "default-scope".parse().unwrap(),
                    "SecretSecret".as_bytes(),
                )]
                .into_iter()
                .collect(),
                // Authorization tokens are 16 byte random keys to a memory hash map.
                authorizer: AuthMap::new(RandomGenerator::new(16)),
                // Bearer tokens are also random generated but 256-bit tokens, since they live longer
                // and this example is somewhat paranoid.
                //
                // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
                // be read and parsed by anyone, but not maliciously created. However, they can not be
                // revoked and thus don't offer even longer lived refresh tokens.
                issuer: TokenMap::new(RandomGenerator::new(16)),

                solicitor: Vacant,

                // A single scope that will guard resources for this endpoint
                scopes: vec!["default-scope".parse().unwrap()],

                response: OAuthResponse::ok,
            },
        }
    }

    pub fn with_solicitor<'a, S>(
        &'a mut self, solicitor: S,
    ) -> impl Endpoint<OAuthRequest, Error = WebError> + 'a
    where
        S: OwnerSolicitor<OAuthRequest> + 'static,
    {
        ErrorInto::new(Generic {
            authorizer: &mut self.endpoint.authorizer,
            registrar: &mut self.endpoint.registrar,
            issuer: &mut self.endpoint.issuer,
            solicitor,
            scopes: &mut self.endpoint.scopes,
            response: OAuthResponse::ok,
        })
    }
}

impl Actor for State {
    type Context = Context<Self>;
}

impl<Op> Handler<OAuthMessage<Op, Extras>> for State
where
    Op: OAuthOperation,
{
    type Result = Result<Op::Item, Op::Error>;

    fn handle(&mut self, msg: OAuthMessage<Op, Extras>, _: &mut Self::Context) -> Self::Result {
        let (op, ex) = msg.into_inner();

        match ex {
            Extras::AuthGet => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, pre_grant: Solicitation| {
                    // This will display a page to the user asking for his permission to proceed. The submitted form
                    // will then trigger the other authorization handler which actually completes the flow.
                    OwnerConsent::InProgress(
                        OAuthResponse::ok()
                            .content_type("text/html")
                            .unwrap()
                            .body(&crate::support::consent_page_html("/authorize".into(), pre_grant)),
                    )
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::AuthPost(query_string) => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, _: Solicitation| {
                    if query_string.contains("allow") {
                        OwnerConsent::Authorized("dummy user".to_owned())
                    } else {
                        OwnerConsent::Denied
                    }
                });

                op.run(self.with_solicitor(solicitor))
            }
            Extras::ClientCredentials => {
                let solicitor = FnSolicitor(move |_: &mut OAuthRequest, solicitation: Solicitation| {
                    // For the client credentials flow, the solicitor is consulted
                    // to ensure that the resulting access token is issued to the
                    // correct owner. This may be the client itself, if clients
                    // and resource owners are from the same set of entities, but
                    // may be distinct if that is not the case.
                    OwnerConsent::Authorized(solicitation.pre_grant().client_id.clone())
                });

                op.run(self.with_solicitor(solicitor))
            }
            _ => op.run(&mut self.endpoint),
        }
    }
}
