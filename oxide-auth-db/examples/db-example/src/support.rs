#[rustfmt::skip]
#[path = "../../../../examples/support/generic.rs"]
mod generic;

use std::collections::HashMap;

pub use self::generic::{consent_page_html, open_in_browser, Client, ClientConfig};

use actix_web::App;
use actix_web::*;

pub fn dummy_client() -> dev::Server {
    HttpServer::new(move || {
        let config = ClientConfig {
            client_id: "LocalClient".into(),
            client_secret: Option::from("test".to_string()),
            protected_url: "http://localhost:8020/".into(),
            token_url: "http://localhost:8020/token".into(),
            refresh_url: "http://localhost:8020/refresh".into(),
            redirect_uri: "http://localhost:8021/endpoint".into(),
        };

        App::new()
            .app_data(Client::new(config))
            .route("/endpoint", web::get().to(endpoint_impl))
            .route("/refresh", web::post().to(refresh))
            .route("/", web::get().to(get_with_token))
    })
    .bind("localhost:8021")
    .expect("Failed to start dummy client")
    .run()
}

async fn endpoint_impl(
    (query, state): (web::Query<HashMap<String, String>>, web::Data<Client>),
) -> HttpResponse {
    if let Some(cause) = query.get("error") {
        return HttpResponse::BadRequest()
            .body(format!("Error during owner authorization: {:?}", cause));
    }

    let code = match query.get("code") {
        None => return HttpResponse::BadRequest().body("Missing code"),
        Some(code) => code.clone(),
    };

    match state.authorize(&code) {
        Ok(()) => HttpResponse::Found().append_header(("Location", "/")).finish(),
        Err(err) => HttpResponse::InternalServerError().body(format!("{}", err)),
    }
}

async fn refresh(state: web::Data<Client>) -> HttpResponse {
    match state.refresh() {
        Ok(()) => HttpResponse::Found().append_header(("Location", "/")).finish(),
        Err(err) => HttpResponse::InternalServerError().body(format!("{}", err)),
    }
}

async fn get_with_token(state: web::Data<Client>) -> HttpResponse {
    let protected_page = match state.retrieve_protected_page() {
        Ok(page) => page,
        Err(err) => return HttpResponse::InternalServerError().body(format!("{}", err)),
    };

    let display_page = format!(
        "<html><style>
            aside{{overflow: auto; word-break: keep-all; white-space: nowrap}}
            main{{text-align: center}}
            main>aside,main>article{{margin: auto; text-align: left; border: 1px solid black; width: 50%}}
        </style>
        <main>
        Used token <aside style>{}</aside> to access
        <a href=\"http://localhost:8020/\">http://localhost:8020/</a>.
        Its contents are:
        <article>{}</article>
        <form action=\"refresh\" method=\"post\"><button>Refresh token</button></form>
        </main></html>", state.as_html(), protected_page);

    HttpResponse::Ok().content_type("text/html").body(display_page)
}
