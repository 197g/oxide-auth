#[rustfmt::skip]
#[path = "../../../../examples/support/generic.rs"]
mod generic;

use std::collections::HashMap;

pub use self::generic::{consent_page_html, open_in_browser, Client, ClientConfig, ClientError};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

pub async fn dummy_client() {
    let client = Arc::new(Client::new(ClientConfig {
        client_id: "LocalClient".into(),
        client_secret: Some("SecretSecret".to_owned()),
        protected_url: "http://localhost:8020/".into(),
        token_url: "http://localhost:8020/token".into(),
        refresh_url: "http://localhost:8020/refresh".into(),
        redirect_uri: "http://localhost:8021/endpoint".into(),
    }));

    let app = Router::new()
        .route("/", get(get_with_token))
        .route("/endpoint", get(endpoint_impl))
        .route("/refresh", post(refresh))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
        )
        .with_state(client);

    let listener = tokio::net::TcpListener::bind("localhost:8021")
        .await
        .expect("Failed to start dummy client");

    println!("Dummy client running on http://localhost:8021");

    axum::serve(listener, app)
        .await
        .expect("Failed to run dummy client");
}

async fn endpoint_impl(
    Query(query): Query<HashMap<String, String>>,
    State(client): State<Arc<Client>>,
) -> Response {
    if let Some(cause) = query.get("error") {
        return (
            StatusCode::BAD_REQUEST,
            format!("Error during owner authorization: {:?}", cause)
        ).into_response();
    }

    let code = match query.get("code") {
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing code"
            ).into_response();
        }
        Some(code) => code.clone(),
    };

    let auth_handle = tokio::task::spawn_blocking(move || {
        client.authorize(&code)
    });
    
    match auth_handle.await {
        Ok(Ok(())) => Redirect::to("/").into_response(),
        Ok(Err(err)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{}", err)
        ).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Task join error: {}", err)
        ).into_response(),
    }
}

async fn refresh(State(client): State<Arc<Client>>) -> Response {
    let refresh_handle = tokio::task::spawn_blocking(move || {
        client.refresh()
    });
    
    match refresh_handle.await {
        Ok(Ok(())) => Redirect::to("/").into_response(),
        Ok(Err(err)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{}", err)
        ).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Task join error: {}", err)
        ).into_response(),
    }
}

async fn get_with_token(State(client): State<Arc<Client>>) -> Response {
    let html = client.as_html();
    let client_clone = client.clone();

    let protected_page_handle = tokio::task::spawn_blocking(move || {
        client_clone.retrieve_protected_page()
    });
    
    let protected_page = match protected_page_handle.await {
        Ok(Ok(page)) => page,
        Ok(Err(err)) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("{}", err)
            ).into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Task join error: {}", err)
            ).into_response();
        }
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
        </main></html>", html, protected_page);

    Html(display_page).into_response()
}