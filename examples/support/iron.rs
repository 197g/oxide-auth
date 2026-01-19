extern crate serde;
extern crate serde_json;

#[path = "./generic.rs"]
mod generic;

pub use self::generic::*;

use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, RwLock};

use iron::{headers, modifiers, IronResult, Request, Response};
use iron::middleware::Handler;
use iron::status::Status;
use reqwest::header;

/// Rough client function mirroring core functionality of an oauth client. This is not actually
/// needed in your implementation but merely exists to provide an interactive example. It will
/// always identify itself as `LocalClient` with redirect url `http://localhost:8021/endpoint`.

#[derive(Default)]
struct State {
    token: RwLock<Option<String>>,
    token_map: RwLock<Option<String>>,
}

pub fn dummy_client() -> impl Handler + 'static {
    let get_state = Arc::new(State::default());
    let endpoint_state = get_state.clone();
    let mut router = router::Router::new();
    router.get(
        "/endpoint",
        move |request: &mut Request| endpoint(get_state.clone(), request),
        "endpoint",
    );
    router.get(
        "/",
        move |request: &mut Request| view(endpoint_state.clone(), request),
        "view",
    );
    router
}

/// Receive the authorization codes at 'http://localhost:8021/endpoint'.
fn endpoint(state: Arc<State>, req: &mut Request) -> IronResult<Response> {
    // Check the received parameters in the input
    let query = req.url.as_ref().query_pairs().collect::<HashMap<_, _>>();

    if let Some(error) = query.get("error") {
        let message = format!("Error during owner authorization: {}", error.as_ref());
        return Ok(Response::with((Status::Ok, message)));
    };

    let code = match query.get("code") {
        None => return Ok(Response::with((Status::BadRequest, "Missing code"))),
        Some(v) => v.clone(),
    };

    // Construct a request against http://localhost:8020/token, the access token endpoint
    let client = reqwest::blocking::Client::new();
    let mut params = HashMap::new();
    params.insert("grant_type", "authorization_code");
    params.insert("client_id", "LocalClient");
    params.insert("code", &code);
    params.insert("redirect_uri", "http://localhost:8021/endpoint");
    let access_token_request = client
        .post("http://localhost:8020/token")
        .form(&params)
        .build()
        .unwrap();
    let mut token_response = match client.execute(access_token_request) {
        Ok(response) => response,
        Err(_) => {
            return Ok(Response::with((
                Status::InternalServerError,
                "Could not fetch bearer token",
            )))
        }
    };

    let mut token = String::new();
    token_response.read_to_string(&mut token).unwrap();
    let token_map: HashMap<String, String> = match serde_json::from_str(&token) {
        Ok(response) => response,
        Err(err) => {
            return Ok(Response::with((
                Status::BadRequest,
                format!("Could not parse token response {:?}", err),
            )))
        }
    };

    if token_map.contains_key("error") {
        return Ok(Response::with((Status::BadRequest, token)));
    }

    let token = match token_map.get("access_token") {
        None => return Ok(Response::with((Status::BadRequest, token))),
        Some(token) => token,
    };

    let token_map = serde_json::to_string_pretty(&token_map).unwrap();
    let token_map = token_map.replace(",", ",</br>");

    let mut set_map = state.token_map.write().unwrap();
    *set_map = Some(token_map);

    let mut set_token = state.token.write().unwrap();
    *set_token = Some(token.to_string());

    let mut response = Response::with(Status::Found);
    response.headers.set(headers::Location("/".into()));
    Ok(response)
}

fn view(state: Arc<State>, _: &mut Request) -> IronResult<Response> {
    let token = state.token.read().unwrap();
    let token = match *token {
        None => return Ok(Response::with((Status::Ok, "No token granted yet"))),
        Some(ref token) => token,
    };

    let token_map = state.token_map.read().unwrap();
    let token_map = token_map.as_ref().unwrap();

    let client = reqwest::blocking::Client::new();
    // Request the page with the oauth token
    let page_request = client
        .get("http://localhost:8020/")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .build()
        .unwrap();

    let mut page_response = match client.execute(page_request) {
        Ok(response) => response,
        Err(_) => {
            return Ok(Response::with((
                Status::BadRequest,
                "Could not access protected resource",
            )))
        }
    };

    let mut protected_page = String::new();
    page_response.read_to_string(&mut protected_page).unwrap();

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
        </main></html>", token_map, protected_page);

    Ok(Response::with((
        Status::Ok,
        modifiers::Header(headers::ContentType::html()),
        display_page,
    )))
}
