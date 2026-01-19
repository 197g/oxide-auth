use crate::primitives::authorizer::{AuthMap, Authorizer};
use crate::primitives::issuer::TokenMap;
use crate::primitives::grant::{Grant, Extensions};
use crate::primitives::registrar::{Client, ClientMap, RegisteredUrl};

use crate::frontends::simple::endpoint::access_token_flow;

use std::collections::HashMap;

use base64::{self, Engine};
use base64::engine::general_purpose::STANDARD;
use chrono::{Utc, Duration};
use serde_json;

use super::{Body, CraftedRequest, CraftedResponse, Status, TestGenerator, ToSingleValueQuery};
use super::defaults::*;

struct AccessTokenSetup {
    registrar: ClientMap,
    authorizer: AuthMap<TestGenerator>,
    issuer: TokenMap<TestGenerator>,
    authtoken: String,
    basic_authorization: String,
}

impl AccessTokenSetup {
    fn private_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));
        let issuer = TokenMap::new(TestGenerator("AccessToken".to_string()));

        let client = Client::confidential(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes(),
        );

        let authrequest = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        let authtoken = authorizer.authorize(authrequest).unwrap();
        registrar.register_client(client);

        let basic_authorization =
            STANDARD.encode(&format!("{}:{}", EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));

        AccessTokenSetup {
            registrar,
            authorizer,
            issuer,
            authtoken,
            basic_authorization,
        }
    }

    fn public_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));
        let issuer = TokenMap::new(TestGenerator("AccessToken".to_string()));

        let client = Client::public(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
        );

        let authrequest = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        let authtoken = authorizer.authorize(authrequest).unwrap();
        registrar.register_client(client);

        let basic_authorization =
            STANDARD.encode(&format!("{}:{}", EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));

        AccessTokenSetup {
            registrar,
            authorizer,
            issuer,
            authtoken,
            basic_authorization,
        }
    }

    fn public_client_empty_secret() -> Self {
        let mut registrar = ClientMap::new();
        let mut authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));
        let issuer = TokenMap::new(TestGenerator("AccessToken".to_string()));

        let client = Client::public(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
        );

        let authrequest = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        let authtoken = authorizer.authorize(authrequest).unwrap();
        registrar.register_client(client);

        let basic_authorization = STANDARD.encode(&format!("{}:", EXAMPLE_CLIENT_ID));

        AccessTokenSetup {
            registrar,
            authorizer,
            issuer,
            authtoken,
            basic_authorization,
        }
    }

    fn assert_json_error_set(response: &CraftedResponse) {
        match &response.body {
            Some(Body::Json(ref json)) => {
                let content: HashMap<String, String> = serde_json::from_str(json).unwrap();
                assert!(content.get("error").is_some(), "Error not set in json response");
            }
            other => panic!("Expected json encoded body, got {:?}", other),
        }

        match response.status {
            Status::Unauthorized => (),
            Status::BadRequest => (),
            _ => panic!("Expected error status, got {:?}", response),
        }
    }

    fn test_simple_error(&mut self, request: CraftedRequest) {
        match access_token_flow(&self.registrar, &mut self.authorizer, &mut self.issuer).execute(request)
        {
            Ok(ref response) => Self::assert_json_error_set(response),
            resp => panic!("Expected non-error reponse, got {:?}", resp),
        }
    }

    fn test_success(&mut self, request: CraftedRequest) {
        let response = access_token_flow(&self.registrar, &mut self.authorizer, &mut self.issuer)
            .execute(request)
            .expect("Expected non-error response");

        self.assert_ok_access_token(response);
    }

    fn test_success_body_credentials(&mut self, request: CraftedRequest) {
        let mut flow = access_token_flow(&self.registrar, &mut self.authorizer, &mut self.issuer);
        flow.allow_credentials_in_body(true);
        let response = flow.execute(request).expect("Expected non-error response");
        self.assert_ok_access_token(response);
    }

    fn assert_ok_access_token(&mut self, response: CraftedResponse) {
        assert_eq!(response.status, Status::Ok);
    }
}

#[test]
fn access_valid_public() {
    let mut setup = AccessTokenSetup::public_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_success(valid_public);
}

#[test]
fn access_valid_public_empty_secret() {
    let mut setup = AccessTokenSetup::public_client_empty_secret();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_success(valid_public);
}

/// Test the outcome when the credentials are provided in both the body and the auth header
#[test]
fn access_valid_public_duplicate_secret() {
    let mut setup = AccessTokenSetup::public_client_empty_secret();

    let duplicate_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(duplicate_public);
}

#[test]
fn access_valid_private() {
    let mut setup = AccessTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_success(valid_public);
}

#[test]
fn regression_case_insensitive_basic() {
    let mut setup = AccessTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_success(valid_public);
}

// When creating a client from a preparsed url expect all equivalent urls to also be valid
// parameters for the redirect_uri. Partly because `Url` already does some normalization during
// parsing. The RFC recommends string-based comparison when the 'client registration included the
// full redirection URI'. When passing an URL however, for the moment the only way, this does not
// apply and would be counter intuitive as such information is not preserved in `url`.
#[test]
fn access_equivalent_url() {
    use crate::primitives::authorizer::Authorizer;

    const CLIENT_ID: &str = "ConfusingClient";
    const REDIRECT_URL: &str = "https://client.example";
    const ALTERNATIVE_URL: &str = "https://client.example/";

    let mut setup = AccessTokenSetup::public_client();

    let confusing_client = Client::public(
        CLIENT_ID,
        RegisteredUrl::Semantic(REDIRECT_URL.parse().unwrap()),
        EXAMPLE_SCOPE.parse().unwrap(),
    );

    setup.registrar.register_client(confusing_client);

    let authrequest = Grant {
        client_id: CLIENT_ID.to_string(),
        owner_id: EXAMPLE_OWNER_ID.to_string(),
        redirect_uri: REDIRECT_URL.parse().unwrap(),
        scope: EXAMPLE_SCOPE.parse().unwrap(),
        until: Utc::now() + Duration::hours(1),
        extensions: Extensions::new(),
    };

    let authtoken = setup.authorizer.authorize(authrequest.clone()).unwrap();
    setup.test_success(CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT_ID),
                ("code", &authtoken),
                ("redirect_uri", REDIRECT_URL),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    });

    let authtoken = setup.authorizer.authorize(authrequest).unwrap();
    setup.test_success(CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT_ID),
                ("code", &authtoken),
                ("redirect_uri", ALTERNATIVE_URL),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    });
}

#[test]
fn access_request_unknown_client() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate as some unknown client with the passphrase
    let unknown_client = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(
            "Basic ".to_string()
                + &STANDARD.encode(&format!("{}:{}", "SomeOtherClient", EXAMPLE_PASSPHRASE)),
        ),
    };

    setup.test_simple_error(unknown_client);
}

#[test]
fn access_request_wrong_authentication() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an unsupported method (instead of Basic)
    let wrong_authentication = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("NotBasic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_authentication);
}

#[test]
fn access_request_wrong_password() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with the wrong password
    let wrong_password = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(
            "Basic ".to_string()
                + &STANDARD.encode(&format!("{}:{}", EXAMPLE_CLIENT_ID, "NotTheRightPassphrase")),
        ),
    };

    setup.test_simple_error(wrong_password);
}

#[test]
fn access_request_empty_password() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an empty password
    let empty_password = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &STANDARD.encode(&format!("{}:{}", EXAMPLE_CLIENT_ID, ""))),
    };

    setup.test_simple_error(empty_password);
}

#[test]
fn access_request_multiple_client_indications() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an unsupported method (instead of Basic)
    let multiple_client_indications = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(multiple_client_indications);
}

#[test]
fn access_request_public_authorization() {
    let mut setup = AccessTokenSetup::public_client();
    // Trying to autenticate a public client
    let public_authorization = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(public_authorization);
}

#[test]
fn access_request_public_missing_client() {
    let mut setup = AccessTokenSetup::public_client();
    // Trying to autenticate with an unsupported method (instead of Basic)
    let public_missing_client = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_simple_error(public_missing_client);
}

#[test]
fn access_request_invalid_basic() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to autenticate with an invalid basic authentication header
    let invalid_basic = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ;;;#Non-base64".to_string()),
    };

    setup.test_simple_error(invalid_basic);
}

#[test]
fn access_request_wrong_redirection() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token with an incorrect redirection url
    let wrong_redirection = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", "https://wrong.client.example/endpoint"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_redirection);
}

#[test]
fn access_request_invalid_redirection() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token with a redirection url which is not an uri
    let invalid_redirection = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", "\\://"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(invalid_redirection);
}

#[test]
fn access_request_no_code() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token without a code
    let no_code = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(no_code);
}

#[test]
fn access_request_multiple_codes() {
    let mut setup = AccessTokenSetup::private_client();
    let mut urlbody = [
        ("grant_type", "authorization_code"),
        ("code", &setup.authtoken),
        ("redirect_uri", EXAMPLE_REDIRECT_URI),
    ]
    .iter()
    .to_single_value_query();
    urlbody
        .get_mut("code")
        .unwrap()
        .push("AnotherAuthToken".to_string());
    // Trying to get an access token with mutiple codes, even if one is correct
    let multiple_codes = CraftedRequest {
        query: None,
        urlbody: Some(urlbody),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(multiple_codes);
}

#[test]
fn access_request_wrong_grant_type() {
    let mut setup = AccessTokenSetup::private_client();
    // Trying to get an access token without a code
    let wrong_grant_type = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "another_grant_type"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(wrong_grant_type);
}

#[test]
fn private_in_body() {
    let mut setup = AccessTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("client_secret", EXAMPLE_PASSPHRASE),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_success_body_credentials(valid_public);
}

#[test]
fn unwanted_private_in_body_fails() {
    let mut setup = AccessTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("client_secret", EXAMPLE_PASSPHRASE),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    // in body must only succeed if we enabled it explicitely in the flow.
    setup.test_simple_error(valid_public);
}

#[test]
fn private_duplicate_authentication() {
    let mut setup = AccessTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("code", &setup.authtoken),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("client_secret", EXAMPLE_PASSPHRASE),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some("Basic ".to_string() + &setup.basic_authorization),
    };

    setup.test_simple_error(valid_public);
}
