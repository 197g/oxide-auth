use std::collections::HashMap;

use crate::primitives::authorizer::AuthMap;
use crate::primitives::registrar::{Client, ClientMap, RegisteredUrl};

use crate::endpoint::{OwnerSolicitor};

use crate::frontends::simple::endpoint::authorization_flow;

use super::{CraftedRequest, Status, TestGenerator, ToSingleValueQuery};
use super::{Allow, Deny};
use super::defaults::*;

struct AuthorizationSetup {
    registrar: ClientMap,
    authorizer: AuthMap<TestGenerator>,
}

impl AuthorizationSetup {
    fn new() -> AuthorizationSetup {
        let mut registrar = ClientMap::new();
        let authorizer = AuthMap::new(TestGenerator("AuthToken".to_string()));

        let client = Client::confidential(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes(),
        );
        registrar.register_client(client);
        AuthorizationSetup {
            registrar,
            authorizer,
        }
    }

    fn test_success(&mut self, request: CraftedRequest) {
        let response = authorization_flow(
            &self.registrar,
            &mut self.authorizer,
            &mut Allow(EXAMPLE_OWNER_ID.to_string()),
        )
        .execute(request)
        .expect("Should not error");

        assert_eq!(response.status, Status::Redirect);

        match response.location {
            Some(ref url) if !url.as_str().contains("error") => (),
            other => panic!("Expected successful redirect: {:?}", other),
        }
    }

    fn test_silent_error(&mut self, request: CraftedRequest) {
        match authorization_flow(
            &self.registrar,
            &mut self.authorizer,
            &mut Allow(EXAMPLE_OWNER_ID.to_string()),
        )
        .execute(request)
        {
            Ok(ref resp) if resp.location.is_some() => panic!("Redirect without client id {:?}", resp),
            Ok(resp) => panic!("Response without client id {:?}", resp),
            Err(_) => (),
        }
    }

    fn test_error_redirect<P>(&mut self, request: CraftedRequest, mut pagehandler: P)
    where
        P: OwnerSolicitor<CraftedRequest>,
    {
        let response =
            authorization_flow(&self.registrar, &mut self.authorizer, &mut pagehandler).execute(request);

        let response = match response {
            Err(resp) => panic!("Expected redirect with error set: {:?}", resp),
            Ok(resp) => resp,
        };

        match response.location {
            Some(ref url) if url.query_pairs().collect::<HashMap<_, _>>().contains_key("error") => {}
            other => panic!("Expected location with error set description: {:?}", other),
        }
    }
}

#[test]
fn auth_success() {
    let success = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_success(success);
}

#[test]
fn auth_request_silent_missing_client() {
    let missing_client = CraftedRequest {
        query: Some([("response_type", "code")].iter().to_single_value_query()),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(missing_client);
}

#[test]
fn auth_request_silent_unknown_client() {
    // The client_id is not registered
    let unknown_client = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", "SomeOtherClient"),
                ("redirect_uri", "https://wrong.client.example/endpoint"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(unknown_client);
}

#[test]
fn auth_request_silent_mismatching_redirect() {
    // The redirect_uri does not match
    let mismatching_redirect = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", "https://wrong.client.example/endpoint"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(mismatching_redirect);
}

#[test]
fn auth_request_silent_mismatching_literal_redirect() {
    // The redirect_uri does not match if stringly matched.
    let mut setup = AuthorizationSetup::new();
    const UNIQUE_CLIENT: &str = "client_auth_request_silent_mismatching_literal_redirect";
    const REGISTERED_URL: &str = "https://right.client.example/endpoint";
    const TRIED_URL: &str = "https://right.client.example/endpoint/";

    let client = Client::confidential(
        UNIQUE_CLIENT,
        RegisteredUrl::Exact(REGISTERED_URL.parse().unwrap()),
        EXAMPLE_SCOPE.parse().unwrap(),
        EXAMPLE_PASSPHRASE.as_bytes(),
    );
    setup.registrar.register_client(client);

    let mismatching_redirect = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", UNIQUE_CLIENT),
                ("redirect_uri", TRIED_URL),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    setup.test_silent_error(mismatching_redirect);

    let valid_redirect = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", UNIQUE_CLIENT),
                ("redirect_uri", REGISTERED_URL),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    setup.test_success(valid_redirect);
}

#[test]
fn auth_request_silent_invalid_redirect() {
    // The redirect_uri is not an uri ('\' is not allowed to appear in the scheme)
    let invalid_redirect = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", "\\://"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_silent_error(invalid_redirect);
}

#[test]
fn auth_request_error_denied() {
    // Used in conjunction with a denying authorization handler below
    let denied_request = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(denied_request, Deny);
}

#[test]
fn auth_request_error_unsupported_method() {
    // Requesting an authorization token for a method other than code
    let unsupported_method = CraftedRequest {
        query: Some(
            [
                ("response_type", "other_method"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new()
        .test_error_redirect(unsupported_method, Allow(EXAMPLE_OWNER_ID.to_string()));
}

#[test]
fn auth_request_error_malformed_scope() {
    // A scope with malformed formatting
    let malformed_scope = CraftedRequest {
        query: Some(
            [
                ("response_type", "code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("scope", "\"no quotes (0x22) allowed\""),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    AuthorizationSetup::new().test_error_redirect(malformed_scope, Allow(EXAMPLE_OWNER_ID.to_string()));
}
