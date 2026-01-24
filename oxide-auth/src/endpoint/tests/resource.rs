use crate::primitives::issuer::TokenMap;
use crate::primitives::generator::RandomGenerator;
use crate::primitives::grant::{Grant, Extensions};
use crate::primitives::scope::Scope;

use crate::frontends::simple::endpoint::resource_flow;

use chrono::{Utc, Duration};

use super::CraftedRequest;
use super::defaults::*;

struct ResourceSetup {
    issuer: TokenMap<RandomGenerator>,
    authtoken: String,
    wrong_scope_token: String,
    small_scope_token: String,
    resource_scope: [Scope; 1],
}

impl ResourceSetup {
    fn new() -> ResourceSetup {
        use crate::primitives::issuer::Issuer;

        // Ensure that valid tokens are 16 bytes long, so we can craft an invalid one
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let authtoken = issuer
            .issue(Grant {
                client_id: EXAMPLE_CLIENT_ID.to_string(),
                owner_id: EXAMPLE_OWNER_ID.to_string(),
                redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
                scope: "legit needed andmore".parse().unwrap(),
                until: Utc::now() + Duration::hours(1),
                extensions: Extensions::new(),
            })
            .unwrap();

        let wrong_scope_token = issuer
            .issue(Grant {
                client_id: EXAMPLE_CLIENT_ID.to_string(),
                owner_id: EXAMPLE_OWNER_ID.to_string(),
                redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
                scope: "wrong needed".parse().unwrap(),
                until: Utc::now() + Duration::hours(1),
                extensions: Extensions::new(),
            })
            .unwrap();

        let small_scope_token = issuer
            .issue(Grant {
                client_id: EXAMPLE_CLIENT_ID.to_string(),
                owner_id: EXAMPLE_OWNER_ID.to_string(),
                redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
                scope: "legit".parse().unwrap(),
                until: Utc::now() + Duration::hours(1),
                extensions: Extensions::new(),
            })
            .unwrap();

        ResourceSetup {
            issuer,
            authtoken: authtoken.token,
            wrong_scope_token: wrong_scope_token.token,
            small_scope_token: small_scope_token.token,
            resource_scope: ["needed legit".parse().unwrap()],
        }
    }

    fn test_access_success(&mut self, request: CraftedRequest) {
        match resource_flow(&mut self.issuer, &self.resource_scope).execute(request) {
            Ok(_) => (),
            Err(ohno) => panic!("Expected an error instead of {:?}", ohno),
        }
    }

    fn test_access_error(&mut self, request: CraftedRequest) {
        if let Ok(resp) = resource_flow(&mut self.issuer, &self.resource_scope).execute(request) {
            panic!("Expected an error instead of {:?}", resp)
        }
    }
}

#[test]
fn resource_success() {
    let mut setup = ResourceSetup::new();
    let success = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &setup.authtoken),
    };

    setup.test_access_success(success);
}

#[test]
fn resource_casing_success() {
    let mut setup = ResourceSetup::new();
    let success = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("bearer ".to_string() + &setup.authtoken),
    };

    setup.test_access_success(success);

    let success = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("bEArEr ".to_string() + &setup.authtoken),
    };

    setup.test_access_success(success);
}

#[test]
fn resource_no_authorization() {
    // Does not have any authorization
    let no_authorization = CraftedRequest {
        query: None,
        urlbody: None,
        auth: None,
    };

    ResourceSetup::new().test_access_error(no_authorization);
}

#[test]
fn resource_invalid_token() {
    // Does not have any authorization
    let invalid_token = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ThisisnotavalidtokenTooLong".to_string()),
    };

    ResourceSetup::new().test_access_error(invalid_token);
}

#[test]
fn resource_wrong_method() {
    let mut setup = ResourceSetup::new();
    // Not indicating the `Bearer` authorization method
    let wrong_method = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("NotBearer ".to_string() + &setup.authtoken),
    };

    setup.test_access_error(wrong_method);
}

#[test]
fn resource_scope_too_small() {
    let mut setup = ResourceSetup::new();
    // Scope of used token is too small for access
    let scope_too_small = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &setup.small_scope_token),
    };

    setup.test_access_error(scope_too_small);
}

#[test]
fn resource_wrong_scope() {
    let mut setup = ResourceSetup::new();
    // Scope of used token does not match the access
    let wrong_scope = CraftedRequest {
        query: None,
        urlbody: None,
        auth: Some("Bearer ".to_string() + &setup.wrong_scope_token),
    };

    setup.test_access_error(wrong_scope);
}
