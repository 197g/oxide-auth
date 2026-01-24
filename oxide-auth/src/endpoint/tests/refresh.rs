use crate::primitives::issuer::{Issuer, IssuedToken, RefreshedToken, TokenMap, TokenType};
use crate::primitives::generator::RandomGenerator;
use crate::primitives::grant::{Grant, Extensions};
use crate::primitives::registrar::{Client, ClientMap, RegisteredUrl};

use std::collections::HashMap;

use base64::{self, Engine};
use base64::engine::general_purpose::STANDARD;
use chrono::{Utc, Duration};
use serde_json;

use super::{Body, CraftedRequest, CraftedResponse, Status, ToSingleValueQuery};
use super::defaults::*;
use crate::code_grant::accesstoken::TokenResponse;
use crate::frontends::simple::endpoint::{refresh_flow, resource_flow};

struct RefreshTokenSetup {
    registrar: ClientMap,
    issuer: TokenMap<RandomGenerator>,
    /// The original issued token. Unused atm.
    #[allow(unused)]
    issued: IssuedToken,
    /// The extract refresh token.
    refresh_token: String,
    /// The combined authorization header.
    basic_authorization: String,
}

impl RefreshTokenSetup {
    fn private_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let client = Client::confidential(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
            EXAMPLE_PASSPHRASE.as_bytes(),
        );

        let grant = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        registrar.register_client(client);
        let issued = issuer.issue(grant).unwrap();
        assert!(issued.refreshable());
        let refresh_token = issued.refresh.clone().unwrap();

        let basic_authorization =
            STANDARD.encode(format!("{}:{}", EXAMPLE_CLIENT_ID, EXAMPLE_PASSPHRASE));
        let basic_authorization = format!("Basic {}", basic_authorization);

        RefreshTokenSetup {
            registrar,
            issuer,
            issued,
            refresh_token,
            basic_authorization,
        }
    }

    fn public_client() -> Self {
        let mut registrar = ClientMap::new();
        let mut issuer = TokenMap::new(RandomGenerator::new(16));

        let client = Client::public(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Exact(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
        );

        let grant = Grant {
            client_id: EXAMPLE_CLIENT_ID.to_string(),
            owner_id: EXAMPLE_OWNER_ID.to_string(),
            redirect_uri: EXAMPLE_REDIRECT_URI.parse().unwrap(),
            scope: EXAMPLE_SCOPE.parse().unwrap(),
            until: Utc::now() + Duration::hours(1),
            extensions: Extensions::new(),
        };

        registrar.register_client(client);
        let issued = issuer.issue(grant).unwrap();
        assert!(issued.refreshable());
        let refresh_token = issued.refresh.clone().unwrap();

        let basic_authorization = "DO_NOT_USE".into();

        RefreshTokenSetup {
            registrar,
            issuer,
            issued,
            refresh_token,
            basic_authorization,
        }
    }

    fn assert_success(&mut self, request: CraftedRequest) -> RefreshedToken {
        let response = refresh_flow(&self.registrar, &mut self.issuer)
            .execute(request)
            .expect("Expected non-failed reponse");
        assert_eq!(response.status, Status::Ok);
        let body = match response.body {
            Some(Body::Json(body)) => body,
            _ => panic!("Expect json body"),
        };
        let body: TokenResponse = serde_json::from_str(&body).expect("Expected valid json body");
        let duration = body.expires_in.unwrap();
        RefreshedToken {
            token: body.access_token.expect("Expected a token"),
            refresh: body.refresh_token,
            until: Utc::now() + Duration::seconds(duration),
            token_type: TokenType::Bearer,
        }
    }

    /// Check that the request failed with 400/401.
    fn assert_unauthenticated(&mut self, request: CraftedRequest) {
        let response = refresh_flow(&self.registrar, &mut self.issuer)
            .execute(request)
            .expect("Expected non-failed reponse");
        let body = self.assert_json_body(&response);
        if response.status == Status::Unauthorized {
            assert!(response.www_authenticate.is_some());
        }

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_client"));
        self.assert_only_error(body);
    }

    /// The request as malformed and not processed any further.
    fn assert_invalid(&mut self, request: CraftedRequest) {
        let response = refresh_flow(&self.registrar, &mut self.issuer)
            .execute(request)
            .expect("Expected non-failed reponse");
        let body = self.assert_json_body(&response);
        assert_eq!(response.status, Status::BadRequest);

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_request"));
        self.assert_only_error(body);
    }

    /// Client authorizes ok but does not match the grant.
    fn assert_invalid_grant(&mut self, request: CraftedRequest) {
        let response = refresh_flow(&self.registrar, &mut self.issuer)
            .execute(request)
            .expect("Expected non-failed reponse");
        let body = self.assert_json_body(&response);
        assert_eq!(response.status, Status::BadRequest);

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_grant"));
        self.assert_only_error(body);
    }

    /// Check that the request failed with 401.
    fn assert_wrong_authentication(&mut self, request: CraftedRequest) {
        let response = refresh_flow(&self.registrar, &mut self.issuer)
            .execute(request)
            .expect("Expected non-failed reponse");
        assert_eq!(response.status, Status::Unauthorized);
        assert!(response.www_authenticate.is_some());

        let body = self.assert_json_body(&response);

        assert_eq!(body.get("error").map(String::as_str), Some("invalid_client"));
        self.assert_only_error(body);
    }

    fn assert_json_body(&mut self, response: &CraftedResponse) -> HashMap<String, String> {
        let body = match &response.body {
            Some(Body::Json(body)) => body,
            _ => panic!("Expect json body"),
        };
        let body: HashMap<String, String> =
            serde_json::from_str(body).expect("Expected valid json body");
        body
    }

    fn assert_only_error(&mut self, mut body: HashMap<String, String>) {
        let _ = body.remove("error");
        let _ = body.remove("error_description");
        let _ = body.remove("error_uri");
        assert!(body.is_empty());
    }

    fn access_resource(&mut self, token: String) {
        let request = CraftedRequest {
            query: None,
            urlbody: None,
            auth: Some(format!("Bearer {}", token)),
        };

        resource_flow(&mut self.issuer, &[EXAMPLE_SCOPE.parse().unwrap()])
            .execute(request)
            .expect("Expected access allowed");
    }
}

#[test]
fn access_valid_public() {
    let mut setup = RefreshTokenSetup::public_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.refresh_token),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    let new_token = setup.assert_success(valid_public);
    setup.access_resource(new_token.token);
}

#[test]
fn access_valid_private() {
    let mut setup = RefreshTokenSetup::private_client();

    let valid_private = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.refresh_token),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone()),
    };

    let new_token = setup.assert_success(valid_private);
    setup.access_resource(new_token.token);
}

#[test]
fn public_private_invalid_grant() {
    let mut setup = RefreshTokenSetup::public_client();
    let client = Client::confidential(
        "PrivateClient",
        RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
        EXAMPLE_SCOPE.parse().unwrap(),
        EXAMPLE_PASSPHRASE.as_bytes(),
    );
    setup.registrar.register_client(client);

    let basic_authorization = STANDARD.encode(format!("{}:{}", "PrivateClient", EXAMPLE_PASSPHRASE));
    let basic_authorization = format!("Basic {}", basic_authorization);

    let authenticated = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.refresh_token),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(basic_authorization),
    };

    setup.assert_invalid_grant(authenticated);
}

#[test]
fn private_wrong_client_fails() {
    let mut setup = RefreshTokenSetup::private_client();

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.refresh_token),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.assert_unauthenticated(valid_public);

    let wrong_authentication = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.refresh_token),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(format!("Basic {}", STANDARD.encode("Wrong:AndWrong"))),
    };

    setup.assert_wrong_authentication(wrong_authentication);
}

#[test]
fn invalid_request() {
    let mut setup = RefreshTokenSetup::private_client();

    let bad_base64 = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.refresh_token),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone() + "=/"),
    };

    setup.assert_invalid(bad_base64);

    let no_token = CraftedRequest {
        query: None,
        urlbody: Some([("grant_type", "refresh_token")].iter().to_single_value_query()),
        auth: Some(setup.basic_authorization.clone()),
    };

    setup.assert_invalid(no_token);
}

#[test]
fn regression_case_insensitive_basic() {
    let mut setup = RefreshTokenSetup::private_client();

    setup.basic_authorization.replace_range(..6, "basic ");
    let case_changed_authorization = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", &setup.refresh_token),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone()),
    };

    setup.assert_success(case_changed_authorization);
}

#[test]
fn public_invalid_token() {
    const WRONG_REFRESH_TOKEN: &str = "not_the_issued_token";
    let mut setup = RefreshTokenSetup::public_client();
    assert_ne!(setup.refresh_token, WRONG_REFRESH_TOKEN);

    let valid_public = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", WRONG_REFRESH_TOKEN),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.assert_invalid_grant(valid_public);
}

#[test]
fn private_invalid_token() {
    const WRONG_REFRESH_TOKEN: &str = "not_the_issued_token";
    let mut setup = RefreshTokenSetup::private_client();
    assert_ne!(setup.refresh_token, WRONG_REFRESH_TOKEN);

    let valid_private = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "refresh_token"),
                ("refresh_token", WRONG_REFRESH_TOKEN),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: Some(setup.basic_authorization.clone()),
    };

    setup.assert_invalid_grant(valid_private);
}
