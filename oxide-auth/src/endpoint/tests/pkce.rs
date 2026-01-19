use crate::primitives::authorizer::AuthMap;
use crate::primitives::issuer::TokenMap;
use crate::primitives::generator::RandomGenerator;
use crate::primitives::registrar::{Client, ClientMap, RegisteredUrl};

use crate::code_grant::accesstoken::TokenResponse;
use crate::endpoint::{AuthorizationFlow, AccessTokenFlow, Endpoint};
use crate::frontends::simple::extensions::{AddonList, Extended, Pkce};
use crate::frontends::simple::endpoint::{Generic, Error, Vacant};

use super::{Allow, Body, CraftedResponse, CraftedRequest, Status, TestGenerator, ToSingleValueQuery};
use super::defaults::*;

use serde_json;

struct PkceSetup {
    registrar: ClientMap,
    authorizer: AuthMap<TestGenerator>,
    issuer: TokenMap<RandomGenerator>,
    auth_token: String,
    verifier: String,
    sha256_challenge: String,
}

impl PkceSetup {
    fn new() -> PkceSetup {
        let client = Client::public(
            EXAMPLE_CLIENT_ID,
            RegisteredUrl::Semantic(EXAMPLE_REDIRECT_URI.parse().unwrap()),
            EXAMPLE_SCOPE.parse().unwrap(),
        );

        let mut registrar = ClientMap::new();
        registrar.register_client(client);

        let token = "ExampleAuthorizationToken".to_string();
        let authorizer = AuthMap::new(TestGenerator(token.clone()));
        let issuer = TokenMap::new(RandomGenerator::new(16));

        PkceSetup {
            registrar,
            authorizer,
            issuer,
            auth_token: token,
            // The following are from https://tools.ietf.org/html/rfc7636#page-18
            sha256_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
        }
    }

    fn allowing_endpoint(
        &mut self,
    ) -> impl Endpoint<CraftedRequest, Error = Error<CraftedRequest>> + '_ {
        let pkce_extension = Pkce::required();

        let mut extensions = AddonList::new();
        extensions.push_code(pkce_extension);

        let endpoint = Generic {
            registrar: &self.registrar,
            authorizer: &mut self.authorizer,
            issuer: &mut self.issuer,
            scopes: Vacant,
            solicitor: Allow(EXAMPLE_OWNER_ID.to_string()),
            response: Vacant,
        };

        Extended::extend_with(endpoint, extensions)
    }

    fn test_correct_access(&mut self, auth_request: CraftedRequest, access_request: CraftedRequest) {
        let mut endpoint = self.allowing_endpoint();

        {
            let mut flow = AuthorizationFlow::prepare(&mut endpoint)
                .unwrap_or_else(|_| panic!("Not violating any requirements on authorization flow."));
            let response = flow
                .execute(auth_request)
                .expect("Expected no flow execution error");
            Self::assert_nonerror_redirect(response);
        }

        {
            let mut flow = AccessTokenFlow::prepare(&mut endpoint)
                .unwrap_or_else(|_| panic!("Not violating any requirements on authorization flow."));
            let response = flow
                .execute(access_request)
                .expect("Expected no flow execution error");
            assert_eq!(response.status, Status::Ok, "Expected access token in response");
            assert!(response.www_authenticate.is_none());

            let body = Self::json_response(response.body);
            assert!(body.error.is_none());
        }
    }

    fn test_failed_verification(
        &mut self, auth_request: CraftedRequest, access_request: CraftedRequest,
    ) {
        let mut endpoint = self.allowing_endpoint();

        {
            let mut flow = AuthorizationFlow::prepare(&mut endpoint)
                .unwrap_or_else(|_| panic!("Not violating any requirements on authorization flow."));
            let response = flow
                .execute(auth_request)
                .expect("Expected no flow execution error");
            Self::assert_nonerror_redirect(response);
        }

        {
            let mut flow = AccessTokenFlow::prepare(&mut endpoint)
                .unwrap_or_else(|_| panic!("Not violating any requirements on authorization flow."));
            let response = flow
                .execute(access_request)
                .expect("Expected no flow execution error");
            assert_eq!(response.status, Status::BadRequest, "Expected failed request");
            assert!(response.www_authenticate.is_none());

            let body = Self::json_response(response.body);
            // https://tools.ietf.org/html/rfc7636#section-4.6
            assert_eq!(body.error, Some("invalid_request".to_owned()));
        }
    }

    fn assert_nonerror_redirect(response: CraftedResponse) {
        assert_eq!(response.status, Status::Redirect, "Expected redirect to client");
        assert!(!response.location.unwrap().as_str().contains("error"));
    }

    fn json_response(body: Option<Body>) -> TokenResponse {
        let body = match body {
            Some(Body::Json(content)) => content,
            other => panic!("Expected json formated credentials, got {:?}", other),
        };

        serde_json::from_str(&body).expect("Body not json encoded")
    }
}

#[test]
fn pkce_correct_verifier() {
    let mut setup = PkceSetup::new();

    let correct_authorization = CraftedRequest {
        query: Some(
            [
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &setup.sha256_challenge),
                ("code_challenge_method", "S256"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    let correct_access = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("code", &setup.auth_token),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("code_verifier", &setup.verifier),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_correct_access(correct_authorization, correct_access);
}

#[test]
fn pkce_failed_verifier() {
    let mut setup = PkceSetup::new();

    let correct_authorization = CraftedRequest {
        query: Some(
            [
                ("client_id", EXAMPLE_CLIENT_ID),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("response_type", "code"),
                ("code_challenge", &setup.sha256_challenge),
                ("code_challenge_method", "S256"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        urlbody: None,
        auth: None,
    };

    let correct_access = CraftedRequest {
        query: None,
        urlbody: Some(
            [
                ("grant_type", "authorization_code"),
                ("client_id", EXAMPLE_CLIENT_ID),
                ("code", &setup.auth_token),
                ("redirect_uri", EXAMPLE_REDIRECT_URI),
                ("code_verifier", "Notthecorrectverifier"),
            ]
            .iter()
            .to_single_value_query(),
        ),
        auth: None,
    };

    setup.test_failed_verification(correct_authorization, correct_access);
}
