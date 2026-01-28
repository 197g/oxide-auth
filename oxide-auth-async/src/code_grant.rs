pub mod refresh {
    use oxide_auth::OAuthOpaqueError;
    use oxide_auth::code_grant::refresh::{BearerToken, Error, Input, Output, Refresh, Request};
    use oxide_auth::primitives::{grant::Grant, registrar::RegistrarError};

    pub trait Endpoint {
        /// Authenticate the requesting confidential client.
        fn registrar(&self) -> &(dyn crate::primitives::Registrar + Sync);

        /// Recover and test the provided refresh token then issue new tokens.
        fn issuer(&mut self) -> &mut (dyn crate::primitives::Issuer + Send);
    }

    pub async fn refresh(
        handler: &mut (dyn Endpoint + Send + Sync), request: &(dyn Request + Sync),
    ) -> Result<BearerToken, Error> {
        enum Requested {
            None,
            Refresh { token: String, grant: Box<Grant> },
            RecoverRefresh { token: String },
            Authenticate { client: String, pass: Option<Vec<u8>> },
        }
        let mut refresh = Refresh::new(request);
        let mut requested = Requested::None;
        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Refresh { token, grant } => {
                    let refreshed = handler
                        .issuer()
                        .refresh(&token, *grant)
                        .await
                        .map_err(|OAuthOpaqueError| Error::Primitive)?;
                    Input::Refreshed(refreshed)
                }
                Requested::RecoverRefresh { token } => {
                    let recovered = handler
                        .issuer()
                        .recover_refresh(&token)
                        .await
                        .map_err(|OAuthOpaqueError| Error::Primitive)?;
                    Input::Recovered {
                        scope: request.scope(),
                        grant: recovered.map(Box::new),
                    }
                }
                Requested::Authenticate { client, pass } => {
                    handler
                        .registrar()
                        .check(&client, pass.as_deref())
                        .await
                        .map_err(|err| match err {
                            RegistrarError::PrimitiveError => Error::Primitive,
                            RegistrarError::Unspecified => Error::unauthorized("basic"),
                        })?;
                    Input::Authenticated {
                        scope: request.scope(),
                    }
                }
            };

            requested = match refresh.advance(input) {
                Output::Err(error) => return Err(error),
                Output::Ok(token) => return Ok(token),
                Output::Refresh { token, grant } => Requested::Refresh {
                    token: token.to_string(),
                    grant,
                },
                Output::RecoverRefresh { token } => Requested::RecoverRefresh {
                    token: token.to_string(),
                },
                Output::Unauthenticated { client, pass } => Requested::Authenticate {
                    client: client.to_string(),
                    pass: pass.map(|p| p.to_vec()),
                },
            };
        }
    }
}

pub mod resource {
    use oxide_auth::code_grant::resource::{Error, Input, Output, Request, Resource};
    use oxide_auth::primitives::grant::Grant;
    use oxide_auth::primitives::scope::Scope;

    pub trait Endpoint {
        /// The list of possible scopes required by the resource endpoint.
        fn scopes(&mut self) -> &[Scope];

        /// Recover and test the provided refresh token then issue new tokens.
        fn issuer(&mut self) -> &mut (dyn crate::primitives::Issuer + Send);
    }

    pub async fn protect(
        handler: &mut (dyn Endpoint + Send + Sync), req: &(dyn Request + Sync),
    ) -> Result<Grant, Error> {
        enum Requested {
            None,
            Request,
            Scopes,
            Grant(String),
        }

        let mut resource = Resource::new();
        let mut requested = Requested::None;
        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Request => Input::Request { request: req },
                Requested::Scopes => Input::Scopes(handler.scopes()),
                Requested::Grant(token) => {
                    let grant = handler
                        .issuer()
                        .recover_token(&token)
                        .await
                        .map_err(|_| Error::PrimitiveError)?;
                    Input::Recovered(grant)
                }
            };

            requested = match resource.advance(input) {
                Output::Err(error) => return Err(error),
                Output::Ok(grant) => return Ok(*grant),
                Output::GetRequest => Requested::Request,
                Output::DetermineScopes => Requested::Scopes,
                Output::Recover { token } => Requested::Grant(token.to_string()),
            };
        }
    }
}

pub mod client_credentials {
    use std::borrow::Cow;

    use async_trait::async_trait;
    use chrono::{Utc, Duration};
    use oxide_auth::{
        OAuthOpaqueError,
        code_grant::{
            accesstoken::{BearerToken, PrimitiveError},
            client_credentials::{ClientCredentials, Error, Input, Output, Request as TokenRequest},
        },
        endpoint::{PreGrant, Scope, Solicitation},
        primitives::{
            grant::{Extensions, Grant},
            prelude::ClientUrl,
            registrar::{BoundClient, RegistrarError},
        },
    };

    #[async_trait]
    pub trait Extension {
        /// Inspect the request and extension data to produce extension data.
        ///
        /// The input data comes from the extension data produced in the handling of the
        /// authorization code request.
        async fn extend(
            &mut self, request: &(dyn TokenRequest + Sync),
        ) -> std::result::Result<Extensions, ()>;
    }

    #[async_trait]
    impl Extension for () {
        async fn extend(
            &mut self, _: &(dyn TokenRequest + Sync),
        ) -> std::result::Result<Extensions, ()> {
            Ok(Extensions::new())
        }
    }

    pub trait Endpoint {
        /// Get the client corresponding to some id.
        fn registrar(&self) -> &(dyn crate::primitives::Registrar + Sync);

        /// Get the authorizer from which we can recover the authorization.
        fn authorizer(&mut self) -> &mut (dyn crate::primitives::Authorizer + Send);

        /// Return the issuer instance to create the access token.
        fn issuer(&mut self) -> &mut (dyn crate::primitives::Issuer + Send);

        /// The system of used extension, extending responses.
        ///
        /// It is possible to use `&mut ()`.
        fn extension(&mut self) -> &mut (dyn Extension + Send);
    }

    /// Represents a valid, currently pending client credentials not bound to an owner.
    ///
    /// This will be passed along to the solicitor to obtain the owner ID, and then
    /// a token will be issued. Since this is the client credentials flow, a pending
    /// response is considered an internal error.
    // Don't ever implement `Clone` here. It's to make it very
    // hard for the user to accidentally respond to a request in two conflicting ways. This has
    // potential security impact if it could be both denied and authorized.
    pub struct Pending {
        pre_grant: PreGrant,
        extensions: Extensions,
    }

    impl Pending {
        /// Reference this pending state as a solicitation.
        pub fn as_solicitation(&self) -> Solicitation<'_> {
            Solicitation::new(&self.pre_grant)
        }

        /// Inform the backend about consent from a resource owner.
        ///
        /// Use negotiated parameters to authorize a client for an owner. The endpoint SHOULD be the
        /// same endpoint as was used to create the pending request.
        pub async fn issue(
            self, handler: &mut (dyn Endpoint + Send), owner_id: String, allow_refresh_token: bool,
        ) -> Result<BearerToken, Error> {
            let pre_grant = self.pre_grant.clone();

            let mut token = handler
                .issuer()
                .issue(Grant {
                    owner_id,
                    client_id: pre_grant.client_id,
                    redirect_uri: pre_grant.redirect_uri.into_url(),
                    scope: pre_grant.scope.clone(),
                    until: Utc::now() + Duration::minutes(10),
                    extensions: self.extensions,
                })
                .await
                .map_err(|OAuthOpaqueError| Error::Primitive(Box::new(PrimitiveError::empty())))?;

            if !allow_refresh_token {
                token.refresh = None;
            }

            Ok(token.convert_bearer_token(self.pre_grant))
        }
    }

    pub async fn client_credentials(
        handler: &mut (dyn Endpoint + Send + Sync), request: &(dyn TokenRequest + Sync),
    ) -> Result<Pending, Error> {
        enum Requested {
            None,
            Authenticate {
                client: String,
                passdata: Vec<u8>,
            },
            Bind {
                client_id: String,
            },
            Extend,
            Negotiate {
                bound_client: BoundClient<'static>,
                scope: Option<Scope>,
            },
        }

        let mut client_credentials = ClientCredentials::new(request);
        let mut requested = Requested::None;

        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Authenticate { client, passdata } => {
                    handler
                        .registrar()
                        .check(&client, Some(passdata.as_slice()))
                        .await
                        .map_err(|err| match err {
                            RegistrarError::Unspecified => Error::unauthorized("basic"),
                            RegistrarError::PrimitiveError => {
                                Error::Primitive(Box::new(PrimitiveError {
                                    grant: None,
                                    extensions: None,
                                }))
                            }
                        })?;
                    Input::Authenticated
                }
                Requested::Bind { client_id } => {
                    let client_url = ClientUrl {
                        client_id: Cow::Owned(client_id),
                        redirect_uri: None,
                    };
                    let bound_client = match handler.registrar().bound_redirect(client_url).await {
                        Err(RegistrarError::Unspecified) => return Err(Error::Ignore),
                        Err(RegistrarError::PrimitiveError) => {
                            return Err(Error::Primitive(Box::new(PrimitiveError {
                                grant: None,
                                extensions: None,
                            })));
                        }
                        Ok(pre_grant) => pre_grant,
                    };
                    Input::Bound { bound_client }
                }
                Requested::Extend => {
                    let extensions = handler
                        .extension()
                        .extend(request)
                        .await
                        .map_err(|_| Error::invalid())?;
                    Input::Extended { extensions }
                }
                Requested::Negotiate { bound_client, scope } => {
                    let pre_grant = handler
                        .registrar()
                        .negotiate(bound_client.clone(), scope.clone())
                        .await
                        .map_err(|err| match err {
                            RegistrarError::PrimitiveError => {
                                Error::Primitive(Box::new(PrimitiveError {
                                    grant: None,
                                    extensions: None,
                                }))
                            }
                            RegistrarError::Unspecified => Error::Ignore,
                        })?;
                    Input::Negotiated { pre_grant }
                }
            };

            requested = match client_credentials.advance(input) {
                Output::Authenticate { client, passdata } => Requested::Authenticate {
                    client: client.to_owned(),
                    passdata: passdata.to_vec(),
                },
                Output::Binding { client_id } => Requested::Bind {
                    client_id: client_id.to_owned(),
                },
                Output::Extend => Requested::Extend,
                Output::Negotiate { bound_client, scope } => Requested::Negotiate {
                    bound_client: bound_client.clone(),
                    scope,
                },
                Output::Ok {
                    pre_grant,
                    extensions,
                } => {
                    return Ok(Pending {
                        pre_grant: pre_grant.clone(),
                        extensions: extensions.clone(),
                    })
                }
                Output::Err(e) => return Err(*e),
            };
        }
    }
}

pub mod access_token {
    use async_trait::async_trait;
    use oxide_auth::{
        code_grant::accesstoken::{
            AccessToken, BearerToken, Error, Input, Output, PrimitiveError, Request as TokenRequest,
        },
        primitives::{
            grant::{Extensions, Grant},
            registrar::RegistrarError,
        },
    };
    // use crate::endpoint::access_token::WrappedRequest;

    #[async_trait]
    pub trait Extension {
        /// Inspect the request and extension data to produce extension data.
        ///
        /// The input data comes from the extension data produced in the handling of the
        /// authorization code request.
        async fn extend(
            &mut self, request: &(dyn TokenRequest + Sync), data: Extensions,
        ) -> std::result::Result<Extensions, ()>;
    }

    #[async_trait]
    impl Extension for () {
        async fn extend(
            &mut self, _: &(dyn TokenRequest + Sync), _: Extensions,
        ) -> std::result::Result<Extensions, ()> {
            Ok(Extensions::new())
        }
    }

    pub trait Endpoint {
        /// Get the client corresponding to some id.
        fn registrar(&self) -> &(dyn crate::primitives::Registrar + Sync);

        /// Get the authorizer from which we can recover the authorization.
        fn authorizer(&mut self) -> &mut (dyn crate::primitives::Authorizer + Send);

        /// Return the issuer instance to create the access token.
        fn issuer(&mut self) -> &mut (dyn crate::primitives::Issuer + Send);

        /// The system of used extension, extending responses.
        ///
        /// It is possible to use `&mut ()`.
        fn extension(&mut self) -> &mut (dyn Extension + Send);
    }

    pub async fn access_token(
        handler: &mut (dyn Endpoint + Send + Sync), request: &(dyn TokenRequest + Sync),
    ) -> Result<BearerToken, Error> {
        enum Requested<'a> {
            None,
            Authenticate {
                client: &'a str,
                passdata: Option<&'a [u8]>,
            },
            Recover(&'a str),
            Extend {
                extensions: &'a mut Extensions,
            },
            Issue {
                grant: &'a Grant,
            },
        }

        let mut access_token = AccessToken::new(request);
        let mut requested = Requested::None;

        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Authenticate { client, passdata } => {
                    handler
                        .registrar()
                        .check(client, passdata)
                        .await
                        .map_err(|err| match err {
                            RegistrarError::Unspecified => Error::unauthorized("basic"),
                            RegistrarError::PrimitiveError => {
                                Error::Primitive(Box::new(PrimitiveError {
                                    grant: None,
                                    extensions: None,
                                }))
                            }
                        })?;
                    Input::Authenticated
                }
                Requested::Recover(code) => {
                    let opt_grant = handler.authorizer().extract(code).await.map_err(|_| {
                        Error::Primitive(Box::new(PrimitiveError {
                            grant: None,
                            extensions: None,
                        }))
                    })?;
                    Input::Recovered(opt_grant.map(Box::new))
                }
                Requested::Extend { extensions } => {
                    let access_extensions = handler
                        .extension()
                        .extend(request, extensions.clone())
                        .await
                        .map_err(|_| Error::invalid())?;

                    Input::Extended { access_extensions }
                }
                Requested::Issue { grant } => {
                    let token = handler.issuer().issue(grant.clone()).await.map_err(|_| {
                        Error::Primitive(Box::new(PrimitiveError {
                            // FIXME: endpoint should get and handle these.
                            grant: None,
                            extensions: None,
                        }))
                    })?;
                    Input::Issued(token)
                }
            };

            requested = match access_token.advance(input) {
                Output::Authenticate { client, passdata } => {
                    Requested::Authenticate { client, passdata }
                }
                Output::Recover { code } => Requested::Recover(code),
                Output::Extend { extensions, .. } => Requested::Extend { extensions },
                Output::Issue { grant } => Requested::Issue { grant },
                Output::Ok(token) => return Ok(token),
                Output::Err(e) => return Err(*e),
            };
        }
    }
}

pub mod authorization {
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use oxide_auth::{
        OAuthOpaqueError,
        code_grant::{
            authorization::{Authorization, Error, ErrorUrl, Input, Output, Request},
            error::{AuthorizationError, AuthorizationErrorType},
        },
        endpoint::{PreGrant, Scope, Solicitation},
        primitives::{
            grant::{Extensions, Grant},
            prelude::ClientUrl,
            registrar::{BoundClient, ExactUrl, RegistrarError},
        },
    };
    use url::Url;

    use std::borrow::Cow;

    /// A system of addons provided additional data.
    ///
    /// An endpoint not having any extension may use `&mut ()` as the result of system.
    #[async_trait]
    pub trait Extension {
        /// Inspect the request to produce extension data.
        async fn extend(
            &mut self, request: &(dyn Request + Sync),
        ) -> std::result::Result<Extensions, ()>;
    }

    #[async_trait]
    impl Extension for () {
        async fn extend(&mut self, _: &(dyn Request + Sync)) -> std::result::Result<Extensions, ()> {
            Ok(Extensions::new())
        }
    }

    /// Required functionality to respond to authorization code requests.
    ///
    /// Each method will only be invoked exactly once when processing a correct and authorized request,
    /// and potentially less than once when the request is faulty.  These methods should be implemented
    /// by internally using `primitives`, as it is implemented in the `frontend` module.
    pub trait Endpoint {
        /// 'Bind' a client and redirect uri from a request to internally approved parameters.
        fn registrar(&self) -> &(dyn crate::primitives::Registrar + Sync);

        /// Generate an authorization code for a given grant.
        fn authorizer(&mut self) -> &mut (dyn crate::primitives::Authorizer + Send);

        /// An extension implementation of this endpoint.
        ///
        /// It is possible to use `&mut ()`.
        fn extension(&mut self) -> &mut (dyn Extension + Send);
    }

    /// Represents a valid, currently pending authorization request not bound to an owner. The frontend
    /// can signal a reponse using this object.
    #[derive(Clone)]
    pub struct Pending {
        pre_grant: PreGrant,
        state: Option<String>,
        extensions: Extensions,
    }

    impl Pending {
        /// Reference this pending state as a solicitation.
        pub fn as_solicitation(&self) -> Solicitation<'_> {
            let base = Solicitation::new(&self.pre_grant);
            match self.state {
                None => base,
                Some(ref state) => base.with_state(state),
            }
        }

        /// Denies the request, which redirects to the client for which the request originated.
        pub fn deny(self) -> Result<Url, Error> {
            let url = self.pre_grant.redirect_uri;
            let mut error = AuthorizationError::default();
            error.set_type(AuthorizationErrorType::AccessDenied);
            let error = ErrorUrl::new(url.into(), self.state.as_deref(), error);
            Err(Error::Redirect(error))
        }

        /// Inform the backend about consent from a resource owner.
        ///
        /// Use negotiated parameters to authorize a client for an owner. The endpoint SHOULD be the
        /// same endpoint as was used to create the pending request.
        pub async fn authorize(
            self, handler: &mut (dyn Endpoint + Send), owner_id: Cow<'_, str>,
        ) -> Result<Url, Error> {
            let mut url = self.pre_grant.redirect_uri.to_url();

            let grant = handler
                .authorizer()
                .authorize(Grant {
                    owner_id: owner_id.into_owned(),
                    client_id: self.pre_grant.client_id,
                    redirect_uri: self.pre_grant.redirect_uri.into(),
                    scope: self.pre_grant.scope,
                    until: Utc::now() + Duration::minutes(10),
                    extensions: self.extensions,
                })
                .await
                .map_err(|OAuthOpaqueError| Error::PrimitiveError)?;

            url.query_pairs_mut()
                .append_pair("code", grant.as_str())
                .extend_pairs(self.state.map(|v| ("state", v)))
                .finish();
            Ok(url)
        }

        /// Retrieve a reference to the negotiated parameters (e.g. scope). These should be displayed
        /// to the resource owner when asking for his authorization.
        pub fn pre_grant(&self) -> &PreGrant {
            &self.pre_grant
        }
    }

    /// Retrieve allowed scope and redirect url from the registrar.
    ///
    /// Checks the validity of any given input as the registrar instance communicates the registrated
    /// parameters. The registrar can also set or override the requested (default) scope of the client.
    /// This will result in a tuple of negotiated parameters which can be used further to authorize
    /// the client by the owner or, in case of errors, in an action to be taken.
    /// If the client is not registered, the request will otherwise be ignored, if the request has
    /// some other syntactical error, the client is contacted at its redirect url with an error
    /// response.
    pub async fn authorization_code(
        handler: &mut (dyn Endpoint + Send + Sync), request: &(dyn Request + Sync),
    ) -> Result<Pending, Error> {
        enum Requested {
            None,
            Bind {
                client_id: String,
                redirect_uri: Option<ExactUrl>,
            },
            Extend,
            Negotiate {
                client_id: String,
                redirect_uri: Url,
                scope: Option<Scope>,
            },
        }

        let mut authorization = Authorization::new(request);
        let mut requested = Requested::None;
        let mut the_redirect_uri = None;

        loop {
            let input = match requested {
                Requested::None => Input::None,
                Requested::Bind {
                    client_id,
                    redirect_uri,
                } => {
                    let client_url = ClientUrl {
                        client_id: Cow::Owned(client_id),
                        redirect_uri: redirect_uri.map(Cow::Owned),
                    };
                    let bound_client = match handler.registrar().bound_redirect(client_url).await {
                        Err(RegistrarError::Unspecified) => return Err(Error::Ignore),
                        Err(RegistrarError::PrimitiveError) => return Err(Error::PrimitiveError),
                        Ok(pre_grant) => pre_grant,
                    };
                    the_redirect_uri = Some(bound_client.redirect_uri.clone().into_owned());
                    Input::Bound {
                        request,
                        bound_client,
                    }
                }
                Requested::Extend => {
                    let grant_extension = match handler.extension().extend(request).await {
                        Ok(extension_data) => extension_data,
                        Err(()) => {
                            let prepared_error = ErrorUrl::with_request(
                                request,
                                the_redirect_uri.unwrap().into_url(),
                                AuthorizationErrorType::InvalidRequest,
                            );
                            return Err(Error::Redirect(prepared_error));
                        }
                    };
                    Input::Extended(grant_extension)
                }
                Requested::Negotiate {
                    client_id,
                    redirect_uri,
                    scope,
                } => {
                    let bound_client = BoundClient {
                        client_id: Cow::Owned(client_id),
                        redirect_uri: Cow::Owned(redirect_uri.clone().into()),
                    };
                    let pre_grant = handler.registrar().negotiate(bound_client, scope).await.map_err(
                        |err| match err {
                            RegistrarError::PrimitiveError => Error::PrimitiveError,
                            RegistrarError::Unspecified => {
                                let prepared_error = ErrorUrl::with_request(
                                    request,
                                    redirect_uri,
                                    AuthorizationErrorType::InvalidScope,
                                );
                                Error::Redirect(prepared_error)
                            }
                        },
                    )?;
                    Input::Negotiated {
                        pre_grant,
                        state: request.state().map(|s| s.into_owned()),
                    }
                }
            };

            requested = match authorization.advance(input) {
                Output::Bind {
                    client_id,
                    redirect_uri,
                } => Requested::Bind {
                    client_id,
                    redirect_uri,
                },
                Output::Extend => Requested::Extend,
                Output::Negotiate { bound_client, scope } => Requested::Negotiate {
                    client_id: bound_client.client_id.clone().into_owned(),
                    redirect_uri: bound_client.redirect_uri.to_url(),
                    scope,
                },
                Output::Ok {
                    pre_grant,
                    state,
                    extensions,
                } => {
                    return Ok(Pending {
                        pre_grant,
                        state,
                        extensions,
                    })
                }
                Output::Err(e) => return Err(e),
            };
        }
    }
}
