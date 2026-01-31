use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, offset::Utc};
use once_cell::sync::Lazy;
use oxide_auth::{
    endpoint::{OAuthError, Scopes, Template},
    primitives::{
        grant::Grant,
        issuer::{IssuedToken, RefreshedToken, TokenType},
        scope::Scope,
        registrar::{
            BoundClient, ClientType, ClientUrl, EncodedClient, PasswordPolicy, PreGrant,
            RegisteredClient, RegistrarError, RegisteredUrl,
        },
    },
};
use oxide_auth_async::{
    endpoint::{Endpoint, OwnerSolicitor},
    primitives::{Authorizer, Issuer, Registrar},
};
use oxide_auth_async_actix::{OAuthRequest, OAuthResponse, WebError};

use std::{sync::Arc, borrow::Cow};
use sqlx::{self, sqlite::SqlitePool, FromRow};
use url::Url;

pub struct DbEndpoint {
    pool: Arc<SqlitePool>,
    solicitor: Option<Box<dyn OwnerSolicitor<OAuthRequest> + Send + Sync>>,
}

#[derive(FromRow)]
pub struct App {
    id: i32,
    uid: String,
    secret: String,
}

impl App {
    fn token(&self) -> String {
        format!("token{}", self.id)
    }
}

static REDIRECT_URI: Lazy<RegisteredUrl> =
    Lazy::new(|| "http://localhost:8021".parse::<Url>().unwrap().into());

static DEFAULT_SCOPES: Lazy<Scope> = Lazy::new(|| "read write".parse::<Scope>().unwrap());

impl DbEndpoint {
    pub async fn create() -> Result<Self> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;

        let mut conn = pool.acquire().await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS apps (
  id INTEGER PRIMARY KEY NOT NULL,
  uid VARCHAR(250) NOT NULL,
  secret VARCHAR(250) NOT NULL
);",
        )
        .execute(&mut conn)
        .await?;
        sqlx::query(
            "INSERT INTO apps (uid, secret)
VALUES (?, ?);",
        )
        .bind("clienta")
        .bind("secreta")
        .execute(&mut conn)
        .await?;

        drop(conn);

        Ok(Self {
            pool: Arc::new(pool),
            solicitor: None,
        })
    }

    pub fn with_solicitor<S>(&self, solicitor: S) -> Self
    where
        S: OwnerSolicitor<OAuthRequest> + Send + Sync + 'static,
    {
        Self {
            pool: self.pool.clone(),
            solicitor: Some(Box::new(solicitor)),
        }
    }

    async fn find_app_by_uid(&self, uid: &str) -> Result<Option<App>> {
        let mut conn = self.pool.acquire().await?;

        let app_opt = sqlx::query_as::<_, App>("SELECT * FROM apps WHERE uid = ?")
            .bind(uid)
            .fetch_optional(&mut conn)
            .await?;

        Ok(app_opt)
    }

    pub async fn find_client_by_id(&self, client_id: &str) -> Result<Option<EncodedClient>> {
        let app_opt = self.find_app_by_uid(client_id).await?;

        Ok(app_opt.map(|app| EncodedClient {
            client_id: app.uid,
            redirect_uri: Lazy::force(&REDIRECT_URI).clone(),
            additional_redirect_uris: Default::default(),
            default_scope: Lazy::force(&DEFAULT_SCOPES).clone(),
            encoded_client: ClientType::Confidential {
                passdata: app.secret.into_bytes(),
            },
        }))
    }
}

impl Endpoint<OAuthRequest> for DbEndpoint {
    type Error = OAuthError;

    fn registrar(&self) -> Option<&(dyn Registrar + Sync)> {
        Some(self)
    }

    fn authorizer_mut(&mut self) -> Option<&mut (dyn Authorizer + Send)> {
        Some(self)
    }

    fn issuer_mut(&mut self) -> Option<&mut (dyn Issuer + Send)> {
        Some(self)
    }

    fn owner_solicitor(&mut self) -> Option<&mut (dyn OwnerSolicitor<OAuthRequest> + Send)> {
        if let Some(solicitor) = self.solicitor.as_deref_mut() {
            Some(solicitor)
        } else {
            None
        }
    }

    fn scopes(&mut self) -> Option<&mut dyn Scopes<OAuthRequest>> {
        None
    }

    fn response(
        &mut self, _request: &mut OAuthRequest, _kind: Template<'_>,
    ) -> Result<OAuthResponse, Self::Error> {
        Ok(Default::default())
    }

    fn error(&mut self, err: OAuthError) -> Self::Error {
        err.into()
    }

    fn web_error(&mut self, _err: WebError) -> Self::Error {
        unreachable!()
    }
}

#[async_trait]
impl Registrar for DbEndpoint {
    async fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = match self.find_client_by_id(&bound.client_id).await {
            Ok(Some(client)) => client,
            _ => return Err(RegistrarError::Unspecified),
        };

        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(client.redirect_uri),
        })
    }

    async fn negotiate<'a>(
        &self, bound: BoundClient<'a>, _scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        let client = match self.find_client_by_id(&bound.client_id).await {
            Ok(Some(client)) => client,
            _ => return Err(RegistrarError::Unspecified),
        };

        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: client.default_scope,
        })
    }

    async fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let client = match self.find_client_by_id(client_id).await {
            Ok(Some(client)) => client,
            _ => return Err(RegistrarError::Unspecified),
        };

        RegisteredClient::new(&client, &CheckSecret).check_authentication(passphrase)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct CheckSecret;

impl PasswordPolicy for CheckSecret {
    fn store(&self, _client_id: &str, _passphrase: &[u8]) -> Vec<u8> {
        unreachable!()
    }

    fn check(&self, _client_id: &str, passphrase: &[u8], stored: &[u8]) -> Result<(), RegistrarError> {
        if stored == passphrase {
            Ok(())
        } else {
            Err(RegistrarError::Unspecified)
        }
    }
}

#[async_trait]
impl Authorizer for DbEndpoint {
    async fn authorize(&mut self, grant: Grant) -> Result<String, ()> {
        let Grant { client_id, .. } = grant;

        let app = match self.find_app_by_uid(&client_id).await {
            Ok(Some(app)) => app,
            _ => return Err(()),
        };

        Ok(app.token())
    }

    async fn extract(&mut self, token: &str) -> Result<Option<Grant>, ()> {
        let id = match token.strip_prefix("token") {
            Some(id) => id,
            None => return Ok(None),
        };

        let app = match self.find_app_by_uid(&id).await {
            Ok(Some(client)) => client,
            _ => return Ok(None),
        };

        Ok(Some(Grant {
            owner_id: app.uid.clone(),
            client_id: app.uid.clone(),
            redirect_uri: Lazy::force(&REDIRECT_URI).clone().into(),
            scope: Lazy::force(&DEFAULT_SCOPES).clone(),
            until: Utc::now() + Duration::minutes(10),
            extensions: Default::default(),
        }))
    }
}

#[async_trait]
impl Issuer for DbEndpoint {
    async fn issue(&mut self, grant: Grant) -> Result<IssuedToken, ()> {
        let Grant { client_id, until, .. } = grant;

        let app = match self.find_app_by_uid(&client_id).await {
            Ok(Some(app)) => app,
            _ => return Err(()),
        };

        Ok(IssuedToken {
            token: format!("token{}", app.id),
            refresh: None,
            until,
            token_type: TokenType::Bearer,
        })
    }

    async fn refresh(&mut self, _refresh: &str, _grant: Grant) -> Result<RefreshedToken, ()> {
        Err(())
    }

    async fn recover_token(&mut self, _: &str) -> Result<Option<Grant>, ()> {
        Ok(None)
    }

    async fn recover_refresh(&mut self, _: &str) -> Result<Option<Grant>, ()> {
        Ok(None)
    }
}
