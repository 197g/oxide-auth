use crate::primitives::db_registrar::OauthClientDBRepository;

use oxide_auth::primitives::prelude::Scope;
use oxide_auth::primitives::registrar::{ClientType, EncodedClient, RegisteredUrl, ExactUrl};

use r2d2_redis::r2d2::Pool;
use r2d2_redis::redis::{Commands, RedisError, ErrorKind};
use r2d2_redis::RedisConnectionManager;
use std::str::FromStr;
use serde::{Serialize, Deserialize};
use url::Url;

// // TODO 参数化
// pub const CLIENT_PREFIX: &str = "client:";

/// redis datasource to Client entries.
#[derive(Debug, Clone)]
pub struct RedisDataSource {
    url: String,
    pool: Pool<RedisConnectionManager>,
    client_prefix: String,
}

/// A client whose credentials have been wrapped by a password policy.
///
/// This provides a standard encoding for `Registrars` who wish to store their clients and makes it
/// possible to test password policies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringfiedEncodedClient {
    /// The id of this client. If this is was registered at a `Registrar`, this should be a key
    /// to the instance.
    pub client_id: String,

    /// The registered redirect uri.
    /// Unlike `additional_redirect_uris`, this is registered as the default redirect uri
    /// and will be replaced if, for example, no `redirect_uri` is specified in the request parameter.
    pub redirect_uri: String,

    /// The redirect uris that can be registered in addition to the `redirect_uri`.
    /// If you want to register multiple redirect uris, register them together with `redirect_uri`.
    pub additional_redirect_uris: Vec<String>,

    /// The scope the client gets if none was given.
    pub default_scope: Option<String>,

    /// client_secret, for authentication.
    pub client_secret: Option<String>,
}

impl StringfiedEncodedClient {
    pub fn to_encoded_client(&self) -> anyhow::Result<EncodedClient> {
        let redirect_uri = RegisteredUrl::from(ExactUrl::from_str(&self.redirect_uri)?);
        let uris = &self.additional_redirect_uris;
        let additional_redirect_uris = uris.iter().fold(vec![], |mut us, u| {
            us.push(RegisteredUrl::from(ExactUrl::from_str(u).unwrap()));
            us
        });

        let client_type = match &self.client_secret {
            None => ClientType::Public,
            Some(secret) => ClientType::Confidential {
                passdata: secret.to_owned().into_bytes(),
            },
        };

        Ok(EncodedClient {
            client_id: (self.client_id).parse().unwrap(),
            redirect_uri,
            additional_redirect_uris,
            default_scope: Scope::from_str(
                self.default_scope.as_ref().unwrap_or(&"".to_string()).as_ref(),
            )
            .unwrap(),
            encoded_client: client_type,
        })
    }

    pub fn from_encoded_client(encoded_client: &EncodedClient) -> Self {
        let additional_redirect_uris = encoded_client
            .additional_redirect_uris
            .iter()
            .map(|u| u.to_owned().as_str().parse().unwrap())
            .collect();
        let default_scope = Some(encoded_client.default_scope.to_string());
        let client_secret = match &encoded_client.encoded_client {
            ClientType::Public => None,
            ClientType::Confidential { passdata } => Some(String::from_utf8(passdata.to_vec()).unwrap()),
        };
        StringfiedEncodedClient {
            client_id: encoded_client.client_id.to_owned(),
            redirect_uri: encoded_client.redirect_uri.to_owned().as_str().parse().unwrap(),
            additional_redirect_uris,
            default_scope,
            client_secret,
        }
    }
}

impl RedisDataSource {
    pub fn new(url: String, max_pool_size: u32, client_prefix: String) -> Result<Self, RedisError> {
        let manager = r2d2_redis::RedisConnectionManager::new(url.as_str())?;
        let pool = Pool::builder().max_size(max_pool_size).build(manager);
        match pool {
            Ok(pool) => Ok(RedisDataSource {
                url,
                pool,
                client_prefix,
            }),
            Err(_e) => Err(RedisError::from((ErrorKind::ClientError, "Build pool error."))),
        }
    }

    pub fn new_with_url(
        url: Url, max_pool_size: u32, client_prefix: String,
    ) -> Result<Self, RedisError> {
        RedisDataSource::new(url.into(), max_pool_size, client_prefix)
    }

    pub fn get_url(&self) -> String {
        self.url.clone()
    }
    pub fn get_pool(&self) -> Pool<RedisConnectionManager> {
        self.pool.clone()
    }
}

impl RedisDataSource {
    /// users can regist to redis a custom client struct which can be Serialized and Deserialized.
    pub fn regist(&self, detail: &StringfiedEncodedClient) -> anyhow::Result<()> {
        let mut pool = self.pool.get()?;
        let client_str = serde_json::to_string(&detail)?;
        pool.set(&(self.client_prefix.to_owned() + &detail.client_id), client_str)?;
        Ok(())
    }
}

impl OauthClientDBRepository for RedisDataSource {
    fn list(&self) -> anyhow::Result<Vec<EncodedClient>> {
        let mut encoded_clients: Vec<EncodedClient> = vec![];
        let mut r = self.pool.get()?;
        let keys = r.keys::<&str, Vec<String>>(&self.client_prefix)?;
        for key in keys {
            let clients_str = r.get::<String, String>(key)?;
            let stringfied_client = serde_json::from_str::<StringfiedEncodedClient>(&clients_str)?;
            encoded_clients.push(stringfied_client.to_encoded_client()?);
        }
        Ok(encoded_clients)
    }

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient> {
        let mut r = self.pool.get()?;
        let client_str = r.get::<&str, String>(&(self.client_prefix.to_owned() + id))?;
        let stringfied_client = serde_json::from_str::<StringfiedEncodedClient>(&client_str)?;
        stringfied_client.to_encoded_client()
    }

    fn regist_from_encoded_client(&self, client: EncodedClient) -> anyhow::Result<()> {
        let detail = StringfiedEncodedClient::from_encoded_client(&client);
        self.regist(&detail)
    }
}
