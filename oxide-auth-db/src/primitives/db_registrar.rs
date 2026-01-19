use std::borrow::Cow;
use std::iter::Extend;
use once_cell::sync::Lazy;
use oxide_auth::primitives::registrar::{
    Argon2, BoundClient, Client, EncodedClient, PasswordPolicy, RegisteredClient, Registrar,
    RegistrarError,
};
use oxide_auth::primitives::prelude::{ClientUrl, PreGrant, Scope};
use crate::db_service::DataSource;
use r2d2_redis::redis::RedisError;

/// A database client service which implemented Registrar.
/// db: repository service to query stored clients or regist new client.
/// password_policy: to encode client_secret.
pub struct DBRegistrar {
    pub repo: DataSource,
    password_policy: Option<Box<dyn PasswordPolicy>>,
}

/// methods to search and regist clients from DataSource.
/// which should be implemented for all DataSource type.
pub trait OauthClientDBRepository {
    fn list(&self) -> anyhow::Result<Vec<EncodedClient>>;

    fn find_client_by_id(&self, id: &str) -> anyhow::Result<EncodedClient>;

    fn regist_from_encoded_client(&self, client: EncodedClient) -> anyhow::Result<()>;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//                             Implementations of DB Registrars                                  //
///////////////////////////////////////////////////////////////////////////////////////////////////

static DEFAULT_PASSWORD_POLICY: Lazy<Argon2> = Lazy::new(Argon2::default);

impl DBRegistrar {
    /// Create an DB connection recording to features.
    pub fn new(url: String, max_pool_size: u32, client_prefix: String) -> Result<Self, RedisError> {
        let repo = DataSource::new(url, max_pool_size, client_prefix)?;
        Ok(DBRegistrar {
            repo,
            password_policy: None,
        })
    }

    /// Insert or update the client record.
    pub fn register_client(&mut self, client: Client) -> Result<(), RegistrarError> {
        let password_policy = Self::current_policy(&self.password_policy);
        let encoded_client = client.encode(password_policy);

        self.repo
            .regist_from_encoded_client(encoded_client)
            .map_err(|_e| RegistrarError::Unspecified)
    }

    /// Change how passwords are encoded while stored.
    pub fn set_password_policy<P: PasswordPolicy + 'static>(&mut self, new_policy: P) {
        self.password_policy = Some(Box::new(new_policy))
    }

    // This is not an instance method because it needs to borrow the box but register needs &mut
    fn current_policy(policy: &Option<Box<dyn PasswordPolicy>>) -> &dyn PasswordPolicy {
        policy
            .as_ref()
            .map(|boxed| &**boxed)
            .unwrap_or(&*DEFAULT_PASSWORD_POLICY)
    }
}

impl Extend<Client> for DBRegistrar {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = Client>,
    {
        iter.into_iter().for_each(|client| {
            let _ = self.register_client(client);
        })
    }
}

impl Registrar for DBRegistrar {
    fn bound_redirect<'a>(&self, bound: ClientUrl<'a>) -> Result<BoundClient<'a>, RegistrarError> {
        let client = match self.repo.find_client_by_id(bound.client_id.as_ref()) {
            Ok(detail) => detail,
            _ => return Err(RegistrarError::Unspecified),
        };
        // Perform exact matching as motivated in the rfc
        let registered_url = match bound.redirect_uri {
            None => client.redirect_uri.clone(),
            Some(ref url) => {
                let original = std::iter::once(&client.redirect_uri);
                let alternatives = client.additional_redirect_uris.iter();
                if let Some(registered) = original
                    .chain(alternatives)
                    .find(|&registered| *registered == *url.as_ref())
                {
                    registered.clone()
                } else {
                    return Err(RegistrarError::Unspecified);
                }
            }
        };
        Ok(BoundClient {
            client_id: bound.client_id,
            redirect_uri: Cow::Owned(registered_url),
        })
    }

    fn negotiate<'a>(
        &self, bound: BoundClient<'a>, _scope: Option<Scope>,
    ) -> Result<PreGrant, RegistrarError> {
        let client = self
            .repo
            .find_client_by_id(&bound.client_id)
            .map_err(|_e| RegistrarError::Unspecified)?;
        Ok(PreGrant {
            client_id: bound.client_id.into_owned(),
            redirect_uri: bound.redirect_uri.into_owned(),
            scope: client.default_scope,
        })
    }

    fn check(&self, client_id: &str, passphrase: Option<&[u8]>) -> Result<(), RegistrarError> {
        let password_policy = Self::current_policy(&self.password_policy);

        let client = self
            .repo
            .find_client_by_id(client_id)
            .map_err(|_e| RegistrarError::Unspecified);
        client.and_then(|op_client| {
            RegisteredClient::new(&op_client, password_policy).check_authentication(passphrase)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxide_auth::primitives::registrar::{ExactUrl, RegisteredUrl};
    use std::str::FromStr;

    #[test]
    fn public_client() {
        let policy = Argon2::default();
        let client = Client::public(
            "ClientId",
            RegisteredUrl::Exact(ExactUrl::from_str("https://example.com").unwrap()),
            "default".parse().unwrap(),
        )
        .encode(&policy);
        let client = RegisteredClient::new(&client, &policy);

        // Providing no authentication data is ok
        assert!(client.check_authentication(None).is_ok());
        // Any authentication data is a fail
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn confidential_client() {
        let policy = Argon2::default();
        let pass = b"AB3fAj6GJpdxmEVeNCyPoA==";
        let client = Client::confidential(
            "ClientId",
            RegisteredUrl::Exact(ExactUrl::from_str("https://example.com").unwrap()),
            "default".parse().unwrap(),
            pass,
        )
        .encode(&policy);
        let client = RegisteredClient::new(&client, &policy);
        assert!(client.check_authentication(None).is_err());
        assert!(client.check_authentication(Some(pass)).is_ok());
        assert!(client.check_authentication(Some(b"not the passphrase")).is_err());
        assert!(client.check_authentication(Some(b"")).is_err());
    }

    #[test]
    fn with_additional_redirect_uris() {
        if crate::requires_redis_and_should_skip() {
            return;
        }

        let client_id = "ClientId";
        let redirect_uri =
            RegisteredUrl::from(ExactUrl::new("https://example.com/foo".parse().unwrap()).unwrap());
        let additional_redirect_uris: Vec<RegisteredUrl> = vec![RegisteredUrl::from(
            ExactUrl::new("https://example.com/bar".parse().unwrap()).unwrap(),
        )];
        let default_scope = "default-scope".parse().unwrap();
        let client = Client::public(client_id, redirect_uri, default_scope)
            .with_additional_redirect_uris(additional_redirect_uris);
        let mut db_registrar = DBRegistrar::new(
            "redis://localhost/3".parse().unwrap(),
            32,
            "client:".parse().unwrap(),
        )
        .unwrap();
        db_registrar.register_client(client).unwrap();

        assert_eq!(
            db_registrar
                .bound_redirect(ClientUrl {
                    client_id: Cow::from(client_id),
                    redirect_uri: Some(Cow::Borrowed(&"https://example.com/foo".parse().unwrap()))
                })
                .unwrap()
                .redirect_uri,
            Cow::Owned::<RegisteredUrl>(RegisteredUrl::from(
                ExactUrl::new("https://example.com/foo".parse().unwrap()).unwrap()
            ))
        );

        assert_eq!(
            db_registrar
                .bound_redirect(ClientUrl {
                    client_id: Cow::from(client_id),
                    redirect_uri: Some(Cow::Borrowed(&"https://example.com/bar".parse().unwrap()))
                })
                .unwrap()
                .redirect_uri,
            Cow::Owned::<RegisteredUrl>(RegisteredUrl::from(
                ExactUrl::new("https://example.com/bar".parse().unwrap()).unwrap()
            ))
        );

        assert!(db_registrar
            .bound_redirect(ClientUrl {
                client_id: Cow::from(client_id),
                redirect_uri: Some(Cow::Borrowed(&"https://example.com/baz".parse().unwrap()))
            })
            .is_err());
    }

    #[test]
    fn client_service() {
        if crate::requires_redis_and_should_skip() {
            return;
        }

        let mut oauth_service = DBRegistrar::new(
            "redis://localhost/3".parse().unwrap(),
            32,
            "client:".parse().unwrap(),
        )
        .unwrap();
        let public_id = "PrivateClientId";
        let client_url = "https://example.com";

        let private_id = "PublicClientId";
        let private_passphrase = b"WOJJCcS8WyS2aGmJK6ZADg==";

        let public_client = Client::public(
            public_id,
            RegisteredUrl::Exact(ExactUrl::new(client_url.parse().unwrap()).unwrap()),
            "default".parse().unwrap(),
        );

        oauth_service.register_client(public_client).unwrap();
        oauth_service
            .check(public_id, None)
            .expect("Authorization of public client has changed");
        oauth_service
            .check(public_id, Some(b""))
            .err()
            .expect("Authorization with password succeeded");

        let private_client = Client::confidential(
            private_id,
            RegisteredUrl::Exact(ExactUrl::new(client_url.parse().unwrap()).unwrap()),
            "default".parse().unwrap(),
            private_passphrase,
        );

        oauth_service.register_client(private_client).unwrap();

        oauth_service
            .check(private_id, Some(private_passphrase))
            .expect("Authorization with right password did not succeed");
        oauth_service
            .check(private_id, Some(b"Not the private passphrase"))
            .err()
            .expect("Authorization succeed with wrong password");
    }
}
