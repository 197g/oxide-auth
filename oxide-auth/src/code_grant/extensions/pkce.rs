use std::borrow::Cow;

use crate::{
    OAuthOpaqueError,
    primitives::grant::{GrantExtension, Value},
};

use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Proof Key for Code Exchange by OAuth Public Clients
///
/// > Auth 2.0 public clients utilizing the Authorization Code Grant are
/// > susceptible to the authorization code interception attack.  This
/// > specification describes the attack as well as a technique to mitigate
/// > against the threat through the use of Proof Key for Code Exchange
/// > (PKCE, pronounced "pixy").
///
/// (from the respective [RFC 7636])
///
/// In short, public clients share a verifier for a secret token when requesting their initial
/// authorization code. When they then make a second request to the autorization server, trading
/// this code for an access token, they can credible assure the server of their identity by
/// presenting the secret token.
///
/// The simple `plain` method only prevents attackers unable to snoop on the connection from
/// impersonating the client, while the `S256` method, which uses one-way hash functions, makes
/// any attack short of reading the victim client's memory infeasible.
///
/// Support for the `plain` method is OPTIONAL and must be turned on explicitely.
///
/// [RFC 7636]: https://tools.ietf.org/html/rfc7636
pub struct Pkce {
    required: bool,
    allow_plain: bool,
}

enum Method {
    Plain(String),
    Sha256(String),
}

impl Pkce {
    /// A pkce extensions which requires clients to use it.
    pub fn required() -> Pkce {
        Pkce {
            required: true,
            allow_plain: false,
        }
    }

    /// Pkce extension which will check verifiers if present but not require them.
    pub fn optional() -> Pkce {
        Pkce {
            required: false,
            allow_plain: false,
        }
    }

    /// Allow usage of the less secure `plain` verification method. This method is NOT secure
    /// an eavesdropping attacker such as rogue processes capturing a devices requests.
    pub fn allow_plain(&mut self) {
        self.allow_plain = true;
    }

    /// Create the encoded method for proposed method and challenge.
    ///
    /// The method defaults to `plain` when none is given, effectively offering increased
    /// compatibility but less security. Support for `plain` is optional and needs to be enabled
    /// explicitely through `Pkce::allow_plain`. This extension may also require clients to use it,
    /// in which case giving no challenge also leads to an error.
    ///
    /// The resulting string MUST NOT be publicly available to the client. Otherwise, it would be
    /// trivial for a third party to impersonate the client in the access token request phase. For
    /// a SHA256 methods the results would not be quite as severe but still bad practice.
    pub fn challenge(
        &self, method: Option<Cow<str>>, challenge: Option<Cow<str>>,
    ) -> Result<Option<Value>, OAuthOpaqueError> {
        let method = method.unwrap_or(Cow::Borrowed("plain"));

        let challenge = match challenge {
            None if self.required => return Err(OAuthOpaqueError),
            None => return Ok(None),
            Some(challenge) => challenge,
        };

        let method = Method::from_parameter(method, challenge)?;
        let method = method.assert_supported_method(self.allow_plain)?;

        Ok(Some(Value::private(Some(method.encode()))))
    }

    /// Verify against the encoded challenge.
    ///
    /// When the challenge is required, ensure again that a challenge was made and a corresponding
    /// method data is present as an extension. This is not strictly necessary since clients should
    /// not be able to delete private extension data but this check does not cost a lot.
    ///
    /// When a challenge was agreed upon but no verifier is present, this method will return an
    /// error.
    pub fn verify(
        &self, method: Option<Value>, verifier: Option<Cow<str>>,
    ) -> Result<(), OAuthOpaqueError> {
        let (method, verifier) = match (method, verifier) {
            (None, _) if self.required => return Err(OAuthOpaqueError),
            (None, _) => return Ok(()),
            // An internal saved method but no verifier
            (Some(_), None) => return Err(OAuthOpaqueError),
            (Some(method), Some(verifier)) => (method, verifier),
        };

        let method = match method.into_private_value() {
            Ok(Some(method)) => method,
            _ => return Err(OAuthOpaqueError),
        };

        let method = Method::from_encoded(Cow::Owned(method))?;

        method.verify(&verifier)
    }
}

impl GrantExtension for Pkce {
    fn identifier(&self) -> &'static str {
        "pkce"
    }
}

/// Base 64 encoding without padding
fn b64encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

impl Method {
    fn from_parameter(method: Cow<str>, challenge: Cow<str>) -> Result<Self, OAuthOpaqueError> {
        match method.as_ref() {
            "plain" => Ok(Method::Plain(challenge.into_owned())),
            "S256" => Ok(Method::Sha256(challenge.into_owned())),
            _ => Err(OAuthOpaqueError),
        }
    }

    fn assert_supported_method(self, allow_plain: bool) -> Result<Self, OAuthOpaqueError> {
        match (self, allow_plain) {
            (this, true) => Ok(this),
            (Method::Sha256(content), false) => Ok(Method::Sha256(content)),
            (Method::Plain(_), false) => Err(OAuthOpaqueError),
        }
    }

    fn encode(self) -> String {
        match self {
            Method::Plain(challenge) => challenge + "p",
            Method::Sha256(challenge) => challenge + "S",
        }
    }

    fn from_encoded(encoded: Cow<str>) -> Result<Method, OAuthOpaqueError> {
        // TODO: avoid allocation in case of borrow and invalid.
        let mut encoded = encoded.into_owned();
        match encoded.pop() {
            None => Err(OAuthOpaqueError),
            Some('p') => Ok(Method::Plain(encoded)),
            Some('S') => Ok(Method::Sha256(encoded)),
            _ => Err(OAuthOpaqueError),
        }
    }

    fn verify(&self, verifier: &str) -> Result<(), OAuthOpaqueError> {
        match self {
            Method::Plain(encoded) => {
                if encoded.as_bytes().ct_eq(verifier.as_bytes()).into() {
                    Ok(())
                } else {
                    Err(OAuthOpaqueError)
                }
            }
            Method::Sha256(encoded) => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let b64digest = b64encode(&hasher.finalize());
                if encoded.as_bytes().ct_eq(b64digest.as_bytes()).into() {
                    Ok(())
                } else {
                    Err(OAuthOpaqueError)
                }
            }
        }
    }
}
