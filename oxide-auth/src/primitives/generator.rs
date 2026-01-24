//! Generators produce string code grant and bearer tokens for a determined grant.
//!
//! In short, a code grant needs to encapsulate information about the owner, client, redirect_uri,
//! scope, and lifetime of a grant. This information needs to be uniquely recoverable.
//!
//! Two major implementation exists:
//!     - `RandomGenerator` depends on the entropy of the generated token to make guessing
//!     infeasible.
//!     - `Assertion` cryptographically verifies the integrity of a token, trading security without
//!     persistent storage for the loss of revocability. It is thus unfit for some backends, which
//!     is not currently expressed in the type system or with traits.

use super::grant::{Value, Extensions, Grant};
use super::{Url, Time};
use super::scope::Scope;

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{digest::CtOutput, Mac, Hmac};
use rand::{rngs::OsRng, RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use rmp_serde;

/// Generic token for a specific grant.
///
/// The interface may be reused for authentication codes, bearer tokens and refresh tokens.
///
/// ## Requirements on implementations
///
/// When queried without repetition (users will change the `usage` counter each time), this
/// method MUST be indistinguishable from a random function. This should be the crypgraphic
/// requirements for signature schemes without requiring the verification property (the
/// function need no be deterministic). This enables two popular choices: actual signature
/// schemes and (pseudo-)random generators that ignore all input.
///
/// The requirement is derived from the fact that one should not be able to derive the tag for
/// another token from ones own. Since there may be multiple tokens for a grant, the `usage`
/// counter makes it possible for `Authorizer` and `Issuer` implementations to differentiate
/// between these.
pub trait TagGrant {
    /// For example sign the input parameters or generate a random token.
    fn tag(&mut self, usage: u64, grant: &Grant) -> Result<String, ()>;
}

/// Generates tokens from random bytes.
///
/// Each byte is chosen randomly from the basic `rand::thread_rng`. This generator will always
/// succeed.
pub struct RandomGenerator {
    random: OsRng,
    len: usize,
}

impl RandomGenerator {
    /// Generates tokens with a specific byte length.
    pub fn new(length: usize) -> RandomGenerator {
        RandomGenerator {
            random: OsRng {},
            len: length,
        }
    }

    fn generate(&self) -> String {
        let mut result = vec![0; self.len];
        let mut rnd = self.random;
        rnd.try_fill_bytes(result.as_mut_slice())
            .expect("Failed to generate random token");

        STANDARD.encode(result)
    }
}

/// Generates tokens by signing its specifics with a private key.
///
/// Tokens produced by the generator include a serialized version of the grant followed by an HMAC
/// signature.  Since data is not encrypted, this token generator will ERROR if any private
/// extension is present in the grant.
///
/// The actual generator is given by a `TaggedAssertion` from `Assertion::tag` which enables
/// signing the same grant for different uses, i.e. separating authorization from bearer grants and
/// refresh tokens.
pub struct Assertion {
    hasher: Hmac<sha2::Sha256>,
}

/// The cryptographic suite ensuring integrity of tokens.
#[non_exhaustive]
pub enum AssertionKind {
    /// Uses [HMAC (RFC 2104)][HMAC] with [SHA-256 (FIPS 180-4)][SHA256] hash.
    ///
    /// [HMAC]: https://tools.ietf.org/html/rfc2104
    /// [SHA256]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    HmacSha256,
}

#[derive(Serialize, Deserialize)]
struct SerdeAssertionGrant {
    /// Identifies the owner of the resource.
    owner_id: String,

    /// Identifies the client to which the grant was issued.
    client_id: String,

    /// The scope granted to the client.
    #[serde(with = "scope_serde")]
    scope: Scope,

    /// The redirection uri under which the client resides. The url package does indeed seem to
    /// parse valid URIs as well.
    #[serde(with = "url_serde")]
    redirect_uri: Url,

    /// Expiration date of the grant (Utc).
    #[serde(with = "time_serde")]
    until: Time,

    /// The public extensions, private extensions not supported currently
    public_extensions: HashMap<String, Option<String>>,
}

#[derive(Serialize, Deserialize)]
struct AssertGrant(Vec<u8>, Vec<u8>);

/// Binds a tag to the data. The signature will be unique for data as well as the tag.
pub struct TaggedAssertion<'a>(&'a Assertion, &'a str);

impl Assertion {
    /// Construct an assertion from a custom secret.
    ///
    /// If the key material mismatches the key length required by the selected hash algorithm then
    /// padding or shortening of the supplied key material may be applied in the form dictated by
    /// the signature type. See the respective standards.
    ///
    /// If future suites are added where this is not possible, this function may panic when supplied
    /// with an incorrect key length.
    ///
    /// Currently, the implementation lacks the ability to really make use of another hasing mechanism than
    /// hmac + sha256.
    pub fn new(kind: AssertionKind, key: &[u8]) -> Self {
        match kind {
            AssertionKind::HmacSha256 => Assertion {
                hasher: Hmac::<sha2::Sha256>::new_from_slice(key).unwrap(),
            },
        }
    }

    /// Construct an assertion instance whose tokens are only valid for the program execution.
    pub fn ephemeral() -> Self {
        // TODO Extract KeySize from currently selected hasher
        let mut rand_bytes: [u8; 32] = [0; 32];
        thread_rng().fill_bytes(&mut rand_bytes);
        Assertion {
            hasher: Hmac::<sha2::Sha256>::new_from_slice(&rand_bytes).unwrap(),
        }
    }

    /// Get a reference to generator for the given tag.
    pub fn tag<'a>(&'a self, tag: &'a str) -> TaggedAssertion<'a> {
        TaggedAssertion(self, tag)
    }

    fn extract(&self, token: &str) -> Result<(Grant, String), ()> {
        let decoded = STANDARD.decode(token).map_err(|_| ())?;
        let assertion: AssertGrant = rmp_serde::from_slice(&decoded).map_err(|_| ())?;

        let mut hasher = self.hasher.clone();
        hasher.update(&assertion.0);
        hasher.verify_slice(assertion.1.as_slice()).map_err(|_| ())?;

        let (_, serde_grant, tag): (u64, SerdeAssertionGrant, String) =
            rmp_serde::from_slice(&assertion.0).map_err(|_| ())?;

        Ok((serde_grant.grant(), tag))
    }

    fn signature(&self, data: &[u8]) -> CtOutput<hmac::Hmac<sha2::Sha256>> {
        let mut hasher = self.hasher.clone();
        hasher.update(data);
        hasher.finalize()
    }

    fn counted_signature(&self, counter: u64, grant: &Grant) -> Result<String, ()> {
        let serde_grant = SerdeAssertionGrant::try_from(grant)?;
        let tosign = rmp_serde::to_vec(&(serde_grant, counter)).unwrap();
        let signature = self.signature(&tosign);
        Ok(STANDARD.encode(signature.into_bytes()))
    }

    fn generate_tagged(&self, counter: u64, grant: &Grant, tag: &str) -> Result<String, ()> {
        let serde_grant = SerdeAssertionGrant::try_from(grant)?;
        let tosign = rmp_serde::to_vec(&(counter, serde_grant, tag)).unwrap();
        let signature = self.signature(&tosign);
        let assert = AssertGrant(tosign, signature.into_bytes().to_vec());

        Ok(STANDARD.encode(rmp_serde::to_vec(&assert).unwrap()))
    }
}

impl<'a> TaggedAssertion<'a> {
    /// Sign the grant for this usage.
    ///
    /// This commits to a token that can be used–according to the usage tag–while the endpoint can
    /// trust in it belonging to the encoded grant. `counter` must be unique for each call to this
    /// function, similar to an IV to prevent accidentally producing the same token for the same
    /// grant (which may have multiple tokens). Note that the `tag` will be recovered and checked
    /// while the IV will not.
    pub fn sign(&self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.0.generate_tagged(counter, grant, self.1)
    }

    /// Inverse operation of generate, retrieve the underlying token.
    ///
    /// Result in an Err if either the signature is invalid or if the tag does not match the
    /// expected usage tag given to this assertion.
    pub fn extract(&self, token: &str) -> Result<Grant, ()> {
        self.0
            .extract(token)
            .and_then(|(token, tag)| if tag == self.1 { Ok(token) } else { Err(()) })
    }
}

impl<T: TagGrant + ?Sized> TagGrant for Box<T> {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        (**self).tag(counter, grant)
    }
}

impl<'a, T: TagGrant + ?Sized + 'a> TagGrant for &'a mut T {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        (**self).tag(counter, grant)
    }
}

impl TagGrant for RandomGenerator {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

impl TagGrant for &RandomGenerator {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

impl TagGrant for Rc<RandomGenerator> {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

impl TagGrant for Arc<RandomGenerator> {
    fn tag(&mut self, _: u64, _: &Grant) -> Result<String, ()> {
        Ok(self.generate())
    }
}

impl TagGrant for Assertion {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

impl TagGrant for &Assertion {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

impl TagGrant for Rc<Assertion> {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

impl TagGrant for Arc<Assertion> {
    fn tag(&mut self, counter: u64, grant: &Grant) -> Result<String, ()> {
        self.counted_signature(counter, grant)
    }
}

mod scope_serde {
    use crate::primitives::scope::Scope;

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(scope: &Scope, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&scope.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Scope, D::Error> {
        let as_string: &str = <&str>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod url_serde {
    use super::Url;

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer, Error};

    pub fn serialize<S: Serializer>(url: &Url, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(url.as_ref())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Url, D::Error> {
        let as_string: &str = <&str>::deserialize(deserializer)?;
        as_string.parse().map_err(Error::custom)
    }
}

mod time_serde {
    use super::Time;
    use chrono::{TimeZone, Utc};

    use serde::ser::{Serializer};
    use serde::de::{Deserialize, Deserializer};

    pub fn serialize<S: Serializer>(time: &Time, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(time.timestamp())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Time, D::Error> {
        let as_timestamp: i64 = <i64>::deserialize(deserializer)?;
        Ok(Utc.timestamp_opt(as_timestamp, 0).unwrap())
    }
}

impl SerdeAssertionGrant {
    fn try_from(grant: &Grant) -> Result<Self, ()> {
        let mut public_extensions: HashMap<String, Option<String>> = HashMap::new();

        if grant.extensions.private().any(|_| true) {
            return Err(());
        }

        for (name, content) in grant.extensions.public() {
            public_extensions.insert(name.to_string(), content.map(str::to_string));
        }

        Ok(SerdeAssertionGrant {
            owner_id: grant.owner_id.clone(),
            client_id: grant.client_id.clone(),
            scope: grant.scope.clone(),
            redirect_uri: grant.redirect_uri.clone(),
            until: grant.until,
            public_extensions,
        })
    }

    fn grant(self) -> Grant {
        let mut extensions = Extensions::new();
        for (name, content) in self.public_extensions.into_iter() {
            extensions.set_raw(name, Value::public(content))
        }
        Grant {
            owner_id: self.owner_id,
            client_id: self.client_id,
            scope: self.scope,
            redirect_uri: self.redirect_uri,
            until: self.until,
            extensions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code, unused)]
    fn assert_send_sync_static() {
        fn uses<T: Send + Sync + 'static>(arg: T) {}
        uses(RandomGenerator::new(16));
        let fake_key = [0u8; 16];
        uses(Assertion::new(AssertionKind::HmacSha256, &fake_key));
    }
}
