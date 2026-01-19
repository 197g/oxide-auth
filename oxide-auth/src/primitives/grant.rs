//! Encapsulates various shared mechanisms for handlings different grants.
use super::{Url, Time};
use super::scope::Scope;

use std::borrow::{Cow, ToOwned};
use std::collections::HashMap;
use std::collections::hash_map::Iter;
use std::rc::Rc;
use std::sync::Arc;

/// Provides a name registry for extensions.
pub trait GrantExtension {
    /// An unique identifier distinguishing this extension type for parsing and storing.
    /// Obvious choices are the registered names as administered by IANA or private identifiers.
    fn identifier(&self) -> &'static str;
}

/// Wraps the data for an extension as a string with access restrictions.
///
/// This is a generic way for extensions to store their data in a universal, encoded form. It is
/// also able to indicate the intended readers for such an extension so that backends can ensure
/// that private extension data is properly encrypted even when present in a self-encoded access
/// token.
///
/// Some extensions have semantics where the presence alone is the stored data, so storing data
/// is optional and storing no data is distinct from not attaching any extension instance at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// An extension that the token owner is allowed to read and interpret.
    Public(Option<String>),

    /// Identifies an extenion whose content and/or existance MUST be kept secret.
    Private(Option<String>),
    // Content which is not saved on the server but initialized/interpreted from other sources.
    // foreign_content: String,
}

/// Links one or several `GrantExtension` instances to their respective data.
///
/// This also serves as a clean interface for both frontend and backend to reliably and
/// conveniently manipulate or query the stored data sets.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Extensions {
    extensions: HashMap<String, Value>,
}

/// Owning copy of a grant.
///
/// This can be stored in a database without worrying about lifetimes or shared across thread
/// boundaries. A reference to this can be converted to a purely referential `GrantRef`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// Identifies the owner of the resource.
    pub owner_id: String,

    /// Identifies the client to which the grant was issued.
    pub client_id: String,

    /// The scope granted to the client.
    pub scope: Scope,

    /// The redirection uri under which the client resides. The url package does indeed seem to
    /// parse valid URIs as well.
    pub redirect_uri: Url,

    /// Expiration date of the grant (Utc).
    pub until: Time,

    /// Encoded extensions existing on this Grant
    pub extensions: Extensions,
}

impl Value {
    /// Creates an extension whose presence and content can be unveiled by the token holder.
    ///
    /// Anyone in possession of the token corresponding to such a grant is potentially able to read
    /// the content of a public extension.
    pub fn public(content: Option<String>) -> Self {
        Value::Public(content)
    }

    /// Creates an extension with secret content only visible for the server.
    ///
    /// Token issuers should take special care to protect the content and the identifier of such
    /// an extension from being interpreted or correlated by the token holder.
    pub fn private(content: Option<String>) -> Value {
        Value::Private(content)
    }

    /// Inspect the public value.
    ///
    /// Returns an `Err` if this is not a public extension, `None` if the extension has no value
    /// but consists only of the key, and `Some(_)` otherwise.
    pub fn public_value(&self) -> Result<Option<&str>, ()> {
        match self {
            Value::Public(Some(content)) => Ok(Some(content)),
            Value::Public(None) => Ok(None),
            _ => Err(()),
        }
    }

    /// Convert into the public value.
    ///
    /// Returns an `Err` if this is not a public extension, `None` if the extension has no value
    /// but consists only of the key, and `Some(_)` otherwise.
    pub fn into_public_value(self) -> Result<Option<String>, ()> {
        match self {
            Value::Public(content) => Ok(content),
            _ => Err(()),
        }
    }

    /// Inspect the private value.
    ///
    /// Returns an `Err` if this is not a private extension, `None` if the extension has no value
    /// but consists only of the key, and `Some(_)` otherwise.
    pub fn private_value(&self) -> Result<Option<&str>, ()> {
        match self {
            Value::Private(Some(content)) => Ok(Some(content)),
            Value::Private(None) => Ok(None),
            _ => Err(()),
        }
    }

    /// Inspect the private value.
    ///
    /// Returns an `Err` if this is not a private extension, `None` if the extension has no value
    /// but consists only of the key, and `Some(_)` otherwise.
    pub fn into_private_value(self) -> Result<Option<String>, ()> {
        match self {
            Value::Private(content) => Ok(content),
            _ => Err(()),
        }
    }
}

impl Extensions {
    /// Create a new extension store.
    pub fn new() -> Extensions {
        Extensions::default()
    }

    /// Set the stored content for a `GrantExtension` instance.
    pub fn set(&mut self, extension: &dyn GrantExtension, content: Value) {
        self.extensions
            .insert(extension.identifier().to_string(), content);
    }

    /// Set content for an extension without a corresponding instance.
    pub fn set_raw(&mut self, identifier: String, content: Value) {
        self.extensions.insert(identifier, content);
    }

    /// Retrieve the stored data of an instance.
    ///
    /// This removes the data from the store to avoid possible mixups and to allow a copyless
    /// retrieval of bigger data strings.
    pub fn remove(&mut self, extension: &dyn GrantExtension) -> Option<Value> {
        self.extensions.remove(extension.identifier())
    }

    /// Iterate of the public extensions whose presence and content is not secret.
    pub fn public(&self) -> PublicExtensions {
        PublicExtensions {
            iter: self.extensions.iter(),
        }
    }

    /// Iterate of the private extensions whose presence and content must not be revealed.
    pub fn private(&self) -> PrivateExtensions {
        PrivateExtensions(self.extensions.iter())
    }
}

/// An iterator over the public extensions of a grant.
pub struct PublicExtensions<'a> {
    iter: Iter<'a, String, Value>,
}

/// An iterator over the private extensions of a grant.
///
/// Implementations which acquire an instance should take special not to leak any secrets to
/// clients and third parties.
pub struct PrivateExtensions<'a>(Iter<'a, String, Value>);

impl<'a> Iterator for PublicExtensions<'a> {
    type Item = (&'a str, Option<&'a str>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (key, value) = self.iter.next()?;

            if let Ok(value) = value.public_value() {
                return Some((key, value));
            }
        }
    }
}

impl<'a> Iterator for PrivateExtensions<'a> {
    type Item = (&'a str, Option<&'a str>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (key, value) = self.0.next()?;

            if let Ok(value) = value.private_value() {
                return Some((key, value));
            }
        }
    }
}

impl<'a, T: GrantExtension + ?Sized> GrantExtension for &'a T {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}

impl<'a, T: GrantExtension + ?Sized> GrantExtension for Cow<'a, T>
where
    T: Clone + ToOwned,
{
    fn identifier(&self) -> &'static str {
        self.as_ref().identifier()
    }
}

impl<T: GrantExtension + ?Sized> GrantExtension for Box<T> {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}

impl<T: GrantExtension + ?Sized> GrantExtension for Arc<T> {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}

impl<T: GrantExtension + ?Sized> GrantExtension for Rc<T> {
    fn identifier(&self) -> &'static str {
        (**self).identifier()
    }
}

#[cfg(test)]
mod tests {
    use super::{Extensions, Value};

    #[test]
    fn iteration() {
        let mut extensions = Extensions::new();
        extensions.set_raw("pub".into(), Value::Public(Some("content".into())));
        extensions.set_raw("pub_none".into(), Value::Public(None));
        extensions.set_raw("priv".into(), Value::Private(Some("private".into())));
        extensions.set_raw("priv_none".into(), Value::Private(None));

        assert_eq!(
            extensions
                .public()
                .filter(|&(name, value)| name == "pub" && value == Some("content"))
                .count(),
            1
        );
        assert_eq!(
            extensions
                .public()
                .filter(|&(name, value)| name == "pub_none" && value == None)
                .count(),
            1
        );
        assert_eq!(extensions.public().count(), 2);

        assert_eq!(
            extensions
                .private()
                .filter(|&(name, value)| name == "priv" && value == Some("private"))
                .count(),
            1
        );
        assert_eq!(
            extensions
                .private()
                .filter(|&(name, value)| name == "priv_none" && value == None)
                .count(),
            1
        );
        assert_eq!(extensions.private().count(), 2);
    }
}
