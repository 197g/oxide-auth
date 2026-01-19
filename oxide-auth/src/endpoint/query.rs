use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::fmt;
use std::iter::FromIterator;
use std::hash::{BuildHasher, Hash};
use std::rc::Rc;
use std::sync::Arc;

use serde::de;
use serde::Deserializer;

/// Allows access to the query parameters in an url or a body.
///
/// Use one of the listed implementations below. Since those may be a bit confusing due to their
/// abundant use of generics, basically use any type of `HashMap` that maps 'str-likes' to a
/// collection of other 'str-likes'. Popular instances may be:
/// * `HashMap<String, String>`
/// * `HashMap<String, Vec<String>>`
/// * `HashMap<Cow<'static, str>, Cow<'static, str>>`
///
/// You should generally not have to implement this trait yourself, and if you do there are
/// additional requirements on your implementation to guarantee standard conformance. Therefore the
/// trait is marked as `unsafe`.
pub unsafe trait QueryParameter {
    /// Get the **unique** value associated with a key.
    ///
    /// If there are multiple values, return `None`. This is very important to guarantee
    /// conformance to the RFC. Afaik it prevents potentially subverting validation middleware,
    /// order dependent processing, or simple confusion between different components who parse the
    /// query string from different ends.
    fn unique_value(&self, key: &str) -> Option<Cow<str>>;

    /// Guarantees that one can grab an owned copy.
    fn normalize(&self) -> NormalizedParameter;
}

/// The query parameter normal form.
///
/// When a request wants to give access to its query or body parameters by reference, it can do so
/// by a reference of the particular trait. But when the representation of the query is not stored
/// in the memory associated with the request, it needs to be allocated to outlive the borrow on
/// the request.  This allocation may as well perform the minimization/normalization into a
/// representation actually consumed by the backend. This normal form thus encapsulates the
/// associated `clone-into-normal form` by various possible constructors from references [WIP].
///
/// This gives rise to a custom `Cow<QueryParameter>` instance by requiring that normalization into
/// memory with unrelated lifetime is always possible.
///
/// Internally a hashmap but this may change due to optimizations.
#[derive(Clone, Debug, Default)]
pub struct NormalizedParameter {
    /// The value is `None` if the key appeared at least twice.
    inner: HashMap<Cow<'static, str>, Option<Cow<'static, str>>>,
}

unsafe impl QueryParameter for NormalizedParameter {
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        self.inner
            .get(key)
            .and_then(|val| val.as_ref().map(Cow::as_ref).map(Cow::Borrowed))
    }

    fn normalize(&self) -> NormalizedParameter {
        self.clone()
    }
}

impl NormalizedParameter {
    /// Create an empty map.
    pub fn new() -> Self {
        NormalizedParameter::default()
    }

    /// Insert a key-value-pair or mark key as dead if already present.
    ///
    /// Since each key must appear at most once, we do not remove it from the map but instead mark
    /// the key as having a duplicate entry.
    pub fn insert_or_poison(&mut self, key: Cow<'static, str>, val: Cow<'static, str>) {
        let unique_val = Some(val);
        self.inner
            .entry(key)
            .and_modify(|val| *val = None)
            .or_insert(unique_val);
    }
}

impl Borrow<dyn QueryParameter> for NormalizedParameter {
    fn borrow(&self) -> &(dyn QueryParameter + 'static) {
        self
    }
}

impl Borrow<dyn QueryParameter + Send> for NormalizedParameter {
    fn borrow(&self) -> &(dyn QueryParameter + Send + 'static) {
        self
    }
}

impl<'de> de::Deserialize<'de> for NormalizedParameter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor(NormalizedParameter);

        impl<'a> de::Visitor<'a> for Visitor {
            type Value = NormalizedParameter;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a sequence of key-value-pairs")
            }

            fn visit_seq<A>(mut self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'a>,
            {
                while let Some((key, value)) = access.next_element::<(String, String)>()? {
                    self.0.insert_or_poison(key.into(), value.into())
                }

                Ok(self.0)
            }
        }

        let visitor = Visitor(NormalizedParameter::default());
        deserializer.deserialize_seq(visitor)
    }
}

impl<K, V> FromIterator<(K, V)> for NormalizedParameter
where
    K: Into<Cow<'static, str>>,
    V: Into<Cow<'static, str>>,
{
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (K, V)>,
    {
        let mut target = NormalizedParameter::default();
        iter.into_iter()
            .for_each(|(k, v)| target.insert_or_poison(k.into(), v.into()));
        target
    }
}

impl ToOwned for dyn QueryParameter {
    type Owned = NormalizedParameter;

    fn to_owned(&self) -> Self::Owned {
        self.normalize()
    }
}

impl ToOwned for dyn QueryParameter + Send {
    type Owned = NormalizedParameter;

    fn to_owned(&self) -> Self::Owned {
        self.normalize()
    }
}

/// Return a reference to value in a collection if it is the only one.
///
/// For example, a vector of string like types returns a reference to its first
/// element if there are no other, else it returns `None`.
///
/// If this were done with slices, that would require choosing a particular
/// value type of the underlying slice e.g. `[String]`.
pub unsafe trait UniqueValue {
    /// Borrow the unique value reference.
    fn get_unique(&self) -> Option<&str>;
}

unsafe impl<K, V, S: BuildHasher> QueryParameter for HashMap<K, V, S>
where
    K: Borrow<str> + Eq + Hash,
    V: UniqueValue + Eq + Hash,
{
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        self.get(key).and_then(V::get_unique).map(Cow::Borrowed)
    }

    fn normalize(&self) -> NormalizedParameter {
        let inner = self
            .iter()
            .filter_map(|(key, val)| {
                val.get_unique().map(|value| {
                    (
                        Cow::Owned(key.borrow().to_string()),
                        Some(Cow::Owned(value.to_string())),
                    )
                })
            })
            .collect();

        NormalizedParameter { inner }
    }
}

unsafe impl<K, V> QueryParameter for Vec<(K, V)>
where
    K: Borrow<str> + Eq + Hash,
    V: Borrow<str> + Eq + Hash,
{
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        let mut value = None;

        for entry in self.iter() {
            if entry.0.borrow() == key {
                if value.is_some() {
                    return None;
                }
                value = Some(Cow::Borrowed(entry.1.borrow()));
            }
        }

        value
    }

    fn normalize(&self) -> NormalizedParameter {
        let mut params = NormalizedParameter::default();
        self.iter()
            .map(|(key, val)| {
                (
                    Cow::Owned(key.borrow().to_string()),
                    Cow::Owned(val.borrow().to_string()),
                )
            })
            .for_each(|(key, val)| params.insert_or_poison(key, val));
        params
    }
}

unsafe impl<'a, Q: QueryParameter + 'a + ?Sized> QueryParameter for &'a Q {
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        (**self).unique_value(key)
    }

    fn normalize(&self) -> NormalizedParameter {
        (**self).normalize()
    }
}

unsafe impl<'a, Q: QueryParameter + 'a + ?Sized> QueryParameter for &'a mut Q {
    fn unique_value(&self, key: &str) -> Option<Cow<str>> {
        (**self).unique_value(key)
    }

    fn normalize(&self) -> NormalizedParameter {
        (**self).normalize()
    }
}

unsafe impl UniqueValue for str {
    fn get_unique(&self) -> Option<&str> {
        Some(self)
    }
}

unsafe impl UniqueValue for String {
    fn get_unique(&self) -> Option<&str> {
        Some(self)
    }
}

unsafe impl<'a, V> UniqueValue for &'a V
where
    V: AsRef<str> + ?Sized,
{
    fn get_unique(&self) -> Option<&str> {
        Some(self.as_ref())
    }
}

unsafe impl<'a> UniqueValue for Cow<'a, str> {
    fn get_unique(&self) -> Option<&str> {
        Some(self.as_ref())
    }
}

unsafe impl<V: UniqueValue> UniqueValue for Option<V> {
    fn get_unique(&self) -> Option<&str> {
        self.as_ref().and_then(V::get_unique)
    }
}

unsafe impl<V: UniqueValue> UniqueValue for [V] {
    fn get_unique(&self) -> Option<&str> {
        if self.len() > 1 {
            None
        } else {
            self.first().and_then(V::get_unique)
        }
    }
}

unsafe impl<V: UniqueValue + ?Sized> UniqueValue for Box<V> {
    fn get_unique(&self) -> Option<&str> {
        (**self).get_unique()
    }
}

unsafe impl<V: UniqueValue + ?Sized> UniqueValue for Rc<V> {
    fn get_unique(&self) -> Option<&str> {
        (**self).get_unique()
    }
}

unsafe impl<V: UniqueValue + ?Sized> UniqueValue for Arc<V> {
    fn get_unique(&self) -> Option<&str> {
        (**self).get_unique()
    }
}

unsafe impl<V: UniqueValue> UniqueValue for Vec<V> {
    fn get_unique(&self) -> Option<&str> {
        if self.len() > 1 {
            None
        } else {
            self.first().and_then(V::get_unique)
        }
    }
}

mod test {
    use super::*;

    /// Compilation tests for various possible QueryParameter impls.
    #[allow(unused)]
    #[allow(dead_code)]
    fn test_query_parameter_impls() {
        let _ = (&HashMap::<String, String>::new()) as &dyn QueryParameter;
        let _ = (&HashMap::<&'static str, &'static str>::new()) as &dyn QueryParameter;
        let _ = (&HashMap::<Cow<'static, str>, Cow<'static, str>>::new()) as &dyn QueryParameter;

        let _ = (&HashMap::<String, Vec<String>>::new()) as &dyn QueryParameter;
        let _ = (&HashMap::<String, Box<String>>::new()) as &dyn QueryParameter;
        let _ = (&HashMap::<String, Box<[Cow<'static, str>]>>::new()) as &dyn QueryParameter;
    }
}
