//! Defines the Scope type and parsing/formatting according to the rfc.
use std::{cmp, fmt, str, error};

use std::collections::HashSet;
use serde::{Deserialize, Serialize};

/// Scope of a given grant or resource, a set of scope-tokens separated by spaces.
///
/// Scopes are interpreted as a conjunction of scope tokens, i.e. a scope is fulfilled if all of
/// its scope tokens are fulfilled.  This induces a partial ordering on scopes where scope `A`
/// is less or equal than scope `B` if all scope tokens of `A` are also found in `B`.  This can be
/// interpreted as the rule
/// > A token with scope `B` is allowed to access a resource requiring scope `A` iff `A <= B`
///
/// Example
/// ------
///
/// ```
/// # extern crate oxide_auth;
/// # use std::cmp;
/// # use oxide_auth::primitives::scope::Scope;
/// let grant_scope    = "some_scope other_scope".parse::<Scope>().unwrap();
/// let resource_scope = "some_scope".parse::<Scope>().unwrap();
/// let uncomparable   = "some_scope third_scope".parse::<Scope>().unwrap();
///
/// // Holding a grant with `grant_scope` allows access to the resource since:
/// assert!(resource_scope <= grant_scope);
/// assert!(resource_scope.allow_access(&grant_scope));
///
/// // But holders would not be allowed to access another resource with scope `uncomparable`:
/// assert!(!(uncomparable <= grant_scope));
/// assert!(!uncomparable.allow_access(&grant_scope));
///
/// // This would also not work the other way around:
/// assert!(!(grant_scope <= uncomparable));
/// assert!(!grant_scope.allow_access(&uncomparable));
/// ```
///
/// Scope-tokens are restricted to the following subset of ascii:
///   - The character '!'
///   - The character range '\x32' to '\x5b' which includes numbers and upper case letters
///   - The character range '\x5d' to '\x7e' which includes lower case letters
///
/// Individual scope-tokens are separated by spaces.
///
/// In particular, the characters '\x22' (`"`) and '\x5c' (`\`)  are not allowed.
///
#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    tokens: HashSet<String>,
}

impl Serialize for Scope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string: &str = Deserialize::deserialize(deserializer)?;
        core::str::FromStr::from_str(string).map_err(serde::de::Error::custom)
    }
}

impl Scope {
    fn invalid_scope_char(ch: char) -> bool {
        match ch {
            '\x21' => false,
            ch if ch >= '\x23' && ch <= '\x5b' => false,
            ch if ch >= '\x5d' && ch <= '\x7e' => false,
            ' ' => false, // Space seperator is a valid char
            _ => true,
        }
    }

    /// Determines if this scope has enough privileges to access some resource requiring the scope
    /// on the right side. This operation is equivalent to comparison via `>=`.
    pub fn priviledged_to(&self, rhs: &Scope) -> bool {
        rhs <= self
    }

    /// Determines if a resouce protected by this scope should allow access to a token with the
    /// grant on the right side. This operation is equivalent to comparison via `<=`.
    pub fn allow_access(&self, rhs: &Scope) -> bool {
        self <= rhs
    }

    /// Create an iterator over the individual scopes.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.tokens.iter().map(AsRef::as_ref)
    }
}

/// Error returned from parsing a scope as encoded in an authorization token request.
#[derive(Debug)]
pub enum ParseScopeErr {
    /// A character was encountered which is not allowed to appear in scope strings.
    ///
    /// Scope-tokens are restricted to the following subset of ascii:
    ///   - The character '!'
    ///   - The character range '\x32' to '\x5b' which includes numbers and upper case letters
    ///   - The character range '\x5d' to '\x7e' which includes lower case letters
    ///
    /// Individual scope-tokens are separated by spaces.
    ///
    /// In particular, the characters '\x22' (`"`) and '\x5c' (`\`)  are not allowed.
    InvalidCharacter(char),
}

impl error::Error for ParseScopeErr {}

impl str::FromStr for Scope {
    type Err = ParseScopeErr;

    fn from_str(string: &str) -> Result<Scope, ParseScopeErr> {
        if let Some(ch) = string.chars().find(|&ch| Scope::invalid_scope_char(ch)) {
            return Err(ParseScopeErr::InvalidCharacter(ch));
        }
        let tokens = string.split(' ').filter(|s| !s.is_empty());
        Ok(Scope {
            tokens: tokens.map(str::to_string).collect(),
        })
    }
}

impl fmt::Display for ParseScopeErr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            ParseScopeErr::InvalidCharacter(chr) => {
                write!(fmt, "Encountered invalid character in scope: {}", chr)
            }
        }
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_tuple("Scope").field(&self.tokens).finish()
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let output = self
            .tokens
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        fmt.write_str(&output)
    }
}

impl cmp::PartialOrd for Scope {
    fn partial_cmp(&self, rhs: &Self) -> Option<cmp::Ordering> {
        let intersect_count = self.tokens.intersection(&rhs.tokens).count();
        if intersect_count == self.tokens.len() && intersect_count == rhs.tokens.len() {
            Some(cmp::Ordering::Equal)
        } else if intersect_count == self.tokens.len() {
            Some(cmp::Ordering::Less)
        } else if intersect_count == rhs.tokens.len() {
            Some(cmp::Ordering::Greater)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parsing() {
        let scope = Scope {
            tokens: ["default", "password", "email"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        let formatted = scope.to_string();
        let parsed = formatted.parse::<Scope>().unwrap();
        assert_eq!(scope, parsed);

        let from_string = "email password default".parse::<Scope>().unwrap();
        assert_eq!(scope, from_string);
    }

    #[test]
    fn test_compare() {
        let scope_base = "cap1 cap2".parse::<Scope>().unwrap();
        let scope_less = "cap1".parse::<Scope>().unwrap();
        let scope_uncmp = "cap1 cap3".parse::<Scope>().unwrap();

        assert_eq!(scope_base.partial_cmp(&scope_less), Some(cmp::Ordering::Greater));
        assert_eq!(scope_less.partial_cmp(&scope_base), Some(cmp::Ordering::Less));

        assert_eq!(scope_base.partial_cmp(&scope_uncmp), None);
        assert_eq!(scope_uncmp.partial_cmp(&scope_base), None);

        assert_eq!(scope_base.partial_cmp(&scope_base), Some(cmp::Ordering::Equal));

        assert!(scope_base.priviledged_to(&scope_less));
        assert!(scope_base.priviledged_to(&scope_base));
        assert!(scope_less.allow_access(&scope_base));
        assert!(scope_base.allow_access(&scope_base));

        assert!(!scope_less.priviledged_to(&scope_base));
        assert!(!scope_base.allow_access(&scope_less));

        assert!(!scope_less.priviledged_to(&scope_uncmp));
        assert!(!scope_base.priviledged_to(&scope_uncmp));
        assert!(!scope_uncmp.allow_access(&scope_less));
        assert!(!scope_uncmp.allow_access(&scope_base));
    }

    #[test]
    fn test_iterating() {
        let scope = "cap1 cap2 cap3".parse::<Scope>().unwrap();
        let all = scope.iter().collect::<Vec<_>>();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&"cap1"));
        assert!(all.contains(&"cap2"));
        assert!(all.contains(&"cap3"));
    }

    #[test]
    fn deserialize_invalid_scope() {
        let scope = "\x22";
        let serialized = rmp_serde::to_vec(&scope).unwrap();
        let deserialized = rmp_serde::from_slice::<Scope>(&serialized);
        assert!(deserialized.is_err());
    }

    #[test]
    fn roundtrip_serialization_scope() {
        let scope = "cap1 cap2 cap3".parse::<Scope>().unwrap();
        let serialized = rmp_serde::to_vec(&scope).unwrap();
        let deserialized = rmp_serde::from_slice::<Scope>(&serialized).unwrap();
        assert_eq!(scope, deserialized);
    }
}
