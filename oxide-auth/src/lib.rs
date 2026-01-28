//! # oxide-auth
//!
//! An OAuth2 server library, for use in combination with actix-web or other front-ends, featuring a
//! set of configurable and pluggable back-ends.
//!
//! ## About
//!
//! `oxide-auth` aims at providing a comprehensive and extensible interface to managing OAuth2
//! tokens on a server. This depends on both a front-end facing web server for network operations
//! and a back-end implementation for policies and data storage. The main interface is designed
//! around traits in both directions, so that the front-end is as easily pluggable as the back-end.
//! There are many adaptations for specific web server crates (`actix`, `rocket`, `iron`,
//! `rouille`) in associated crates
//!
//! ## Create a web server with OAuth security
//!
//! So you want to build a new OAuth provider? Instead of only relying on tokens provided by other
//! large internet entities, you want to make your own tokens? Examples of this use case: A web
//! facing data portal, automation endpoints (in the style of Reddit or Discord), or even to
//! restrict the authorization of different components of your own software by applying these
//! techniques to your `REST`/`GraphQL`/.. back-end.
//!
//! Choose one of the available adaptor crates, a complete list can be found in the [`frontends`]
//! module, or translate the HTTP to the generic software endpoint found in [`frontends::simple`].
//!
//! Next, a set of [`primitives`] needs to be chosen. These will depend on the policies need for
//! Your use case but will in general encompass a [`Registrar`], an [`Authorizer`], and an
//! [`Issuer`]. There is a simple, in-memory implementation provided for each of those. More
//! complex solutions might require a customized trait implementation especially when specific
//! cryptographic standards or consistency requirements are needed. (It would be appreciated if
//! those were shared with the community as an open-source project, for example as a complementary
//! crate, but not mandatory).
//!
//! And finally, an implementation of an [`Endpoint`] is required, handling the request type that
//! has been chosen and forwarding it to the primitives. In very simple cases this can be an
//! instantiation of the [`Generic`] struct.  But for most complex cases it should instead be a
//! custom trait implementation that is tailored to Your specific requirements. Besides the
//! previously chosen primitives, the endpoint require You to choose two more interface: An
//! [`OwnerSolicitor`] to interact with Your session handling, user consent, and CSRF protection;
//! and the [`Scopes`] deciding required permissions for a request.
//!
//! ## Custom Front-Ends
//!
//! A key feature is the ability to add your own front-end without jeopardizing safety
//! requirements. For example to add your in-house server and request representation! This requires
//! custom, related implementations of [`WebRequest`] and [`WebResponse`]. In theory, you are not
//! even restricted to HTTP as long as the parameters can be transmitted safely. _WARNING_: Custom
//! front-ends MUST ensure a secure transportation layer with confidential clients. This means
//! using TLS for communication over HTTPS.
//!
//! For more information, see the documentation of [`endpoint`] and [`frontends`].
//!
//! [`WebRequest`]: code_grant/frontend/trait.WebRequest.html
//! [`WebResponse`]: code_grant/frontend/trait.WebResponse.html
//! [`endpoint`]: endpoint/index.html
//! [`Endpoint`]: endpoint/trait.Endpoint.html
//! [`frontends`]: frontends/index.html
//! [`frontends::simple`]: frontends/simple/index.html
//! [`Generic`]: frontends/simple/endpoint/struct.Generic.html
//! [`primitives`]: primitives/index.html
//! [`Registrar`]: primitives/registrar/trait.Registrar.html
//! [`Authorizer`]: primitives/authorizer/trait.Authorizer.html
//! [`Issuer`]: primitives/issuer/trait.Issuer.html
//! [`OwnerSolicitor`]: endpoint/trait.OwnerSolicitor.html
//! [`Scopes`]: endpoint/trait.Scopes.html
#![warn(missing_docs)]

pub mod code_grant;
pub mod endpoint;
pub mod frontends;
pub mod primitives;

/// An opaque error type used to avoid leaking sensitive information
#[derive(Debug)]
pub struct OAuthOpaqueError;
