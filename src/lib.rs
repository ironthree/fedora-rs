//! This crate contains code that helps serve as the basis for interacting with Fedora (web)
//! services and implementing other features or API bindings on top of it.
//!
//! Currently, an implementation for OpenID authentication against one of the Fedora Project
//! OpenID providers and a generic, anonymous, unauthenticated session are available.

#![deny(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used)]

use std::time::Duration;

/// default value of the User-Agent HTTP header: `fedora-rs v$CARGO_PKG_VERSION`
const FEDORA_USER_AGENT: &str = concat!("fedora-rs v", env!("CARGO_PKG_VERSION"));
/// default value of the request timeout duration
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

mod session;
pub use session::Session;

mod anonymous;
pub use anonymous::AnonymousSessionBuilder;

mod openid;
pub use openid::{OpenIDClientError, OpenIDSessionBuilder, OpenIDSessionKind, OpenIDSessionLogin};

// re-export reqwest and url, they are part of the public API
pub use reqwest;
pub use url;

/// release notes for all versions of this crate
#[doc = include_str!("../CHANGELOG.md")]
#[cfg(doc)]
#[allow(unused_imports)]
pub mod changelog {
    // includes for intra-doc links
    use super::Session;
}
