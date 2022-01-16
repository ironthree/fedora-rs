//! This crate contains code that helps serve as the basis for interacting with fedora (web)
//! services and implementing other features on top of it.
//!
//! Currently, an implementation for OpenID authentication and a generic, anonymous,
//! unauthenticated session are available.

#![deny(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used)]

use std::time::Duration;

/// default value of the User-Agent HTTP header: "fedora-rs v2.0.0"
const FEDORA_USER_AGENT: &str = concat!("fedora-rs v", env!("CARGO_PKG_VERSION"));
/// default value of the request timeout duration
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

mod session;
pub use session::Session;

mod anonymous;
pub use anonymous::AnonymousSessionBuilder;

mod openid;
pub use openid::{OpenIDClientError, OpenIDSessionBuilder, OpenIDSessionKind, OpenIDSessionLogin};
