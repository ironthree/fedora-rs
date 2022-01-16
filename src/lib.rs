//! This module contains code that helps serve as the basis for interacting with fedora (web)
//! services and implementing other features on top of it.
//!
//! Currently, an implementation for OpenID authentication and an anonymous session are available.

//#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used)]

use std::time::Duration;

const FEDORA_USER_AGENT: &str = concat!("fedora-rs v", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

mod session;
pub use session::Session;

mod anonymous;

mod openid;
pub use openid::{OpenIDClientError, OpenIDSessionKind};
