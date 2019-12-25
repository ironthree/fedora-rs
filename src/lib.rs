//! This module contains code that helps serve as the basis for interacting with fedora (web)
//! services and implementing other features on top of it.
//!
//! Currently, an implementation for OpenID authentication and an anonymous session are available.

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

use std::time::Duration;

const FEDORA_USER_AGENT: &str = "fedora-rs";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub mod session;
pub use session::Session;

pub mod anonymous;
pub use anonymous::{AnonymousSession, AnonymousSessionBuilder};

pub mod openid;
pub use openid::{OpenIDSession, OpenIDSessionBuilder};
