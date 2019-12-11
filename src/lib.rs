//! This module contains utilities that serve as the basis for
//! interacting with fedora (web) services.
//!
//! Currently, only a work-in-progress implementation for OpenID authentication
//! and an anonymous session is available.

use std::time::Duration;

const FEDORA_USER_AGENT: &str = "fedora-rs";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub mod session;
pub use session::Session;

pub mod anonymous;
pub use anonymous::{AnonymousSession, AnonymousSessionBuilder};

pub mod openid;
pub use openid::{OpenIDSession, OpenIDSessionBuilder};
