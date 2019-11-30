//! This module contains utilities that serve as the basis for
//! interacting with fedora (web) services.
//!
//! Currently, only a work-in-progress implementation for OpenID authentication
//! is available.

const FEDORA_USER_AGENT: &str = "fedora-rs";

pub mod openid;
pub use openid::{OpenIDClient, OpenIDClientBuilder};
