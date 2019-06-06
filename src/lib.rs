//! This module contains utilities that serve as the basis for
//! interacting with fedora (web) services.

const FEDORA_USER_AGENT: &str = "fedora-rs";

pub mod openid;
pub use openid::{OpenIDClient, OpenIDClientBuilder};
