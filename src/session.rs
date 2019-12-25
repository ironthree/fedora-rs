//! This module contains the common interface definition for all session types.
//!
//! Currently, only a session with OpenID authentication and an anonymous session are implemented.

use reqwest::blocking::Client;

/// This trait is used to mark both `AnonymousSession` and `OpenIDSession`, so they can be used
/// interchangeably or dynamically.
pub trait Session {
    /// This method returs a reference to the wrapped [`reqwest`](https://docs.rs/reqwest) client.
    fn session(&self) -> &Client;
}
