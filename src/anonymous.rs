//! This module contains an anonymous session implementation providing the same interface as the
//! authenticated implementations of [`Session`](../session/trait.Session.html).

use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;

use crate::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

/// This error is returned if the initialization of a [`reqwest`](https://docs.rs/reqwest) session
/// fails.
#[derive(Debug, thiserror::Error)]
#[error("Failed to initialize session: {error}")]
pub struct InitialisationError {
    error: reqwest::Error,
}

impl From<reqwest::Error> for InitialisationError {
    fn from(error: reqwest::Error) -> Self {
        Self { error }
    }
}

/// Use this builder to construct a custom anonymous session that implements the
/// same [`Session`](../session/trait.Session.html) trait as the
/// [`OpenIDSession`](../openid/struct.OpenIDSession.html).
///
/// ```
/// let session = fedora::AnonymousSessionBuilder::new()
///     .timeout(std::time::Duration::from_secs(120))
///     .user_agent("rustdoc")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct AnonymousSessionBuilder<'a> {
    timeout: Option<Duration>,
    user_agent: Option<&'a str>,
}

impl<'a> AnonymousSessionBuilder<'a> {
    /// This method creates a new builder.
    pub fn new() -> Self {
        AnonymousSessionBuilder {
            timeout: None,
            user_agent: None,
        }
    }

    /// This method can be used to override the default request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// This method can be used to override the default request user agent.
    pub fn user_agent(mut self, user_agent: &'a str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// This method consumes the builder and attempts to build the session.
    pub fn build(self) -> Result<AnonymousSession, InitialisationError> {
        let timeout = match self.timeout {
            Some(timeout) => timeout,
            None => DEFAULT_TIMEOUT,
        };

        let user_agent = match self.user_agent {
            Some(user_agent) => user_agent,
            None => FEDORA_USER_AGENT,
        };

        // set default headers for our requests
        // - User Agent
        // - Accept: application/json
        let mut headers = HeaderMap::new();

        headers.insert(USER_AGENT, HeaderValue::from_str(user_agent).unwrap());

        headers.insert(ACCEPT, HeaderValue::from_str("application/json").unwrap());

        // construct reqwest session with:
        // - custom default headers
        // - no-redirects policy
        let client = Client::builder()
            .default_headers(headers)
            .cookie_store(true)
            .timeout(timeout)
            .redirect(Policy::none())
            .build()?;

        Ok(AnonymousSession { client })
    }
}

/// An anonymous session with slightly custom settings, and implementing the
/// same [`Session`](../session/trait.Session.html) Trait as the
/// [`OpenIDSession`](../openid/struct.OpenIDSession.html). It currently only wraps a
/// `reqwest::blocking::Client`.
#[derive(Debug)]
pub struct AnonymousSession {
    client: Client,
}

impl AnonymousSession {}

impl Session for AnonymousSession {
    fn session(&self) -> &Client {
        &self.client
    }
}
