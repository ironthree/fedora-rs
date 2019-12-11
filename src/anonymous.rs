use std::time::Duration;

use failure::Fail;
use reqwest::Client;

use crate::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

/// This error is returned if the initialization of a `reqwest` session fails.
#[derive(Debug, Fail)]
#[fail(display = "Failed to initialize session: {}", error)]
pub struct InitialisationError {
    error: reqwest::Error,
}

impl From<reqwest::Error> for InitialisationError {
    fn from(error: reqwest::Error) -> Self {
        Self { error }
    }
}

/// Use this builder to construct a custom anonymous session that implements the
/// same `Session` trait as the `OpenIDSession`.
///
/// ```
/// let session = fedora::AnonymousSessionBuilder::new()
///     .timeout(std::time::Duration::from_secs(120))
///     .user_agent(String::from("rustdoc"))
///     .build().unwrap();
/// ```
#[derive(Debug, Default)]
pub struct AnonymousSessionBuilder {
    timeout: Option<Duration>,
    user_agent: Option<String>,
}

impl AnonymousSessionBuilder {
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
    pub fn user_agent(mut self, user_agent: String) -> Self {
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
            None => String::from(FEDORA_USER_AGENT),
        };

        // set default headers for our requests
        // - User Agent
        // - Accept: application/json
        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&user_agent).unwrap(),
        );

        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_str("application/json").unwrap(),
        );

        // construct reqwest session with:
        // - custom default headers
        // - no-redirects policy
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .redirect(reqwest::RedirectPolicy::none())
            .build()?;

        Ok(AnonymousSession { client })
    }
}

/// An anonymous session with slightly custom settings, and implementing the
/// same `Session` Trait as the `OpenIDSession`. It currently only wraps a
/// `reqwest::Client`.
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
