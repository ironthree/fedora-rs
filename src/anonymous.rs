//! This module contains an implementation for building anonymous [`Session`]s.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::Client;

use crate::session::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

/// This type encapsulates the (optional) arguments that are required for building an anonymous
/// session.
#[derive(Debug, Default)]
pub struct AnonymousSessionBuilder<'a> {
    /// optional override of the default timeout duration
    timeout: Option<Duration>,
    /// optional override of the default User-Agent header
    user_agent: Option<&'a str>,
}

impl<'a> AnonymousSessionBuilder<'a> {
    /// This method constructs a new [`AnonymousSessionBuilder`] instance.
    pub fn new() -> Self {
        AnonymousSessionBuilder {
            timeout: None,
            user_agent: None,
        }
    }

    /// Override the default request timeout duration.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Override the default User-Agent header.
    #[must_use]
    pub fn user_agent(mut self, user_agent: &'a str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// This method consumes the [`AnonymousSessionBuilder`] and returns a [`Session`] with
    /// custom timeout and User-Agent header settings.
    pub fn build(self) -> Session {
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

        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(user_agent).expect("Failed to parse hardcoded HTTP headers, this should not happen."),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_str("application/json")
                .expect("Failed to parse hardcoded HTTP headers, this should not happen."),
        );

        // construct reqwest session with:
        // - custom default headers
        // - no-redirects policy
        let client = Client::builder()
            .default_headers(headers)
            .cookie_store(true)
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .expect("Failed to initialize the network stack.");

        Session { client }
    }
}
