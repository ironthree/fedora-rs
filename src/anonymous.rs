use std::time::Duration;

use failure::Fail;
use reqwest::Client;

use crate::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

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

#[derive(Debug, Default)]
pub struct AnonymousSessionBuilder {
    timeout: Option<Duration>,
    user_agent: Option<String>,
}

impl AnonymousSessionBuilder {
    pub fn new() -> Self {
        AnonymousSessionBuilder {
            timeout: None,
            user_agent: None,
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

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
