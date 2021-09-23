//! This module contains a session implementation with authentication via the fedora OpenID
//! provider.

mod cookies;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::session::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

use cookies::{CachingJar, CookieCacheError, CookieCacheState};

/// This is the OpenID authentication endpoint for "production" instances of
/// fedora services.
pub const FEDORA_OPENID_API: &str = "https://id.fedoraproject.org/api/v1/";

/// This is the OpenID authentication endpoint for "staging" instances of
/// fedora services.
pub const FEDORA_OPENID_STG_API: &str = "https://id.stg.fedoraproject.org/api/v1/";

/// This collection of errors is returned for various failure modes when setting
/// up a session authenticated via OpenID.
#[derive(Debug, thiserror::Error)]
pub enum OpenIDClientError {
    /// This error represents a network-related issue that occurred within
    /// [`reqwest`](https://docs.rs/reqwest).
    #[error("Failed to contact OpenID provider: {error}")]
    RequestError {
        /// The inner error contains the error passed from [`reqwest`](https://docs.rs/reqwest).
        error: reqwest::Error,
    },
    /// This error is returned when an input URL was invalid.
    #[error("Failed to parse redirection URL: {error}")]
    UrlParsingError {
        /// The inner error contains the error that occurred when parsing the invalid URL.
        error: url::ParseError,
    },
    /// This error is returned if a HTTP redirect was invalid.
    #[error("{error}")]
    RedirectionError {
        /// The inner error contains more details (failed to decode URL / missing URL from headers).
        error: String,
    },
    /// This error is returned for authentication-related issues.
    #[error("Failed to authenticate with OpenID service: {error}")]
    AuthenticationError {
        /// The inner error contains an explanation why the authentication request failed.
        error: String,
    },
    /// This error is returned when the JSON response from the OpenID endpoint
    /// was not in the standard format, or was missing expected values.
    #[error("Failed to deserialize JSON returned by OpenID endpoint: {error}")]
    DeserializationError {
        /// The inner error contains the deserialization error message from
        /// [`serde_json`](https://docs.rs/serde_json).
        error: serde_json::error::Error,
    },
    /// This error is returned when an error occurs during authentication,
    /// primarily due to wrong combinations of username and password.
    #[error("Authentication failed, possibly due to wrong username / password.")]
    LoginError,
}

impl From<reqwest::Error> for OpenIDClientError {
    fn from(error: reqwest::Error) -> Self {
        OpenIDClientError::RequestError { error }
    }
}

impl From<url::ParseError> for OpenIDClientError {
    fn from(error: url::ParseError) -> Self {
        OpenIDClientError::UrlParsingError { error }
    }
}

impl From<serde_json::error::Error> for OpenIDClientError {
    fn from(error: serde_json::error::Error) -> Self {
        OpenIDClientError::DeserializationError { error }
    }
}

/// This struct represents an OpenID endpoint's response after a successful authentication request.
#[derive(Debug, Deserialize)]
struct OpenIDResponse {
    success: bool,
    response: OpenIDParameters,
}

/// This struct contains the concrete OpenID parameters. They are currently unused, except for the
/// `openid.return_to` parameter.
#[allow(missing_docs)]
#[derive(Debug, Deserialize, Serialize)]
pub struct OpenIDParameters {
    #[serde(rename = "openid.assoc_handle")]
    pub assoc_handle: String,
    #[serde(rename = "openid.cla.signed_cla")]
    pub cla_signed_cla: String,
    #[serde(rename = "openid.claimed_id")]
    pub claimed_id: String,
    #[serde(rename = "openid.identity")]
    pub identity: String,
    #[serde(rename = "openid.lp.is_member")]
    pub lp_is_member: String,
    #[serde(rename = "openid.mode")]
    pub mode: String,
    #[serde(rename = "openid.ns")]
    pub ns: String,
    #[serde(rename = "openid.ns.cla")]
    pub ns_cla: String,
    #[serde(rename = "openid.ns.lp")]
    pub ns_lp: String,
    #[serde(rename = "openid.ns.sreg")]
    pub ns_sreg: String,
    #[serde(rename = "openid.op_endpoint")]
    pub op_endpoint: String,
    #[serde(rename = "openid.response_nonce")]
    pub response_nonce: String,
    /// This parameter is used to determine which URL to return to for completing a successful
    /// authentication flow.
    #[serde(rename = "openid.return_to")]
    pub return_to: String,
    #[serde(rename = "openid.sig")]
    pub sig: String,
    #[serde(rename = "openid.signed")]
    pub signed: String,
    #[serde(rename = "openid.sreg.email")]
    pub sreg_email: String,
    #[serde(rename = "openid.sreg.nickname")]
    pub sreg_nickname: String,

    /// This catch-all map contains all attributes that are not captured by the known parameters.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Use this builder to construct a custom session authenticated via OpenID. It implements the
/// [`Session`](../session/trait.Session.html) trait, like
/// [`AnonymousSession`](../anonymous/struct.AnonymousSession.html).
///
/// ```
/// # use url::Url;
/// # use std::time::Duration;
///
/// let builder = fedora::OpenIDSessionBuilder::default(
///     Url::parse("https://bodhi.fedoraproject.org/login").unwrap(),
///     "fedorauser",
///     "password12",
/// )
/// .timeout(Duration::from_secs(120))
/// .user_agent("rustdoc");
///
/// // let session = builder.build()?;
/// ```
#[derive(Debug)]
pub struct OpenIDSessionBuilder<'a> {
    auth_url: Url,
    login_url: Url,
    username: &'a str,
    password: &'a str,
    timeout: Option<Duration>,
    user_agent: Option<&'a str>,
}

impl<'a> OpenIDSessionBuilder<'a> {
    /// This method creates a new builder for the "production" instances of the fedora services.
    pub fn default(login_url: Url, username: &'a str, password: &'a str) -> Self {
        OpenIDSessionBuilder {
            auth_url: Url::parse(FEDORA_OPENID_API).unwrap(),
            login_url,
            username,
            password,
            timeout: None,
            user_agent: None,
        }
    }

    /// This method creates a new builder for the "staging" instances of the fedora services.
    pub fn staging(login_url: Url, username: &'a str, password: &'a str) -> Self {
        OpenIDSessionBuilder {
            auth_url: Url::parse(FEDORA_OPENID_STG_API).unwrap(),
            login_url,
            username,
            password,
            timeout: None,
            user_agent: None,
        }
    }

    /// This method creates a custom builder, where both authentication endpoint and login URL need
    /// to be specified manually.
    pub fn custom(auth_url: Url, login_url: Url, username: &'a str, password: &'a str) -> Self {
        OpenIDSessionBuilder {
            auth_url,
            login_url,
            username,
            password,
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

    /// This method consumes the builder and attempts to build the session, complete the
    /// authentication workflow, and return a session with all the necessary cookies and headers
    /// included.
    pub fn build(self) -> Result<OpenIDSession, OpenIDClientError> {
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
        let mut default_headers = HeaderMap::new();

        default_headers.append(USER_AGENT, HeaderValue::from_str(user_agent).unwrap());
        default_headers.append(ACCEPT, HeaderValue::from_str("application/json").unwrap());

        // try loading persistent cookie jar
        let jar: Option<CachingJar> = match CachingJar::read_from_disk() {
            Ok((jar, state)) => {
                if let CookieCacheState::Fresh = state {
                    // on-disk cache is fresh
                    Some(jar)
                } else {
                    // on-disk cache was expired
                    None
                }
            },
            Err(error) => {
                // fall back to empty cookie jar if either
                if let CookieCacheError::DoesNotExist = error {
                    // on-disk cache does not exist yet
                    log::info!("Creating new cookie cache.");
                } else {
                    // failed to deserialize on-disk cache
                    log::info!("Failed to load cached cookies: {}", error);
                }
                None
            },
        };

        if let Some(jar) = jar {
            // construct new client with default redirect handling, but keep all cookies
            let client: Client = Client::builder()
                .default_headers(default_headers)
                .cookie_store(true)
                .cookie_provider(Arc::new(jar))
                .timeout(timeout)
                .build()?;

            return Ok(OpenIDSession { client, params: None });
        } else {
            let jar = Arc::new(CachingJar::empty());

            // construct reqwest session for authentication with:
            // - custom default headers
            // - no-redirects policy
            let client: Client = Client::builder()
                .default_headers(default_headers.clone())
                .cookie_store(true)
                .cookie_provider(jar.clone())
                .timeout(timeout)
                .redirect(Policy::none())
                .build()?;

            // log in
            let mut url = self.login_url;
            let mut state: HashMap<String, String> = HashMap::new();

            // ask fedora OpenID system how to authenticate
            // follow redirects until the login form is reached to collect all parameters
            loop {
                let response = client.get(url.clone()).send()?;
                let status = response.status();

                #[cfg(feature = "debug")]
                dbg!(&response);

                // get and keep track of URL query arguments
                let args = url.query_pairs();

                for (key, value) in args {
                    state.insert(key.to_string(), value.to_string());
                }

                if status.is_redirection() {
                    // set next URL to redirect destination
                    let header: &HeaderValue = match response.headers().get("location") {
                        Some(value) => value,
                        None => {
                            return Err(OpenIDClientError::RedirectionError {
                                error: String::from("No redirect URL provided in HTTP redirect headers."),
                            });
                        },
                    };

                    let string = match header.to_str() {
                        Ok(string) => string,
                        Err(_) => {
                            return Err(OpenIDClientError::RedirectionError {
                                error: String::from("Failed to decode redirect URL."),
                            });
                        },
                    };

                    url = Url::parse(string)?;
                } else {
                    break;
                }
            }

            // insert username and password into the state / query
            state.insert("username".to_string(), self.username.to_string());
            state.insert("password".to_string(), self.password.to_string());

            // insert additional query arguments into the state / query
            state.insert("auth_module".to_string(), "fedoauth.auth.fas.Auth_FAS".to_string());
            state.insert("auth_flow".to_string(), "fedora".to_string());

            #[allow(clippy::or_fun_call)]
            state
                .entry("openid.mode".to_string())
                .or_insert("checkid_setup".to_string());

            // send authentication request
            let response = match client.post(self.auth_url).form(&state).send() {
                Ok(response) => response,
                Err(error) => {
                    return Err(OpenIDClientError::AuthenticationError {
                        error: error.to_string(),
                    })
                },
            };

            #[cfg(feature = "debug")]
            dbg!(&response);

            // the only indication that authenticating failed is a non-JSON response, or invalid message
            let string = response.text()?;
            let openid_auth: OpenIDResponse = match serde_json::from_str(&string) {
                Ok(value) => value,
                Err(_) => {
                    return Err(OpenIDClientError::LoginError);
                },
            };

            if !openid_auth.success {
                return Err(OpenIDClientError::AuthenticationError {
                    error: String::from("OpenID endpoint returned an error code."),
                });
            }

            let return_url = Url::parse(&openid_auth.response.return_to)?;

            let response = match client.post(return_url).form(&openid_auth.response).send() {
                Ok(response) => response,
                Err(error) => return Err(OpenIDClientError::RequestError { error }),
            };

            #[cfg(feature = "debug")]
            dbg!(&response);

            if !response.status().is_success() && !response.status().is_redirection() {
                #[cfg(feature = "debug")]
                println!("{}", &response.text()?);

                return Err(OpenIDClientError::AuthenticationError {
                    error: String::from("Failed to complete authentication with the original site."),
                });
            };

            if let Err(error) = jar.write_to_disk() {
                log::error!("Failed to write cached cookies: {}", error);
            }

            // construct new client with default redirect handling, but keep all cookies
            let client: Client = Client::builder()
                .default_headers(default_headers)
                .cookie_store(true)
                .cookie_provider(jar)
                .timeout(timeout)
                .build()?;

            Ok(OpenIDSession {
                client,
                params: Some(openid_auth.response),
            })
        }
    }
}

/// An session that contains cookies obtained by successfully authenticating via OpenID, which
/// implements the [`Session`](../session/trait.Session.html) trait, just like the
/// [`AnonymousSession`](../anonymous/struct.AnonymousSession.html). It currently only wraps a
/// `reqwest::blocking::Client`.
#[derive(Debug)]
pub struct OpenIDSession {
    client: Client,
    params: Option<OpenIDParameters>,
}

impl OpenIDSession {
    /// This method returns a reference to the [`OpenIDParameters`](struct.OpenIDParameters.html)
    /// that were returned by the OpenID endpoint after successful authentication.
    /// If no authentication was performed, because cached session cookies were not expired yet,
    /// then this method will return `None`.
    pub fn params(&self) -> Option<&OpenIDParameters> {
        self.params.as_ref()
    }
}

impl Session for OpenIDSession {
    fn session(&self) -> &Client {
        &self.client
    }
}
