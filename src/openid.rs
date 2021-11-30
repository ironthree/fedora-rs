mod cookies;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::Client;
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
    Request {
        /// The inner error contains the error passed from [`reqwest`](https://docs.rs/reqwest).
        #[from]
        error: reqwest::Error,
    },
    /// This error is returned when an input URL was invalid.
    #[error("Failed to parse redirection URL: {error}")]
    UrlParsing {
        /// The inner error contains the error that occurred when parsing the invalid URL.
        #[from]
        error: url::ParseError,
    },
    /// This error is returned if a HTTP redirect was invalid.
    #[error("{error}")]
    Redirection {
        /// The inner error contains more details (failed to decode URL / missing URL from headers).
        error: String,
    },
    /// This error is returned for authentication-related issues.
    #[error("Failed to authenticate with OpenID service: {error}")]
    Authentication {
        /// The inner error contains an explanation why the authentication request failed.
        error: String,
    },
    /// This error is returned when the JSON response from the OpenID endpoint
    /// was not in the standard format, or was missing expected values.
    #[error("Failed to deserialize JSON returned by OpenID endpoint: {error}")]
    Deserialization {
        /// The inner error contains the deserialization error message from
        /// [`serde_json`](https://docs.rs/serde_json).
        #[from]
        error: serde_json::error::Error,
    },
    /// This error is returned when an error occurs during authentication,
    /// primarily due to wrong combinations of username and password.
    #[error("Authentication failed, possibly due to wrong username / password.")]
    Login,
}

#[derive(Debug, Deserialize)]
struct OpenIDResponse {
    success: bool,
    response: OpenIDParameters,
}

#[derive(Debug, Deserialize, Serialize)]
struct OpenIDParameters {
    #[serde(rename = "openid.assoc_handle")]
    assoc_handle: String,
    #[serde(rename = "openid.cla.signed_cla")]
    cla_signed_cla: String,
    #[serde(rename = "openid.claimed_id")]
    claimed_id: String,
    #[serde(rename = "openid.identity")]
    identity: String,
    #[serde(rename = "openid.lp.is_member")]
    lp_is_member: String,
    #[serde(rename = "openid.mode")]
    mode: String,
    #[serde(rename = "openid.ns")]
    ns: String,
    #[serde(rename = "openid.ns.cla")]
    ns_cla: String,
    #[serde(rename = "openid.ns.lp")]
    ns_lp: String,
    #[serde(rename = "openid.ns.sreg")]
    ns_sreg: String,
    #[serde(rename = "openid.op_endpoint")]
    op_endpoint: String,
    #[serde(rename = "openid.response_nonce")]
    response_nonce: String,
    /// This parameter is used to determine which URL to return to for completing a successful
    /// authentication flow.
    #[serde(rename = "openid.return_to")]
    return_to: String,
    #[serde(rename = "openid.sig")]
    sig: String,
    #[serde(rename = "openid.signed")]
    signed: String,
    #[serde(rename = "openid.sreg.email")]
    sreg_email: String,
    #[serde(rename = "openid.sreg.nickname")]
    sreg_nickname: String,

    /// This catch-all map contains all attributes that are not captured by the known parameters.
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug)]
pub struct OpenIDSessionBuilder<'a> {
    login_url: Url,
    auth_url: Url,
    timeout: Option<Duration>,
    user_agent: Option<&'a str>,
}

#[derive(Debug)]
pub enum OpenIDSessionKind {
    Default,
    Staging,
    Custom { auth_url: Url },
}

impl<'a> OpenIDSessionBuilder<'a> {
    pub fn new(login_url: Url, kind: OpenIDSessionKind) -> Self {
        use OpenIDSessionKind::*;

        let auth_url = match kind {
            Default => Url::parse(FEDORA_OPENID_API).expect("Failed to parse a hardcoded URL, this should not happen."),
            Staging => {
                Url::parse(FEDORA_OPENID_STG_API).expect("Failed to parse a hardcoded URL, this should not happen.")
            },
            Custom { auth_url } => auth_url,
        };

        OpenIDSessionBuilder {
            login_url,
            auth_url,
            timeout: None,
            user_agent: None,
        }
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn user_agent(mut self, user_agent: &'a str) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn build(self) -> OpenIDSessionLogin {
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

        default_headers.append(
            USER_AGENT,
            HeaderValue::from_str(user_agent).expect("Failed to parse hardcoded HTTP headers, this should not happen."),
        );
        default_headers.append(
            ACCEPT,
            HeaderValue::from_str("application/json")
                .expect("Failed to parse hardcoded HTTP headers, this should not happen."),
        );

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

        OpenIDSessionLogin {
            login_url: self.login_url,
            auth_url: self.auth_url,
            headers: default_headers,
            timeout,
            jar,
        }
    }
}

#[derive(Debug)]
pub struct OpenIDSessionLogin {
    login_url: Url,
    auth_url: Url,
    headers: HeaderMap,
    timeout: Duration,
    jar: Option<CachingJar>,
}

impl OpenIDSessionLogin {
    pub async fn login(self, username: &str, password: &str) -> Result<Session, OpenIDClientError> {
        if let Some(jar) = self.jar {
            // write non-expired cookies back to disk
            if let Err(error) = jar.write_to_disk() {
                log::error!("Failed to write cached cookies: {}", error);
            }

            // construct new client with default redirect handling, but keep all cookies
            let client: Client = Client::builder()
                .default_headers(self.headers)
                .cookie_store(true)
                .cookie_provider(Arc::new(jar))
                .timeout(self.timeout)
                .build()
                .expect("Failed to initialize the network stack.");

            return Ok(Session { client });
        }

        let jar = Arc::new(CachingJar::empty());

        // construct reqwest session for authentication with:
        // - custom default headers
        // - no-redirects policy
        let client: Client = Client::builder()
            .default_headers(self.headers.clone())
            .cookie_store(true)
            .cookie_provider(jar.clone())
            .timeout(self.timeout)
            .redirect(Policy::none())
            .build()
            .expect("Failed to initialize the network stack.");

        // start log in process
        // TODO: verify URL, cross-reference with python-fedora
        let mut url = self.login_url;
        let mut state: HashMap<String, String> = HashMap::new();

        // ask fedora OpenID system how to authenticate
        // follow redirects until the login form is reached to collect all parameters
        loop {
            let response = client.get(url.clone()).send().await?;
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
                        return Err(OpenIDClientError::Redirection {
                            error: String::from("No redirect URL provided in HTTP redirect headers."),
                        });
                    },
                };

                let string = match header.to_str() {
                    Ok(string) => string,
                    Err(_) => {
                        return Err(OpenIDClientError::Redirection {
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
        state.insert("username".to_string(), username.to_string());
        state.insert("password".to_string(), password.to_string());

        // insert additional query arguments into the state / query
        state.insert("auth_module".to_string(), "fedoauth.auth.fas.Auth_FAS".to_string());
        state.insert("auth_flow".to_string(), "fedora".to_string());

        #[allow(clippy::or_fun_call)]
        state
            .entry("openid.mode".to_string())
            .or_insert("checkid_setup".to_string());

        // send authentication request
        // TODO: verify URL, cross-reference with python-fedora
        let response = match client.post(self.auth_url).form(&state).send().await {
            Ok(response) => response,
            Err(error) => {
                return Err(OpenIDClientError::Authentication {
                    error: error.to_string(),
                })
            },
        };

        #[cfg(feature = "debug")]
        dbg!(&response);

        // the only indication that authenticating failed is a non-JSON response, or invalid message
        let string = response.text().await?;
        let openid_auth: OpenIDResponse = match serde_json::from_str(&string) {
            Ok(value) => value,
            Err(_) => {
                return Err(OpenIDClientError::Login);
            },
        };

        if !openid_auth.success {
            return Err(OpenIDClientError::Authentication {
                error: String::from("OpenID endpoint returned an error code."),
            });
        }

        let return_url = Url::parse(&openid_auth.response.return_to)?;

        let response = match client.post(return_url).form(&openid_auth.response).send().await {
            Ok(response) => response,
            Err(error) => return Err(OpenIDClientError::Request { error }),
        };

        #[cfg(feature = "debug")]
        dbg!(&response);

        if !response.status().is_success() && !response.status().is_redirection() {
            #[cfg(feature = "debug")]
            println!("{}", &response.text().await?);

            return Err(OpenIDClientError::Authentication {
                error: String::from("Failed to complete authentication with the original site."),
            });
        };

        // write freshly baked cookies back to disk
        if let Err(error) = jar.write_to_disk() {
            log::error!("Failed to write cached cookies: {}", error);
        }

        // construct new client with default redirect handling, but keep all cookies
        let client: Client = Client::builder()
            .default_headers(self.headers)
            .cookie_store(true)
            .cookie_provider(jar)
            .timeout(self.timeout)
            .build()
            .expect("Failed to initialize the network stack.");

        Ok(Session { client })
    }
}
