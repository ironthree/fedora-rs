//! This module contains a session implementation with authentication via the fedora OpenID
//! provider.

use std::collections::HashMap;
use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use url::Url;

use crate::session::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

mod cookie_cache;
use cookie_cache::CookieCache;

mod error;
pub use error::OpenIDClientError;

mod parameters;
use parameters::{OpenIDParameters, OpenIDResponse};

/// This is the OpenID authentication endpoint for "production" instances of
/// fedora services.
pub const FEDORA_OPENID_API: &str = "https://id.fedoraproject.org/api/v1/";

/// This is the OpenID authentication endpoint for "staging" instances of
/// fedora services.
pub const FEDORA_OPENID_STG_API: &str = "https://id.stg.fedoraproject.org/api/v1/";

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
    cache_cookies: bool,
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
            cache_cookies: false,
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
            cache_cookies: false,
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
            cache_cookies: false,
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

    /// This method can be used to make the session cache cookies on disk.
    pub fn cache_cookies(mut self, cache_cookies: bool) -> Self {
        self.cache_cookies = cache_cookies;
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

        default_headers.append(USER_AGENT, HeaderValue::from_str(&user_agent).unwrap());
        default_headers.append(ACCEPT, HeaderValue::from_str("application/json").unwrap());

        // take the shortcut if cookies have been stored already
        match CookieCache::from_cached() {
            // cookie cache successfully loaded
            Ok(cookies) => {
                if let Ok(session) =
                    session_from_cookie_cache(&cookies, self.login_url.to_string(), default_headers.clone(), timeout)
                {
                    // cookie cache is valid and not expired
                    return Ok(OpenIDSession {
                        client: session,
                        params: None,
                    });
                }
            },
            // failed to load cookie cache
            Err(error) => println!("{}", error),
        };

        // construct reqwest session for authentication with:
        // - custom default headers
        // - no-redirects policy
        let client: Client = Client::builder()
            .default_headers(default_headers)
            .cookie_store(true)
            .timeout(timeout)
            .redirect(Policy::none())
            .build()?;

        // log in
        let mut url = self.login_url;
        let mut state: HashMap<String, String> = HashMap::new();
        let mut cookie_cache = CookieCache::new(url.to_string());

        // ask fedora OpenID system how to authenticate
        // follow redirects until the login form is reached to collect all parameters
        loop {
            let response = client.get(url.clone()).send()?;
            let status = response.status();

            cookie_cache.ingest_cookies(&response);

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

        if !response.status().is_success() && !response.status().is_redirection() {
            return Err(OpenIDClientError::AuthenticationError {
                error: String::from("Failed to complete authentication with the original site."),
            });
        };

        if self.cache_cookies {
            if let Err(error) = cookie_cache.write_cached() {
                println!("{}", error);
            }
        };

        Ok(OpenIDSession {
            client,
            params: Some(openid_auth.response),
        })
    }
}

fn session_from_cookie_cache(
    cookie_cache: &CookieCache,
    login_url: String,
    default_headers: HeaderMap,
    timeout: std::time::Duration,
) -> Result<Client, OpenIDClientError> {
    if cookie_cache.login_url != login_url {
        return Err(OpenIDClientError::CookieCacheError {
            message: String::from("Login URLs don't match. Not reusing cached cookies."),
        });
    };

    if cookie_cache.is_expired() {
        return Err(OpenIDClientError::CookieCacheError {
            message: String::from("Cookies are expired."),
        });
    };

    let mut cookie_headers = match cookie_cache.cookie_headers() {
        Ok(headers) => headers,
        Err(_) => {
            return Err(OpenIDClientError::CookieCacheError {
                message: String::from("Failed to construct cookie headers."),
            })
        },
    };

    cookie_headers.extend(default_headers);

    // construct reqwest session for authentication with:
    // - custom default headers
    // - no-redirects policy
    let client: Client = Client::builder()
        .default_headers(cookie_headers)
        .cookie_store(true)
        .timeout(timeout)
        .redirect(Policy::none())
        .build()?;

    Ok(client)
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
    pub fn params(&self) -> Option<&OpenIDParameters> {
        self.params.as_ref()
    }
}

impl Session for OpenIDSession {
    fn session(&self) -> &Client {
        &self.client
    }
}
