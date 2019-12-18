use std::collections::HashMap;
use std::time::Duration;

use failure::Fail;
use reqwest::RedirectPolicy;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, USER_AGENT};
use serde::Deserialize;
use url::Url;

use crate::session::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

/// This is the OpenID authentication endpoint for "production" instances of
/// fedora services.
const FEDORA_OPENID_API: &str = "https://id.fedoraproject.org/api/v1/";

/// This is the OpenID authentication endpoint for "staging" instances of
/// fedora services.
const FEDORA_OPENID_STG_API: &str = "https://id.stg.fedoraproject.org/api/v1/";

/// This collection of errors is returned for various failure modes when setting
/// up a session authenticated via OpenID.
#[derive(Debug, Fail)]
pub enum OpenIDClientError {
    /// This error is returned for networking-related issues.
    #[fail(display = "Failed to contact OpenID provider: {}", error)]
    RequestError { error: reqwest::Error },
    /// This error is returned when an input URL was invalid.
    #[fail(display = "Failed to parse redirection URL: {}", error)]
    UrlParsingError { error: url::ParseError },
    /// This error is returned if a HTTP redirect was invalid.
    #[fail(display = "{}", error)]
    RedirectionError { error: String },
    /// This error is returned for authentication-related issues.
    #[fail(display = "Failed to authenticate with OpenID service: {}", error)]
    AuthenticationError { error: reqwest::Error },
    /// This error is returned when the JSON response from the OpenID endpoint
    /// was not in the standard format, or was missing expected values.
    #[fail(
        display = "Failed to deserialize JSON returned by OpenID endpoint: {}",
        error
    )]
    DeserializationError { error: serde_json::error::Error },
    /// This error is returned for various authentication flow issues.
    #[fail(display = "Failed to complete OpenID authentication flow: {}", error)]
    AuthenticationFlowError { error: String },
    /// This error is returned when an error occurs during authentication,
    /// primarily due to wrong combinations of username and password.
    #[fail(display = "Authentication failed, possibly due to wrong username / password.")]
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

/// This struct represents an OpenID endpoint's response after a successful
/// authentication request.
#[derive(Debug, Deserialize)]
struct OpenIDResponse {
    success: bool,
    response: HashMap<String, String>,
}

/// This struct contains the concrete OpenID parameters. They are currently
/// unused.
#[derive(Debug, Deserialize)]
struct OpenIDParameters {
    #[serde(rename(deserialize = "openid.ns.sreg"))]
    openid_ns_sreg: String,
    #[serde(rename(deserialize = "openid.mode"))]
    openid_mode: String,
    #[serde(rename(deserialize = "openid.sreg.nickname"))]
    openid_sreg_nickname: String,
    #[serde(rename(deserialize = "openid.claimed_id"))]
    openid_claimed_id: String,
    #[serde(rename(deserialize = "openid.sig"))]
    openid_sig: String,
    #[serde(rename(deserialize = "openid.return_to"))]
    openid_return_to: String,
    #[serde(rename(deserialize = "openid.signed"))]
    openid_signed: String,
    #[serde(rename(deserialize = "openid.cla.signed_cla"))]
    openid_cla_signed_cla: String,
    #[serde(rename(deserialize = "openid.assoc_handle"))]
    openid_assoc_handle: String,
    #[serde(rename(deserialize = "openid.sreg.email"))]
    openid_sreg_email: String,
    #[serde(rename(deserialize = "openid.ns"))]
    openid_ns: String,
    #[serde(rename(deserialize = "openid.lp.is_member"))]
    openid_lp_is_member: String,
    #[serde(rename(deserialize = "openid.ns.cla"))]
    openid_ns_cla: String,
    #[serde(rename(deserialize = "openid.response_nonce"))]
    openid_response_nonce: String,
    #[serde(rename(deserialize = "openid.op_endpoint"))]
    openid_op_endpoint: String,
    #[serde(rename(deserialize = "openid.ns.lp"))]
    openid_ns_lp: String,
    #[serde(rename(deserialize = "openid.identity"))]
    openid_identity: String,
}

/// Use this builder to construct a custom session authenticated via OpenID.
/// It implements the `Session` trait, like `AnonymousSession`.
///
/// ```
/// # use url::Url;
/// # use std::time::Duration;
///
/// let builder = fedora::OpenIDSessionBuilder::default(
///     Url::parse("https://bodhi.fedoraproject.org/login").unwrap(),
///     String::from("fedorauser"),
///     String::from("password12")
/// ).timeout(
///     Duration::from_secs(120)
/// ).user_agent(
///     String::from("rustdoc")
/// );
///
/// // let session = builder.build()?;
/// ```
#[derive(Debug)]
pub struct OpenIDSessionBuilder {
    auth_url: Url,
    login_url: Url,
    username: String,
    password: String,
    timeout: Option<Duration>,
    user_agent: Option<String>,
}

impl OpenIDSessionBuilder {
    /// This method creates a new builder for the "production" instances
    /// of the fedora services.
    pub fn default(login_url: Url, username: String, password: String) -> Self {
        OpenIDSessionBuilder {
            auth_url: Url::parse(FEDORA_OPENID_API).unwrap(),
            login_url,
            username,
            password,
            timeout: None,
            user_agent: None,
        }
    }

    /// This method creates a new builder for the "staging" instances
    /// of the fedora services.
    pub fn staging(login_url: Url, username: String, password: String) -> Self {
        OpenIDSessionBuilder {
            auth_url: Url::parse(FEDORA_OPENID_STG_API).unwrap(),
            login_url,
            username,
            password,
            timeout: None,
            user_agent: None,
        }
    }

    /// This method creates a custom builder, where both authentication endpoint
    /// and login URL need to be specified manually.
    pub fn custom(auth_url: Url, login_url: Url, username: String, password: String) -> Self {
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
    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// This method consumes the builder and attempts to build the session,
    /// complete the authentication workflow, and return a session with
    /// all the necessary cookies and headers included.
    pub fn build(self) -> Result<OpenIDSession, OpenIDClientError> {
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
        let mut default_headers = HeaderMap::new();

        default_headers.append(
            USER_AGENT,
            HeaderValue::from_str(&user_agent).unwrap(),
        );

        default_headers.append(
            ACCEPT,
            HeaderValue::from_str("application/json").unwrap(),
        );

        // construct reqwest session for authentication with:
        // - custom default headers
        // - no-redirects policy
        let client: Client = Client::builder()
            .default_headers(default_headers)
            .cookie_store(true)
            .timeout(timeout)
            .redirect(RedirectPolicy::none())
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
            {
                dbg!(&response);
            }

            // get and keep track of URL query arguments
            let args = url.query_pairs();

            for (key, value) in args {
                state.insert(key.to_string(), value.to_string());
            }

            if status.is_redirection() {
                // set next URL to redirect destination
                let header: &HeaderValue = match response.headers().get("location")
                {
                    Some(value) => value,
                    None => {
                        return Err(OpenIDClientError::RedirectionError {
                            error: String::from(
                                "No redirect URL provided in HTTP redirect headers.",
                            ),
                        });
                    }
                };

                let string = match header.to_str() {
                    Ok(string) => string,
                    Err(_) => {
                        return Err(OpenIDClientError::RedirectionError {
                            error: String::from("Failed to decode redirect URL."),
                        });
                    }
                };

                url = Url::parse(string)?;
            } else {
                break;
            }
        }

        // insert username and password into the state / query
        state.insert(String::from("username"), self.username);
        state.insert(String::from("password"), self.password);

        // insert additional query arguments into the state / query
        state.insert(
            String::from("auth_module"),
            String::from("fedoauth.auth.fas.Auth_FAS"),
        );

        state.insert(String::from("auth_flow"), String::from("fedora"));

        #[allow(clippy::or_fun_call)]
        state
            .entry(String::from("openid.mode"))
            .or_insert(String::from("checkid_setup"));

        // send authentication request
        let response = match client.post(self.auth_url).form(&state).send() {
            Ok(response) => response,
            Err(error) => return Err(OpenIDClientError::AuthenticationError { error }),
        };

        #[cfg(feature = "debug")]
        {
            dbg!(&response);
        }

        // the only indication that authenticating failed is a non-JSON response
        let string = response.text()?;
        let openid_auth: OpenIDResponse = match serde_json::from_str(&string) {
            Ok(value) => value,
            Err(_) => {
                return Err(OpenIDClientError::LoginError);
            }
        };

        if !openid_auth.success {
            return Err(OpenIDClientError::AuthenticationFlowError {
                error: String::from("OpenID endpoint returned an error code."),
            });
        }

        let return_url = match openid_auth.response.get("openid.return_to") {
            Some(return_to) => (Url::parse(return_to)?),
            None => return Err(OpenIDClientError::AuthenticationFlowError {
                error: String::from("OpenID endpoint returned an error code.") })
        };

        let response = match client.post(return_url).form(&openid_auth.response).send() {
            Ok(response) => response,
            Err(error) => return Err(OpenIDClientError::RequestError { error }),
        };

        #[cfg(feature = "debug")]
            {
                dbg!(&response);
            }

        if !response.status().is_success() && !response.status().is_redirection() {
            #[cfg(feature = "debug")]
            {
                println!("{}", &response.text()?);
            }

            return Err(OpenIDClientError::AuthenticationFlowError {
                error: String::from("Failed to complete authentication with the original site.")
            });
        };

        Ok(OpenIDSession { client })
    }
}

/// An session that contains cookies obtained by successfully authenticating
/// via OpenID, which implements the `Session` trait, just like the
/// `AnonymousSession`. It currently only wraps a `reqwest::blocking::Client`.
#[derive(Debug)]
pub struct OpenIDSession {
    client: Client,
}

impl OpenIDSession {}

impl Session for OpenIDSession {
    fn session(&self) -> &Client {
        &self.client
    }
}
