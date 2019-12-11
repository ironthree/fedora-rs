use std::collections::HashMap;
use std::time::Duration;

use cookie::CookieJar;
use failure::Fail;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Url};
use serde::Deserialize;

use crate::session::Session;
use crate::{DEFAULT_TIMEOUT, FEDORA_USER_AGENT};

const FEDORA_OPENID_API: &str = "https://id.fedoraproject.org/api/v1/";
const FEDORA_OPENID_STG_API: &str = "https://id.fedoraproject.org/api/v1/";

#[derive(Debug, Fail)]
pub enum OpenIDClientError {
    #[fail(display = "Failed to contact OpenID provider: {}", error)]
    RequestError { error: reqwest::Error },
    #[fail(display = "Failed to parse redirection URL: {}", error)]
    UrlParsingError { error: reqwest::UrlError },
    #[fail(display = "{}", error)]
    RedirectionError { error: String },
    #[fail(display = "Failed to authenticate with OpenID service: {}", error)]
    AuthenticationError { error: reqwest::Error },
    #[fail(
        display = "Failed to deserialize JSON returned by OpenID endpoint: {}",
        error
    )]
    DeserializationError { error: serde_json::error::Error },
    #[fail(display = "Failed to complete OpenID authentication flow: {}", error)]
    AuthenticationFlowError { error: String },
    #[fail(display = "Authentication failed, possibly due to wrong username / password.")]
    LoginError,
}

impl From<reqwest::Error> for OpenIDClientError {
    fn from(error: reqwest::Error) -> Self {
        OpenIDClientError::RequestError { error }
    }
}

impl From<reqwest::UrlError> for OpenIDClientError {
    fn from(error: reqwest::UrlError) -> Self {
        OpenIDClientError::UrlParsingError { error }
    }
}

impl From<serde_json::error::Error> for OpenIDClientError {
    fn from(error: serde_json::error::Error) -> Self {
        OpenIDClientError::DeserializationError { error }
    }
}

#[derive(Debug, Deserialize)]
struct OpenIDResponse {
    success: bool,
    response: HashMap<String, String>,
}

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

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

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
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&user_agent).unwrap(),
        );

        default_headers.append(
            reqwest::header::ACCEPT,
            HeaderValue::from_str("application/json").unwrap(),
        );

        // construct reqwest session for authentication with:
        // - custom default headers
        // - no-redirects policy
        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(timeout)
            .redirect(reqwest::RedirectPolicy::none())
            .build()?;

        // log in
        let mut url = self.login_url.clone();
        let mut cookies = CookieJar::new();
        let mut headers = HeaderMap::new();
        let mut state: HashMap<String, String> = HashMap::new();

        // ask fedora OpenID system how to authenticate
        // follow redirects until the login form is reached to collect all parameters
        loop {
            #[cfg(feature = "debug")] { dbg!(&headers); }

            let response = client.get(url.clone()).headers(headers.clone()).send()?;
            let status = response.status();

            #[cfg(feature = "debug")] { dbg!(&response); }

            // get and keep track of URL query arguments
            let args = url.query_pairs();

            for (key, value) in args {
                state.insert(key.to_string(), value.to_string());
            }

            for cookie in response.cookies() {
                let new = cookie::Cookie::new(cookie.name().to_owned(), cookie.value().to_owned());

                headers.append(
                    reqwest::header::COOKIE,
                    HeaderValue::from_str(&new.to_string()).unwrap(),
                );

                cookies.add(new);
            }

            if status.is_redirection() {
                // set next URL to redirect destination
                let header: &reqwest::header::HeaderValue = match response.headers().get("location")
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

        #[cfg(feature = "debug")] { dbg!(&headers); }

        // send authentication request
        let mut response = match client
            .post(self.auth_url)
            .form(&state)
            .headers(headers.clone())
            .send()
        {
            Ok(response) => response,
            Err(error) => return Err(OpenIDClientError::AuthenticationError { error }),
        };

        #[cfg(feature = "debug")] { dbg!(&response); }

        for cookie in response.cookies() {
            let new = cookie::Cookie::new(cookie.name().to_owned(), cookie.value().to_owned());

            headers.append(
                reqwest::header::COOKIE,
                HeaderValue::from_str(&new.to_string()).unwrap(),
            );

            cookies.add(new);
        }

        let string = response.text()?;

        // the only indication that authenticating failed is a non-JSON response
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

        // construct a new, clean session with all the necessary cookies
        let mut default_headers = HeaderMap::new();

        default_headers.append(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&user_agent).unwrap(),
        );

        default_headers.append(
            reqwest::header::ACCEPT,
            HeaderValue::from_str("application/json").unwrap(),
        );

        for (header_name, header_value) in headers.into_iter() {
            if let Some(header_name) = header_name {
                default_headers.append(header_name, header_value);
            }
        }

        let client = reqwest::Client::builder()
            .default_headers(default_headers)
            .timeout(timeout)
            .build()?;

        Ok(OpenIDSession { client })
    }
}

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
