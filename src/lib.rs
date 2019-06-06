//! This module contains utilities that serve as the basis for
//! interacting with fedora (web) services.

use std::collections::HashMap;
use std::time::Duration;

use failure::Fail;
use reqwest::Url;

const FEDORA_OPENID_API: &str = "https://id.fedoraproject.org/api/v1/";
const FEDORA_USER_AGENT: &str = "fedora-rs";

/// This struct encapsulates all options that are needed to construct the actual
/// `OpenIDClient` instance.
#[derive(Debug)]
pub struct OpenIDClientBuilder {
    login_url: Url,
    timeout: Option<Duration>,
    user_agent: Option<String>,
}

#[derive(Debug, Fail)]
#[fail(display = "Failed to initialize session: {}", error)]
pub struct BuilderError {
    error: reqwest::Error,
}

impl From<reqwest::Error> for BuilderError {
    fn from(error: reqwest::Error) -> Self {
        Self { error }
    }
}

impl OpenIDClientBuilder {
    /// This method is used to create a new `OpenIDClientBuilder` instance.
    /// Since the login URL is necessary in every case, it has to be supplied
    /// here.
    pub fn new(login_url: Url) -> Self {
        OpenIDClientBuilder {
            login_url,
            timeout: None,
            user_agent: None,
        }
    }

    /// This method can be used to override the default request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// This method can be used to override the default user agent.
    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// This method tries to construct the actual `OpenIDClient` instance with
    /// the supplied settings.
    ///
    /// If everything works as expected, an `Ok(OpenIDClient)` is returned,
    /// and an explanatory `Err(String)` otherwise.
    pub fn build(self) -> Result<OpenIDClient, BuilderError> {
        let timeout = match self.timeout {
            Some(timeout) => timeout,
            None => Duration::from_secs(60),
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
            reqwest::header::HeaderValue::from_str(FEDORA_USER_AGENT).unwrap(),
        );

        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_str("application/json").unwrap(),
        );

        // construct reqwest session with:
        // - custom default headers
        // - cookie store enabled
        // - no-redirects policy
        let session = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .cookie_store(true)
            .redirect(reqwest::RedirectPolicy::none())
            .build()?;

        Ok(OpenIDClient {
            session,
            login_url: self.login_url,
            user_agent,
            authenticated: false,
        })
    }
}

/// The `OpenIDClient` provides a way to authenticate with the OpenID
/// service that fedora provides - which is required for sending authenticated
/// requests to some of the fedora web services.
#[derive(Debug)]
pub struct OpenIDClient {
    session: reqwest::Client,
    login_url: Url,
    user_agent: String,
    authenticated: bool,
}

#[derive(Debug, Fail)]
pub enum ClientError {
    #[fail(display = "Failed to contact OpenID provider: {}", error)]
    RequestError { error: reqwest::Error },
    #[fail(display = "Failed to parse redirection URL: {}", error)]
    UrlParsingError { error: reqwest::UrlError },
    #[fail(display = "{}", error)]
    RedirectionError { error: String },
    #[fail(display = "Failed to authenticate with OpenID service: {}", error)]
    AuthenticationError { error: reqwest::Error },
}

impl From<reqwest::Error> for ClientError {
    fn from(error: reqwest::Error) -> Self {
        ClientError::RequestError { error }
    }
}

impl From<reqwest::UrlError> for ClientError {
    fn from(error: reqwest::UrlError) -> Self {
        ClientError::UrlParsingError { error }
    }
}

impl OpenIDClient {
    /// This method does the hard work of doing the authentication dance by
    /// querying the OpenID service for the required arguments, traverses
    /// several redirects, and constructs and sends the resulting authentication
    /// request to the fedora OpenID endpoint.
    ///
    /// It returns `Ok(())` in case the requests worked as intended, and returns
    /// an `Err(String)` if something went wrong.
    pub fn login(&mut self, username: String, password: String) -> Result<(), ClientError> {
        let mut url = self.login_url.clone();
        let mut state: HashMap<String, String> = HashMap::new();

        // ask fedora OpenID system how to authenticate
        // follow redirects until the "final destination" is reached
        loop {
            let response = self.session.get(url.clone()).send()?;
            let status = response.status();

            // get and keep track of URL query arguments
            let args = url.query_pairs();

            for (key, value) in args {
                state.insert(key.to_string(), value.to_string());
            }

            if status.is_redirection() {
                // set next URL to redirect destination
                let header: &reqwest::header::HeaderValue = match response
                    .headers().get("location") {
                    Some(value) => value,
                    None => return Err(ClientError::RedirectionError {
                        error: String::from("No redirect URL provided in HTTP redirect headers.")
                    }),
                };

                let string = match header.to_str() {
                    Ok(string) => string,
                    Err(_) => return Err(ClientError::RedirectionError {
                        error: String::from("Failed to decode redirect URL.")
                    }),
                };

                url = Url::parse(string)?;
            } else {
                // final destination reached
                break;
            }
        }

        // insert username and password into the state / query
        state.insert(String::from("username"), username);
        state.insert(String::from("password"), password);

        // insert additional query arguments into the state / query
        state.insert(
            String::from("auth_module"),
            String::from("fedoauth.auth.fas.Auth_FAS"),
        );
        state.insert(String::from("auth_flow"), String::from("fedora"));

        if !state.contains_key("openid.mode") {
            state.insert(String::from("openid.mode"), String::from("checkid_setup"));
        }

        // send authentication request
        let mut _response = match self.session.post(FEDORA_OPENID_API).form(&state).send() {
            Ok(response) => response,
            Err(error) => return Err(ClientError::AuthenticationError { error }),
        };

        self.authenticated = true;
        Ok(())
    }

    /// This method can be used to determine whether a user has successfully
    /// authenticated with the fedora OpenID service yet.
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// This method returns a reference to a `reqwest::Client` instance that
    /// can be used to send requests.
    pub fn session(&self) -> &reqwest::Client {
        &self.session
    }
}
