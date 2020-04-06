use failure::Fail;

/// This collection of errors is returned for various failure modes when setting
/// up a session authenticated via OpenID.
#[derive(Debug, Fail)]
pub enum OpenIDClientError {
    /// This error represents a network-related issue that occurred within
    /// [`reqwest`](https://docs.rs/reqwest).
    #[fail(display = "Failed to contact OpenID provider: {}", error)]
    RequestError {
        /// The inner error contains the error passed from [`reqwest`](https://docs.rs/reqwest).
        error: reqwest::Error,
    },
    /// This error is returned when an input URL was invalid.
    #[fail(display = "Failed to parse redirection URL: {}", error)]
    UrlParsingError {
        /// The inner error contains the error that occurred when parsing the invalid URL.
        error: url::ParseError,
    },
    /// This error is returned if a HTTP redirect was invalid.
    #[fail(display = "{}", error)]
    RedirectionError {
        /// The inner error contains more details (failed to decode URL / missing URL from headers).
        error: String,
    },
    /// This error is returned for authentication-related issues.
    #[fail(display = "Failed to authenticate with OpenID service: {}", error)]
    AuthenticationError {
        /// The inner error contains an explanation why the authentication request failed.
        error: String,
    },
    /// This error is returned when the JSON response from the OpenID endpoint
    /// was not in the standard format, or was missing expected values.
    #[fail(display = "Failed to deserialize JSON returned by OpenID endpoint: {}", error)]
    DeserializationError {
        /// The inner error contains the deserialization error message from
        /// [`serde_json`](https://docs.rs/serde_json).
        error: serde_json::error::Error,
    },
    /// This error is returned when an error occurs during authentication,
    /// primarily due to wrong combinations of username and password.
    #[fail(display = "Authentication failed, possibly due to wrong username / password.")]
    LoginError,
    /// This error is returned when an error occurs during usage of the on-disk
    /// cookie cache (either it's invalid, or it's expired).
    #[fail(display = "Failed to use on-disk cookie cache.")]
    CookieCacheError { message: String },
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
