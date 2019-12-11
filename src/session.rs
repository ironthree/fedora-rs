use reqwest::Client;

/// This trait is used to mark both `AnonymousSession` and `OpenIDSession`, so
/// they can be used interchangeably.
pub trait Session {
    fn session(&self) -> &Client;
}
