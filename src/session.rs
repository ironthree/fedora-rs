//! This module contains the definition of the [`Session`] type, and associated methods for building
//! anonymous or authenticated sessions.

use reqwest::Client;
use url::Url;

use crate::anonymous::AnonymousSessionBuilder;
use crate::openid::{OpenIDSessionBuilder, OpenIDSessionKind};

#[derive(Debug)]
/// This type is a thin newtype wrapper around [`reqwest::Client`] with implementations for
/// constructing both a generic / unauthenticated session, and a session pre-authenticated via
/// an OpenID provider.
pub struct Session {
    pub(crate) client: Client,
}

impl Session {
    /// This method returns a reference to the wrapped [`reqwest::Client`].
    pub fn session(&self) -> &Client {
        &self.client
    }

    /// This method returns a new builder for an anonymous session.
    pub fn anonymous<'a>() -> AnonymousSessionBuilder<'a> {
        AnonymousSessionBuilder::new()
    }

    /// This method returns a new builder for a session that will need to be authenticated via an
    /// OpenID provider.
    pub fn openid_auth<'a>(login_url: Url, kind: OpenIDSessionKind) -> OpenIDSessionBuilder<'a> {
        OpenIDSessionBuilder::new(login_url, kind)
    }
}
