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
    /// This method returns a reference to the wrapped [`reqwest::Client`]:
    ///
    /// ```
    /// # use fedora::Session;
    /// let session = Session::anonymous().build();
    /// let client: &reqwest::Client = session.session();
    /// ```
    pub fn session(&self) -> &Client {
        &self.client
    }

    /// This method returns a new builder for an anonymous session.
    ///
    /// ```
    /// # use fedora::Session;
    /// let anon_session: Session = Session::anonymous().build();
    /// ```
    pub fn anonymous<'a>() -> AnonymousSessionBuilder<'a> {
        AnonymousSessionBuilder::new()
    }

    /// This method returns a new builder for a session that will need to be authenticated via an
    /// OpenID provider.
    ///
    /// ```
    /// # use fedora::Session;
    /// use fedora::{OpenIDSessionKind, OpenIDSessionLogin};
    /// use url::Url;
    ///
    /// let login: OpenIDSessionLogin = Session::openid_auth(
    ///     Url::parse("https://bodhi.fedoraproject.org/login").unwrap(),
    ///     OpenIDSessionKind::Default
    /// ).build();
    pub fn openid_auth<'a>(login_url: Url, kind: OpenIDSessionKind) -> OpenIDSessionBuilder<'a> {
        OpenIDSessionBuilder::new(login_url, kind)
    }
}
