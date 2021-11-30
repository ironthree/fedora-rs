use reqwest::Client;
use url::Url;

use crate::anonymous::AnonymousSessionBuilder;
use crate::openid::{OpenIDSessionBuilder, OpenIDSessionKind};

#[derive(Debug)]
pub struct Session {
    pub(crate) client: Client,
}

impl Session {
    pub fn session(&self) -> &Client {
        &self.client
    }

    pub fn anonymous<'a>() -> AnonymousSessionBuilder<'a> {
        AnonymousSessionBuilder::new()
    }

    pub fn openid_auth<'a>(login_url: Url, kind: OpenIDSessionKind) -> OpenIDSessionBuilder<'a> {
        OpenIDSessionBuilder::new(login_url, kind)
    }
}
