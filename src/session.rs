use reqwest::Client;

pub trait Session {
    fn session(&self) -> &Client;
}
