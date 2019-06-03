use std::collections::HashMap;

use reqwest::Url;

const FEDORA_OPENID_API: &str = "https://id.fedoraproject.org/api/v1/";
const FEDORA_USER_AGENT: &str = "fedora-rs";

pub struct OpenIDClient {
    pub session: reqwest::Client,
    login_url: String,
    user_agent: String,
}

impl OpenIDClient {
    pub fn new(base_url: String) -> OpenIDClient {
        // base URL ends with a slash by convention, so add it if it isn't there
        let base_url = if base_url.ends_with('/') {
            base_url
        } else {
            format!("{}/", base_url)
        };

        // by default, the login URL is just the base URL plus "/login"
        let login_url = Url::parse(&base_url)
            .unwrap()
            .join("/login")
            .unwrap()
            .as_str()
            .to_owned();

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
            .cookie_store(true)
            .redirect(reqwest::RedirectPolicy::none())
            .build()
            .unwrap();

        OpenIDClient {
            session,
            // base_url,
            login_url,
            user_agent: String::from(FEDORA_USER_AGENT),
        }
    }

    pub fn login_url(mut self, login_url: String) -> OpenIDClient {
        self.login_url = login_url;
        self
    }

    pub fn user_agent(mut self, user_agent: String) -> OpenIDClient {
        self.user_agent = user_agent;
        self
    }

    pub fn login(self, username: String, password: String) -> Result<(), String> {
        let mut url = self.login_url.clone();
        let mut state: HashMap<String, String> = HashMap::new();

        // ask fedora OpenID system how to authenticate
        // follow redirects until the "final destination" is reached
        loop {
            let response = match self.session.get(&url).send() {
                Ok(response) => response,
                Err(error) => {
                    return Err(format!("Failed to contact OpenID provider: {:?}", error))
                }
            };

            let status = response.status();

            // get and keep track of URL query arguments
            let query = Url::parse(&url).unwrap();
            let args = query.query_pairs();

            for (key, value) in args {
                state.insert(key.to_string(), value.to_string());
            }

            if status.is_redirection() {
                // set next URL to redirect destination
                url = response
                    .headers()
                    .get("location")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned();
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
            Err(error) => {
                return Err(format!("Failed to authenticate: {:#?}", error.status()));
            }
        };

        Ok(())
    }
}
