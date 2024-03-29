use std::io::{stdin, stdout, Write};

use fedora::{OpenIDSessionKind, Session};
use reqwest::Url;

fn prompt_username() -> String {
    let mut username = String::new();

    print!("FAS username: ");
    stdout().flush().unwrap();
    stdin().read_line(&mut username).unwrap();

    username.trim().to_string()
}

fn prompt_password() -> String {
    rpassword::prompt_password("FAS password: ").unwrap()
}

#[tokio::main]
async fn main() -> Result<(), String> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    // read username and password from stdin
    let username = prompt_username();
    let password = prompt_password();

    let login_url = Url::parse("https://bodhi.stg.fedoraproject.org/login?method=openid").unwrap();

    let login = Session::openid_auth(login_url, OpenIDSessionKind::Staging).build();
    let session = login.login(&username, &password).await;

    match session {
        Ok(_session) => {
            println!("Successfully logged in.");
            Ok(())
        },
        Err(error) => Err(error.to_string()),
    }
}
