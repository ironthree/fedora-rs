use std::io::{stdin, stdout, Write};

use fedora::OpenIDSessionBuilder;
use reqwest::Url;

fn main() -> Result<(), String> {
    let mut username = String::new();
    let mut password = String::new();

    print!("FAS username: ");
    stdout().flush().unwrap();
    if let Err(error) = stdin().read_line(&mut username) {
        return Err(error.to_string());
    }
    let username = username.trim().to_string();

    print!("FAS password: ");
    stdout().flush().unwrap();
    if let Err(error) = stdin().read_line(&mut password) {
        return Err(error.to_string());
    }
    let password = password.trim().to_string();

    let login_url = Url::parse("https://bodhi.fedoraproject.org/login").unwrap();

    let session = OpenIDSessionBuilder::default(login_url, &username, &password)
        .cache_cookies(true)
        .build();

    match session {
        Ok(_session) => {
            println!("Successfully logged in.");
            Ok(())
        },
        Err(error) => Err(format!("{}", error)),
    }
}
