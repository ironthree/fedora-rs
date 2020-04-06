use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use reqwest::header::{HeaderMap, HeaderValue, COOKIE};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct CookieCache {
    pub login_url: String,
    pub cookies: Vec<SimpleCookie>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SimpleCookie {
    name: String,
    value: String,
    expires: Option<DateTime<Utc>>,
}

impl CookieCache {
    pub fn new(login_url: String) -> CookieCache {
        CookieCache {
            login_url,
            cookies: Vec::new(),
        }
    }

    pub fn ingest_cookies(&mut self, response: &reqwest::blocking::Response) {
        for cookie in response.cookies() {
            let hashbrown = convert_cookie(cookie);

            let mut duplicate = false;
            for cached in &self.cookies {
                if cached.name == hashbrown.name && cached.value == hashbrown.value {
                    duplicate = true;
                    break;
                };
            }

            if !duplicate {
                self.cookies.push(hashbrown);
            }
        }
    }

    fn cache_path() -> Result<PathBuf, String> {
        let cache_dir = match dirs::cache_dir() {
            Some(path) => path,
            None => return Err(String::from("Unable to determine cache directory.")),
        };

        let cache_file = cache_dir.join("fedora-rs.json");

        Ok(cache_file)
    }

    pub fn from_cached() -> Result<CookieCache, String> {
        let cache_path = CookieCache::cache_path()?;

        let cache = match fs::read_to_string(&cache_path) {
            Ok(contents) => contents,
            Err(error) => return Err(format!("Failed to read cache file: {}", error)),
        };

        let cookie_cache: CookieCache = match serde_json::from_str(&cache) {
            Ok(result) => result,
            Err(error) => {
                return match fs::remove_file(&cache_path) {
                    Ok(_) => Err(format!("Cookie cache was corrupt and was deleted: {}", error)),
                    Err(second) => Err(format!(
                        "Cookie cache was corrupt ({}) but could not be deleted ({}).",
                        error, second
                    )),
                };
            },
        };

        Ok(cookie_cache)
    }

    pub fn write_cached(&self) -> Result<(), String> {
        let cache_path = CookieCache::cache_path()?;

        let contents = match serde_json::to_string_pretty(self) {
            Ok(result) => result,
            Err(error) => return Err(format!("Failed to write JSON data: {}", error)),
        };

        if let Err(error) = fs::write(cache_path, &contents) {
            Err(format!("Failed to write cookie cache to disk: {}", error))
        } else {
            Ok(())
        }
    }

    pub fn is_expired(&self) -> bool {
        let mut expired = false;
        let now = Utc::now();

        for cookie in &self.cookies {
            if let Some(expiration) = cookie.expires {
                if expiration <= now {
                    expired = true;
                    break;
                }
            }
        }

        expired
    }

    pub fn cookie_headers(&self) -> Result<HeaderMap, String> {
        let mut cookie_headers = HeaderMap::new();

        for cookie in &self.cookies {
            match HeaderValue::from_str(&format!("{}={}", cookie.name, cookie.value)) {
                Ok(value) => cookie_headers.append(COOKIE, value),
                Err(error) => return Err(format!("Failed to convert cookie into HTTP headers: {}", error)),
            };
        }

        Ok(cookie_headers)
    }
}

fn convert_cookie(cookie: reqwest::cookie::Cookie) -> SimpleCookie {
    let name = cookie.name().to_string();
    let value = cookie.value().to_string();

    let expires = match (cookie.max_age(), cookie.expires()) {
        (Some(max_age), _) => Some(Utc::now() + Duration::from_std(max_age).unwrap()),
        (None, Some(datetime)) => {
            let duration = datetime
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Cookie expiration date is before UNIX epoch - something went wrong here.");

            let epoch: DateTime<Utc> = "1970-01-01 00:00:00 UTC".parse().unwrap();
            Some(epoch + chrono::Duration::from_std(duration).unwrap())
        },
        (None, None) => None,
    };

    SimpleCookie { name, value, expires }
}
