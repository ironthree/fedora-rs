use std::convert::From;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::sync::RwLock;

use bytes::Bytes;
use reqwest::cookie::CookieStore;
use reqwest::header::HeaderValue;
use reqwest::Url;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CookieCacheError {
    #[error("No existing cookie cache found.")]
    DoesNotExist,
    #[error("Failed to read cookie cache from disk.")]
    FileSystemError,
    #[error("Failed to (de)serialize cookie cache: {error}")]
    SerializationError { error: serde_json::Error },
}

impl From<serde_json::Error> for CookieCacheError {
    fn from(error: serde_json::Error) -> Self {
        Self::SerializationError { error }
    }
}

impl From<std::io::Error> for CookieCacheError {
    fn from(_: std::io::Error) -> Self {
        Self::FileSystemError
    }
}

fn get_cookie_cache_path() -> Result<PathBuf, CookieCacheError> {
    let home = dirs::home_dir().ok_or(CookieCacheError::FileSystemError)?;
    Ok(home.join(".fedora/fedora-rs-cookie-jar.json"))
}

// based on reqwest::cookie::Cookie::parse
fn parse_cookie(value: &HeaderValue) -> Result<cookie::Cookie, cookie::ParseError> {
    std::str::from_utf8(value.as_bytes())
        .map_err(cookie::ParseError::from)
        .and_then(cookie::Cookie::parse)
}

// based on reqwest::cookie::Jar
#[derive(Debug)]
pub(crate) struct CachingJar {
    store: RwLock<cookie_store::CookieStore>,
}

impl CachingJar {
    pub fn empty() -> CachingJar {
        CachingJar {
            store: RwLock::new(cookie_store::CookieStore::default()),
        }
    }

    pub fn read_from_disk() -> Result<CachingJar, CookieCacheError> {
        let path = get_cookie_cache_path()?;

        let contents = match read_to_string(path) {
            Ok(string) => Ok(string),
            Err(error) => {
                if let std::io::ErrorKind::NotFound = error.kind() {
                    Err(CookieCacheError::DoesNotExist)
                } else {
                    Err(error.into())
                }
            },
        }?;

        let store: cookie_store::CookieStore = serde_json::from_str(&contents)?;

        Ok(CachingJar {
            store: RwLock::new(store),
        })
    }

    pub fn write_to_disk(&self) -> Result<(), CookieCacheError> {
        let path = get_cookie_cache_path()?;
        let contents = serde_json::to_string_pretty(&self.store)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

impl CookieStore for CachingJar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &Url) {
        let iter = cookie_headers.filter_map(|val| parse_cookie(val).map(|cookie| cookie.into_owned()).ok());
        self.store.write().unwrap().store_response_cookies(iter, url);
    }

    fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let s = self
            .store
            .read()
            .unwrap()
            .get_request_cookies(url)
            .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
            .collect::<Vec<_>>()
            .join("; ");

        if s.is_empty() {
            return None;
        }

        HeaderValue::from_maybe_shared(Bytes::from(s)).ok()
    }
}
