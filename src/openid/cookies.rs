//! This module contains a simple cookie jar implementation based on the implementation from
//! [`reqwest::cookie::Jar`], extended with functions to persist it as a file on disk.

use std::convert::From;
use std::fs::read_to_string;
use std::path::PathBuf;
use std::sync::RwLock;

use bytes::Bytes;
use reqwest::cookie::CookieStore;
use reqwest::header::HeaderValue;
use reqwest::Url;

/// This error describes the types of error that can occur when loading cached session cookies from
/// disk.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CookieCacheError {
    /// No on-disk cookie cache exists at the existed path yet.
    #[error("No existing cookie cache found.")]
    DoesNotExist,
    /// An error occurred while attempting to read on-disk cookie cache.
    #[error("Failed to read cookie cache from disk.")]
    FileSystemError,
    /// An error occurred while (de)serializing the cookie cache to / from JSON.
    #[error("Failed to (de)serialize cookie cache: {error}")]
    SerializationError {
        #[from]
        error: serde_json::Error,
    },
}

impl From<std::io::Error> for CookieCacheError {
    fn from(_: std::io::Error) -> Self {
        Self::FileSystemError
    }
}

/// This helper function constructs the path to the default location for the on-disk cookie cache.
fn get_cookie_cache_path() -> Result<PathBuf, CookieCacheError> {
    let home = dirs::home_dir().ok_or(CookieCacheError::FileSystemError)?;
    Ok(home.join(".fedora/fedora-rs-cookie-jar.json"))
}

/// This function is used to parse [`HeaderValue`]s into cookies. It is based on the private
/// `parse` method from [`reqwest::cookie::Cookie`].
fn parse_cookie(value: &HeaderValue) -> Result<cookie::Cookie, cookie::ParseError> {
    std::str::from_utf8(value.as_bytes())
        .map_err(cookie::ParseError::from)
        .and_then(cookie::Cookie::parse)
}

/// A simple implementation of the [`CookieStore`](reqwest::cookie::CookieStore) trait, based on
/// the default implementation in [`reqwest::cookie::Jar`], but with additional methods for using a
/// simple on-disk cookie cache for persistent cookies.
#[derive(Debug)]
pub(crate) struct CachingJar {
    pub(crate) store: RwLock<cookie_store::CookieStore>,
}

impl CachingJar {
    /// Creates a cookie jar from a given [`CookieStore`].
    pub fn new(store: cookie_store::CookieStore) -> CachingJar {
        CachingJar {
            store: RwLock::new(store),
        }
    }

    /// Creates an empty cookie jar.
    pub fn empty() -> CachingJar {
        CachingJar {
            store: RwLock::new(cookie_store::CookieStore::default()),
        }
    }

    /// Attempt to read cached persistent cookies from the on-disk cookie cache. If successful, the
    /// return value is a new [`CachingJar`] instance that contains non-expired cookies.
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

        // deserialization implementation for CookieStore skips expired cookies internally
        let store: cookie_store::CookieStore = serde_json::from_str(&contents)?;

        Ok(CachingJar::new(store))
    }

    /// Attempt to write persistent cookies to the on-disk cookie cache.
    pub fn write_to_disk(&self) -> Result<(), CookieCacheError> {
        let path = get_cookie_cache_path()?;

        let store = &*self.store.read().expect("Poisoned lock!");
        let contents = serde_json::to_string_pretty(store)?;

        std::fs::write(path, contents)?;
        Ok(())
    }
}

// implementation based on reqwest::cookie::Jar
impl CookieStore for CachingJar {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &Url) {
        let iter = cookie_headers.filter_map(|val| parse_cookie(val).map(|cookie| cookie.into_owned()).ok());
        self.store
            .write()
            .expect("Poisoned RwLock! Something has gone wrong.")
            .store_response_cookies(iter, url);
    }

    fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let s = self
            .store
            .read()
            .expect("Poisoned RwLock! Something has gone wrong.")
            .get_request_values(url)
            .map(|(name, value)| format!("{}={}", name, value))
            .collect::<Vec<_>>()
            .join("; ");

        if s.is_empty() {
            return None;
        }

        HeaderValue::from_maybe_shared(Bytes::from(s)).ok()
    }
}
