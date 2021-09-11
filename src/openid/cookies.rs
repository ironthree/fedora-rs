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

/// This helper function constructs the path to the default location for the on-disk cookie cache.
fn get_cookie_cache_path() -> Result<PathBuf, CookieCacheError> {
    let home = dirs::home_dir().ok_or(CookieCacheError::FileSystemError)?;
    Ok(home.join(".fedora/fedora-rs-cookie-jar.json"))
}

/// This enum describes the state of the cookie cache - fresh or expired.
pub(crate) enum CookieCacheState {
    /// none of the loaded cookies were expired
    Fresh,
    /// at least one of the loaded cookies was expired
    Expired,
}

/// This function is used to parse [`HeaderValue`s](reqwest::header::HeaderValue) into cookies. It
/// is based on the private `parse` method implementation from [`reqwest::cookie::Cookie`].
fn parse_cookie(value: &HeaderValue) -> Result<cookie::Cookie, cookie::ParseError> {
    std::str::from_utf8(value.as_bytes())
        .map_err(cookie::ParseError::from)
        .and_then(cookie::Cookie::parse)
}

/// A simple implementation of the [`CookieStore`](reqwest::cookie::CookieStore) trait, based on the
/// default implementation in [reqwest::cookie::Jar], but with additional methods for using a
/// simple on-disk cookie cache for persistent cookies.
#[derive(Debug)]
pub(crate) struct CachingJar {
    store: RwLock<cookie_store::CookieStore>,
}

impl CachingJar {
    /// Creates an empty cookie jar.
    pub fn empty() -> CachingJar {
        CachingJar {
            store: RwLock::new(cookie_store::CookieStore::default()),
        }
    }

    /// Attempt to read cached persistent cookies from the on-disk cookie cache. If successful, the
    /// return value is a tuple consisting of a new [CachingJar] instance, and a [CookieCacheState]
    /// value indicating whether any of the cached cookies are expired or not.
    pub fn read_from_disk() -> Result<(CachingJar, CookieCacheState), CookieCacheError> {
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

        Ok(if store.iter_any().any(|cookie| cookie.is_expired()) {
            log::info!("Session cookie(s) have expired, re-authentication necessary.");
            (
                CachingJar {
                    store: RwLock::new(store),
                },
                CookieCacheState::Expired,
            )
        } else {
            log::debug!("Session cookie(s) are fresh, no re-authentication necessary.");
            (
                CachingJar {
                    store: RwLock::new(store),
                },
                CookieCacheState::Fresh,
            )
        })
    }

    /// Attempt to write persistent cookies to the on-disk cookie cache.
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
