### Release 2.1.0 "Dirs" (November 06, 2023)

This release contains a fix for a small bug in the cookie cache implementation,
and updates some dependencies:

- The directory containing the cookie cache for OpenID authentication is crated
  ahead of time if it does not already exist. Fixes issues with storing and
  loading cookies for the first time.
- Update the dirs crate to version 5.
- Update the env_logger crate to version 0.10.
- Bump MSRV to 1.67.0 (due to transitive dependencies).

### Release 2.0.2 "Bump" (July 17, 2022)

This release only bumps versions of some dependencies:

- bump `cookie` from 0.15 to 0.16
- bump `cookie_store` from 0.15 to 0.16
- bump `reqwest` from 0.11.6 to 0.11.11

The major bumps in `cookie` and `cookie_crate` are not exposed to users of this
crate, and while `reqwest` *is* part of this crate's public API, it's a bump
to a compatible version.

### Release 2.0.1 "Optimize" (May 18, 2022)

This release contains small fixes and optimizations for the OpenID session and
improves the heuristics that are used to determine whether cached session
cookies were still fresh.

### Release 2.0.0 "Finally" (February 01, 2022)

This release contains no code changes compared to the previous beta. The only
changes are some updated crate dependencies (to match the versions that are
available from Fedora repositories at the time of publishing).

For a complete list of changes since `v1.1.0`, read the release notes for the
last two beta releases.

### Release 2.0.0-beta.2 "Spring Cleaning" (January 28, 2022)

This beta release only includes some code cleanups and small improvements for
error messages and documentation.

### Release 2.0.0-beta.1 "Modern Times" (January 20, 2022)

This version is an almost-complete rewrite of the entire crate, with
numerous changes and improvements. Most notably, all network calls are now
`async` (which has been the default API in [`reqwest`] for some time), and the
API for creating and using [`Session`] instances has been simplified.
[`Session`] is now a plain newtype struct that wraps a [`reqwest::Client`],
instead of being a trait. This means it is no longer necessary to deal with
trait objects, or care about boxing, dynamic or static dispatch.

### Release 1.1.0 "Cookie Monster" (September 23, 2021)

This version introduces a simple on-disk cookie cache (like python-fedora) to
reduce the number of necessary re-authentications via OpenID, which should
speed up usage of authenticated web interfaces (like bodhi) so long as the
cookie cache is fresh.

### Release 1.0.0 "Up This Grade" (Jan. 05, 2021)

Changes:

- breaking: updated [`reqwest`] from `0.10` to `0.11` (breaking change,
  because parts of [`reqwest`] are re-exported)
- port from `failure` to [`thiserror`]

### Release 0.2.2 "Take this" (Dec. 31, 2019)

New features:

- allow usage of OpenID parameters returned by the endpoint

### Release 0.2.1 "Quantum Leap" (Dec. 31, 2019)

Internal changes:

- support the [`reqwest`] 0.10.0 stable release

### Release 0.2.0 "DON'T let it go" (Dec. 29, 2020)

API changes:

- accept `&str` instead of taking ownership of `Strings`, where possible

### Release 0.1.1 "Pretty Please" (Dec. 25, 2019)

Incremental improvements:

- add settings for nightly `rustfmt`
- clean up and slightly refactor code
- simplify error handling
- make OpenID parameters public
- document all public items, add some hyperlinks

### Release 0.1.0 "Hello World" (Dec. 18, 2019)

Incremental improvements:

- switch to `reqwest` 0.10 pre-releases for proper, automatic cookie handling
- provide anonymous and authenticated sessions with compatible interfaces

### Release 0.0.7 "Sid" (Dec. 12, 2019)

Incremental improvements:

- fix issues with OpenID authentication
- manually track session cookies

### Release 0.0.6 "Convini" (Nov. 30, 2019)

Incremental improvements:

- add methods for automatically create clients for production, staging instances
- add method to manually specify URLs for OpenID endpoint

### Release 0.0.5 "Move along" (Jun. 06, 2019)

Internal refactoring only.

### Release 0.0.4 "Mandatory Materials" (Jun. 06, 2019)

Incremental improvements:

- implement more sophisticated error handling
- update README with current status

### Release 0.0.3 "Bod the Buildhi" (Jun. 06, 2019)

Incremental improvements:

- refactor OpenID authentication support
- split builder from client

### Release 0.0.2 "References spark joy" (Jun. 03, 2019)

Incremental improvements:

- fix ownership issues preventing API usage
- document some public items

### Release 0.0.1 "A Beginning" (Jun. 03, 2019)

Initial release, work-in-progress state.

