# base library for interacting with fedora services

[![crates.io](https://img.shields.io/crates/v/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/d/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/l/fedora.svg)](https://crates.io/crates/fedora/)
[![docs.rs](https://docs.rs/fedora/badge.svg)](https://docs.rs/fedora/)

This package provides a base library for interacting with Fedora web services.

It is intended to provide functionality similar to the [`fedora`][fedora.py] Python package, but for Rust.

[fedora.py]: https://github.com/fedora-infra/python-fedora


## DONE

- OpenID authentication (for example, for bodhi)


## TODO

- authenticating with OpenID Connect
- authenticating for FAS2, wiki


## Development

If you're interested in using this crate, you can enable "debug mode" by enabling the `debug` feature.
This will enable various debug output throughout the crate (primarily HTTP response codes and cookies).

