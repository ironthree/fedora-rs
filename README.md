# base library for interacting with fedora services

[![crates.io](https://img.shields.io/crates/v/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/d/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/l/fedora.svg)](https://crates.io/crates/fedora/)
[![docs.rs](https://docs.rs/fedora/badge.svg)](https://docs.rs/fedora/)

This crate provides a base for interacting with Fedora web services.

It is intended to provide functionality similar to the [`fedora`][fedora.py]
Python package, but for Rust.

Refer to the docs on [docs.rs] for a complete description of the functionality
of this crate.

[docs.rs]: https://docs.rs/fedora
[fedora.py]: https://github.com/fedora-infra/python-fedora

## DONE

- OpenID authentication (for example, for bodhi)

## TODO

- authenticating with OpenID Connect
- authenticating for FAS2, wiki

