# base library for interacting with fedora services

[![crates.io](https://img.shields.io/crates/v/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/d/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/l/fedora.svg)](https://crates.io/crates/fedora/)
[![docs.rs](https://docs.rs/fedora/badge.svg)](https://docs.rs/fedora/)

This package provides a base library for interacting with fedora web services.
It is intended to provide functionality similar to the [`fedora`][fedora.py]
python package, but for rust.

[fedora.py]: https://github.com/fedora-infra/python-fedora

Right now, the dependencies of this crate are [`reqwest`][reqwest] and
[`failure`][failure].

[reqwest]: https://docs.rs/reqwest
[failure]: https://docs.rs/failure


**NOTE**: The API is not finalized yet, and minor changes will still happen
before the `0.1.0` release.


## DONE

- OpenID authentication


## TODO

- authenticating with OpenID Connect
- authenticating for FAS2, wiki

