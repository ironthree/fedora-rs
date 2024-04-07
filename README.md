# base library for interacting with Fedora services (DEPRECATED)

[![crates.io](https://img.shields.io/crates/v/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/d/fedora.svg)](https://crates.io/crates/fedora/)
[![crates.io](https://img.shields.io/crates/l/fedora.svg)](https://crates.io/crates/fedora/)
[![docs.rs](https://docs.rs/fedora/badge.svg)](https://docs.rs/fedora/)

**WARNING**: The OpenID-based authentication method for Fedora web services that
was provided by this crate no longer works. Most web services that are part of
the Fedora Project have moved to OpenID Connect (OIDC) or Kerberos-based
authentication. Bodhi was one of the last services that provided a deprecated
OpenID authentication endpoint, but that endpoint was accidentally broken in
bodhi-server v8.0.0 and can likely not be fixed. That makes the `fedora` crate
obsolete.

If another project that is related with the Fedora Project wants to use the "fedora"
name to publish on crates.io, transfer of ownership of the name can be discussed.
Please open a ticket on GitHub in this case.
