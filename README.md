themis.rs
=========

Rust implementation of [**Themis** cryptographic framework][themis].
It's meant to provide C bindings compatible with existing Themis core written in C,
as well as native Rust API compatible with existing Rust-Themis wrapper over the C library.

[themis]: https://github.com/cossacklabs/themis

## Why?

Because memory management in C is hard and not safe.
And because it's fun to rewrite stuff in Rust, obviously.

## License

The code is distributed under [**Apache License 2.0**](LICENSE).
