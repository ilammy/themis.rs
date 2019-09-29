soter-boringssl-sys
===================

Raw FFI bindings to Soter's copy of Google's [**BoringSSL** library][boringssl].

[boringssl]: https://boringssl.googlesource.com/boringssl/

## Supported versions

BoringSSL is vendored here, so each version of this crate depends on a particular version of BoringSSL.
Each new release will usually vendor the latest version of BoringSSL in order to pick up bug fixes and improvements.

## Bindings

Rust bindings live in [`src/lib.rs`](src/lib.rs).
These are direct _unsafe_ bindings to BoringSSL functions,
for idiomatic Rust API look at the [**soter-boringssl**][soter-boringssl] crate.

[soter-boringssl]: https://crates.io/crates/soter-boringssl

These bindings are auto-generated using the **bindgen** tool
with some additional postprocessing performed by the [`bindgen.sh`](bindgen.sh) script.
In particular, each public function gets annotated with a `#[link_name]` attribute.
For example, given the following bindgen output:

```rust
extern "C" {
    pub fn RAND_bytes(buf: *mut u8, len: usize) -> ::std::os::raw::c_int;
}
```

we add a `#[link_name]` attribute as follows, where X.Y.Z is the current crate version:

```rust
extern "C" {
    #[link_name = "__SOTER_BORINGSSL_X_Y_Z_RAND_bytes"]
    pub fn RAND_bytes(buf: *mut u8, len: usize) -> ::std::os::raw::c_int;
}
```

This approach is based on Google's [**Mundane** crypto library][mundane].

[mundane]: https://github.com/google/mundane

## Symbol prefixing

Rust heavily favors static linkage.
Normally, it's not possible to link multiple copies of software with C API
because the namespace for C symbols is global at link time.
In order to avoid this problem and prevent conflicts with other libraries,
we compile BoringSSL with a custom symbol prefix specific to the crate version.

### Prefixing

Each BoringSSL symbol is given a prefix of `__SOTER_BORINGSSL_X_Y_Z_`,
where the current crate version number is X.Y.Z.
This way, if two different versions of the crate are present during a build,
no C symbol will be defined under the same name in both builds of BoringSSL.

### Two-phase build

BoringSSL's build system has [built-in support][prefix] for symbol prefixing.
However, it requires a full of list of symbols to be known before the build.
Since the exact symbol set is highly platform-dependent,
we can't provide a premade list of symbols we are interested in.
Instead, we discover the symbols dynamically at build time by doing a two-phase build.

[prefix]: https://boringssl.googlesource.com/boringssl/+/HEAD/BUILDING.md#building-with-prefixed-symbols

In the first phase, we build BoringSSL as normal, with no symbol prefixing.
Then, the build script scrapes the list of symbols from the build artifacts.
Using this list, we run the build again – the second phase –
this time using BoringSSL's symbol prefixing feature.
We use the artifacts from the second build when performing the final Rust build.

### Library naming

In order to use a library in an application, Rust tells the linker to search for it.
The way linkers work is that they look through a list of directories for an artifact with an appropriate name.
For example, a `#[link(name = "crypto")]` attribute turns into an `-lcrypto` flag for the linker,
which will walk through a bunch of standard system directories
and will use the first `libcrypto.a` it finds there
(or `crypto.lib` on Windows).

In order to ensure that the linker uses _our_ BoringSSL libraries,
we give them unique names and tell the linker about Rust build directories.
For example, the cryptography library – normally stored in `libcrypto.a` –
gets renamed into `libsoter_crypto_x_y_z.a` which includes the crate version.
Now the linker will not confuse different crate versions
and will not fall back to using OpenSSL distributed with the system.

## License

It's complicated.
Redistributed source code of BoringSSL has [its own license](boringssl/LICENSE).
A bulk of code in this crate is based on Google's work and is distributed under [MIT license](LICENSE).
Everything else is distributed under [Apache License 2.0](../../LICENSE).
