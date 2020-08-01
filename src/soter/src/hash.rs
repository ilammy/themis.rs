// Copyright 2020 themis.rs maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Computing cryptographic hashes.

use boringssl::{
    EVP_DigestFinal_ex, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_create, EVP_MD_CTX_size,
    EVP_sha256, EVP_sha512, EVP_MD_CTX,
};

use crate::error::{Error, ErrorKind, Result};

/// Algorithms supported by [`Hash`].
///
/// [`Hash`]: struct.Hash.html
pub enum Algorithm {
    SHA256,
    SHA512,
}

/// Soter hash function.
///
/// `Hash` computes hash sums or message digests of byte streams.
/// The interface is analogous to [`std::hash::Hasher`], but different:
///
///   - the output is a byte buffer, not `u64`
///   - you cannot update the hash after obtaining the result
///   - the methods may fail (but should not normally)
///   - British spelling ;)
///
/// [`std::hash::Hasher`]: https://doc.rust-lang.org/std/hash/trait.Hasher.html
///
/// # Example
///
/// ```
/// use hex_literal::hex;
/// use soter::hash::{Algorithm, Hash};
///
/// let mut hash = Hash::new(Algorithm::SHA256);
/// hash.write("abc");
/// let hash = hash.get();
///
/// assert_eq!(hash, hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
/// ```
pub struct Hash {
    ctx: EVP_MD_CTX,
    finalised: bool,
}

impl Hash {
    /// Prepares a new hash computation with given algorithm.
    pub fn new(algorithm: Algorithm) -> Hash {
        // Normally this should not fail. Possible reasons include
        // allocation failure (unrecoverable in current Rust) and
        // missing support for the algorithm (unrecoverable too,
        // the build system should have included all algorithms).
        Hash::try_new(algorithm).expect("failed to make a new Hash")
    }

    fn try_new(algorithm: Algorithm) -> Result<Hash> {
        let evp = match algorithm {
            Algorithm::SHA256 => EVP_sha256(),
            Algorithm::SHA512 => EVP_sha512(),
        };
        let mut ctx = EVP_MD_CTX_create()?;
        EVP_DigestInit(&mut ctx, evp)?;
        Ok(Hash {
            ctx,
            finalised: false,
        })
    }

    /// Returns the hash sum of the bytes written.
    ///
    /// The result is written into the provided buffer (starting from the beginning)
    /// and a slice of the buffer with the hash is returned.
    ///
    /// # Errors
    ///
    /// You cannot [`write`] more data into this `Hash` after it has been finalised.
    /// In order to compute a new hash, you will have to create a new `Hash`.
    ///
    /// You also cannot retrieve the hash value again after finalisation.
    /// Further calls to [`finalise`] will fail with an error.
    ///
    /// If the buffer is too small for the result to fit, an error of [`BufferTooSmall`] kind
    /// is returned, indicating the minimum size needed. Hash computation is not finalised
    /// in this case and you can try getting the result again after reallocation.
    /// You can also use [`output_size`] to obtain the expected size of the result
    /// and allocate a suitable buffer beforehand.
    ///
    /// [`write`]: struct.Hash.html#method.write
    /// [`finalise`]: struct.Hash.html#method.finalise
    /// [`BufferTooSmall`]: ../error/enum.ErrorKind.html#variant.BufferTooSmall
    /// [`output_size`]: struct.Hash.html#method.output_size
    pub fn finalise<'a>(&mut self, buffer: &'a mut [u8]) -> Result<&'a [u8]> {
        if self.finalised {
            return Err(Error::new(ErrorKind::Failure));
        }
        let result = EVP_DigestFinal_ex(&mut self.ctx, buffer)?;
        self.finalised = true;
        Ok(result)
    }

    /// Returns the hash sum of the bytes written.
    ///
    /// This is a convenience wrapper over [`finalise`] which returns the result
    /// in a newly allocated vector, consuming this `Hash` object.
    ///
    /// # Panics
    ///
    /// It is an error to call this method after calling [`finalise`].
    ///
    /// [`finalise`]: struct.Hash.html#method.finalise
    pub fn get(mut self) -> Vec<u8> {
        let mut result = vec![0; self.output_size()];
        self.finalise(&mut result).expect("failed to finalise Hash");
        result
    }

    /// Writes some data into this `Hash`.
    ///
    /// # Panics
    ///
    /// It is an error to use this method after calling [`finalise`].
    ///
    /// [`finalise`]: struct.Hash.html#tymethod.finalise
    pub fn write(&mut self, bytes: impl AsRef<[u8]>) {
        if self.finalised {
            panic!("cannot write into finalised Hash");
        }
        // Normally this should never happen. If it does, this is an implementation bug.
        EVP_DigestUpdate(&mut self.ctx, bytes.as_ref()).expect("failed to update Hash")
    }

    /// Returns output size of this `Hash` in bytes.
    pub fn output_size(&self) -> usize {
        EVP_MD_CTX_size(&self.ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    // We use quite long literals and hex_literal::hex! converts them into arrays,
    // but Rust arrays have poor support in generics sometimes, so here's a helper
    // macro hex! which is like hex_literal::hex!, but always outputs slices.
    macro_rules! hex {
        ($literal:expr) => {
            &hex_literal::hex!($literal)[..]
        };
    }

    // Test vectors provided by NIST et al.:
    // https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
    // https://www.di-mgt.com.au/sha_testvectors.html

    mod sha256 {
        use super::super::*;

        #[test]
        fn test_vectors() {
            let test_vectors: &[(&[u8], &str)] = &[
                (hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), ""),
                (hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "abc"),
                (hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"), "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                (hex!("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"), "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            ];
            for (expected_output, input) in test_vectors {
                let mut hash = Hash::new(Algorithm::SHA256);
                hash.write(input);
                assert_eq!(hash.get(), *expected_output);
            }
        }

        #[test]
        fn test_vectors_megabyte() {
            let expected_output =
                hex!("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
            let pattern = "a".repeat(1000);
            let mut hash = Hash::new(Algorithm::SHA256);
            for _ in 0..1000 {
                hash.write(&pattern);
            }
            assert_eq!(hash.get(), expected_output);
        }

        #[test]
        #[cfg_attr(not(feature = "long_tests"), ignore)]
        fn test_vectors_gigabyte() {
            let expected_output =
                hex!("50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e");
            let pattern = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
            let mut hash = Hash::new(Algorithm::SHA256);
            for _ in 0..16777216 {
                hash.write(&pattern);
            }
            assert_eq!(hash.get(), expected_output);
        }
    }

    mod sha512 {
        use super::super::*;

        #[test]
        fn test_vectors() {
            let test_vectors: &[(&[u8], &str)] = &[
                (hex!("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"), ""),
                (hex!("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"), "abc"),
                (hex!("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"), "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                (hex!("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"), "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            ];
            for (expected_output, input) in test_vectors {
                let mut hash = Hash::new(Algorithm::SHA512);
                hash.write(input);
                assert_eq!(hash.get(), *expected_output);
            }
        }

        #[test]
        fn test_vectors_megabyte() {
            let expected_output = hex!("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
            let pattern = "a".repeat(1000);
            let mut hash = Hash::new(Algorithm::SHA512);
            for _ in 0..1000 {
                hash.write(&pattern);
            }
            assert_eq!(hash.get(), expected_output);
        }

        #[test]
        #[cfg_attr(not(feature = "long_tests"), ignore)]
        fn test_vectors_gigabyte() {
            let expected_output = hex!("b47c933421ea2db149ad6e10fce6c7f93d0752380180ffd7f4629a712134831d77be6091b819ed352c2967a2e2d4fa5050723c9630691f1a05a7281dbe6c1086");
            let pattern = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
            let mut hash = Hash::new(Algorithm::SHA512);
            for _ in 0..16777216 {
                hash.write(&pattern);
            }
            assert_eq!(hash.get(), expected_output);
        }
    }

    #[test]
    fn output_sizes() {
        assert_eq!(Hash::new(Algorithm::SHA256).output_size(), 256 / 8);
        assert_eq!(Hash::new(Algorithm::SHA512).output_size(), 512 / 8);
    }

    #[test]
    fn cannot_finalise_twice() {
        let mut hash = Hash::new(Algorithm::SHA512);
        let mut output = [0; 512 / 8];
        assert!(hash.finalise(&mut output).is_ok());
        assert!(hash.finalise(&mut output).is_err());
    }

    #[test]
    #[should_panic(expected = "cannot write into finalised Hash")]
    fn cannot_write_past_finalise() {
        let mut hash = Hash::new(Algorithm::SHA256);
        let mut output = [0; 256 / 8];
        assert!(hash.finalise(&mut output).is_ok());
        hash.write(b"abc"); // should panic
    }

    #[test]
    #[should_panic(expected = "failed to finalise Hash")]
    fn cannot_get_after_finalise() {
        let mut hash = Hash::new(Algorithm::SHA256);
        let mut output = [0; 256 / 8];
        assert!(hash.finalise(&mut output).is_ok());
        let _ = hash.get(); // should panic
    }

    #[test]
    fn finalise_short() {
        let mut hash = Hash::new(Algorithm::SHA256);
        let mut output = [0; 128 / 8];
        // You can't finalise if the buffer is too small.
        let err = hash.finalise(&mut output).expect_err("not enough buffer");
        assert_eq!(err.kind(), ErrorKind::BufferTooSmall(256 / 8));
        // But you can after you reallocate.
        let mut output = [0; 256 / 8];
        assert!(hash.finalise(&mut output).is_ok());
    }

    #[test]
    fn finalise_long() {
        let mut hash = Hash::new(Algorithm::SHA256);
        let mut output = [0xED; 512 / 8];
        let result = hash.finalise(&mut output).expect("big buffer is fine");
        // If the buffer is bigger than necessary, it's only partially filled.
        let empty_sha256 = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(result, empty_sha256);
        assert_eq!(&output[32..64], [0xED; 32]);
    }
}
