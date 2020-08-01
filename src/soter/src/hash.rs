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
