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

use crate::error::{Error, ErrorKind, Result, ResultExt};

/// Reference to message digest function descriptor.
#[allow(non_camel_case_types)]
pub struct EVP_MD(*const boringssl::EVP_MD);

// It is possible to move EVP_MD into a different thread and since it's just
// a constant reference, it's safe to access it concurrently.
unsafe impl Send for EVP_MD {}
unsafe impl Sync for EVP_MD {}

/// Returns SHA-256 message digest.
pub fn EVP_sha256() -> EVP_MD {
    EVP_MD(unsafe { boringssl::EVP_sha256() })
}

/// Returns SHA-512 message digest.
pub fn EVP_sha512() -> EVP_MD {
    EVP_MD(unsafe { boringssl::EVP_sha512() })
}

/// Message digest computation context.
#[allow(non_camel_case_types)]
pub struct EVP_MD_CTX(*mut boringssl::EVP_MD_CTX);

// It is possible to move EVP_MD_CTX into a different thread. It is also safe
// to access it concurrently in read-only fashion.
unsafe impl Send for EVP_MD_CTX {}
unsafe impl Sync for EVP_MD_CTX {}

/// Allocates, initialises and returns a digest context.
pub fn EVP_MD_CTX_create() -> Result<EVP_MD_CTX> {
    let ctx = unsafe { boringssl::EVP_MD_CTX_create() };
    if ctx.is_null() {
        return Err(Error::new(ErrorKind::Failure));
    }
    Ok(EVP_MD_CTX(ctx))
}

impl Drop for EVP_MD_CTX {
    fn drop(&mut self) {
        unsafe { boringssl::EVP_MD_CTX_destroy(self.0) }
    }
}

/// Returns the output size of this message digest.
pub fn EVP_MD_CTX_size(ctx: &EVP_MD_CTX) -> usize {
    unsafe { boringssl::EVP_MD_CTX_size(ctx.0) }
}

/// Sets up digest context to use the given digest type.
pub fn EVP_DigestInit(ctx: &mut EVP_MD_CTX, type_: EVP_MD) -> Result<()> {
    unsafe { boringssl::EVP_DigestInit_ex(ctx.0, type_.0, std::ptr::null_mut()).default_error() }
}

/// Hashes bytes of data into the digest context.
pub fn EVP_DigestUpdate(ctx: &mut EVP_MD_CTX, bytes: &[u8]) -> Result<()> {
    use std::ffi::c_void as void;
    unsafe {
        boringssl::EVP_DigestUpdate(ctx.0, bytes.as_ptr() as *const void, bytes.len())
            .default_error()
    }
}

/// Retrieves the digest value from the context and places it into the buffer.
///
/// The buffer should have sufficient size for the digest. If the buffer is smaller than needed,
/// an error is returned. If the buffer is bigger, only a subslice is filled in and returned.
///
/// This call wipes the digest value from the context so it cannot be retrieved again.
pub fn EVP_DigestFinal_ex<'a>(ctx: &mut EVP_MD_CTX, buffer: &'a mut [u8]) -> Result<&'a [u8]> {
    // It may seem like EVP_DigestFinal_ex() uses the "size" parameter as the current size
    // of the buffer and handles the short buffer case, but in fact it requires the buffer
    // to have sufficient size, and the "size" parameter is only an out-parameter.
    let need_size = EVP_MD_CTX_size(ctx);
    if buffer.len() < need_size {
        return Err(Error::new(ErrorKind::BufferTooSmall(need_size)));
    }
    let mut size = 0;
    unsafe {
        boringssl::EVP_DigestFinal_ex(ctx.0, buffer.as_mut_ptr(), &mut size).default_error()?;
    }
    Ok(&buffer[..size as usize])
}
