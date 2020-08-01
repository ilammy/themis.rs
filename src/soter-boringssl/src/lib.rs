// Copyright 2019 themis.rs maintainers
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

// We follow BoringSSL naming convention, allow it.
#![allow(non_snake_case)]

mod error;
mod hash;
mod rand;

pub use error::{Error, ErrorKind, Result};
pub use hash::{
    EVP_DigestFinal_ex, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_create, EVP_MD_CTX_size,
    EVP_sha256, EVP_sha512, EVP_MD_CTX, EVP_MD,
};
pub use rand::RAND_bytes;
