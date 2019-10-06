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

use crate::error::{default_error, Result};

/// Puts cryptographically strong pseudo-random bytes into `buf`.
pub fn RAND_bytes(buf: &mut [u8]) -> Result {
    let err = unsafe { boringssl::RAND_bytes(buf.as_mut_ptr(), buf.len()) };
    default_error(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer() {
        assert!(RAND_bytes(&mut []).is_ok());
    }

    #[test]
    fn normal_buffer() {
        let mut buffer = [0; 32];
        assert!(RAND_bytes(&mut buffer).is_ok());
    }
}
