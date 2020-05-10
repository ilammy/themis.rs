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

//! Cyclic redundancy checks (CRC).

/// CRC-32C computation.
///
/// This computes reflected Castagnoli CRC-32C with polynomial 0x11EDC6F41,
/// as defined by [RFC 3309](https://tools.ietf.org/html/rfc3309) for SCTP.
///
/// # Examples
///
/// ```
/// use soter::crc::CRC32C;
///
/// let checksum = CRC32C::checksum("123456789");
///
/// assert_eq!(checksum, 0x839206E3);
/// ```
pub struct CRC32C(u32);

impl CRC32C {
    /// Computes CRC-32C checksum for given data.
    pub fn checksum(data: impl AsRef<[u8]>) -> u32 {
        let mut crc32 = CRC32C::new();
        crc32.update(data);
        crc32.complete()
    }

    /// Prepares new CRC-32C computation.
    #[allow(clippy::new_without_default)]
    pub fn new() -> CRC32C {
        CRC32C(INIT_CRC32)
    }

    /// Updates CRC with new data.
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0 = platform::update_crc32c_runtime(self.0, data.as_ref());
    }

    /// Finalizes CRC computation and returns checksum.
    pub fn complete(self) -> u32 {
        self.result()
    }

    /// Finalizes CRC computation and returns checksum.
    ///
    /// You can reuse this CRC object to compute another checksum.
    pub fn reset(&mut self) -> u32 {
        let result = self.result();
        self.0 = INIT_CRC32;
        result
    }

    fn result(&self) -> u32 {
        // Note the byte swap applied after the usual CRC negation.
        (!self.0).swap_bytes()
    }
}

// The following items and modules are public to make them accessible in benchmarks
// but they are not an intended interface for the end users, hence #[doc(hidden)].

#[doc(hidden)]
pub mod platform;

/// Initial state for CRC-32 computation.
#[doc(hidden)]
#[allow(clippy::unreadable_literal)]
pub const INIT_CRC32: u32 = 0xFFFFFFFF;

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod tests {
    mod crc32c {
        use super::super::*;

        #[test]
        fn known_values() {
            // All CRC checksums return zero for empty input.
            assert_eq!(CRC32C::checksum(""), 0);
            // From CRC catalog:
            // http://reveng.sourceforge.net/crc-catalogue/17plus.htm#crc.cat.crc-32c
            assert_eq!(CRC32C::checksum("123456789"), 0x839206E3);
            // Some more test values computed here:
            // http://www.zorc.breitbandkatze.de/crc.html
            assert_eq!(CRC32C::checksum("CRC-32C"), 0xED6F84DA);
            assert_eq!(
                CRC32C::checksum("The quick brown fox jumps over the lazy dog"),
                0x04046222
            );
            // (Keep in mind that this CRC outputs 'reflected' results.)
        }

        #[test]
        fn incremental_computation() {
            let input = "Test Input Please Ignore";

            let mut crc = CRC32C::new();
            crc.update(&input[..10]);
            crc.update(&input[10..]);

            assert_eq!(crc.complete(), CRC32C::checksum(input));
        }

        #[test]
        fn repeated_computation() {
            let mut crc = CRC32C::new();

            crc.update("test");
            let value1 = crc.reset();

            crc.update("test");
            let value2 = crc.reset();

            assert_eq!(value1, value2);
        }
    }
}
