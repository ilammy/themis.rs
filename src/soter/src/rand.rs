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

//! Generating random data.

/// Generates pseudo-random bytes.
///
/// This functions generates cryptographically strong pseudo-random bytes and fills
/// the provided buffer with them.
///
/// # Panics
///
/// If the system does not have enough entropy to fill the entire buffer with random data,
/// this function will panic. There is nothing that the application can do to avoid it,
/// other than having being started after the system entropy pool had been properly seeded.
///
/// Note that some cryptographic backends might instead directly abort the process in this
/// case, so you really should not try to ‘handle’ this failure.
///
/// # Example
///
/// ```
/// # fn main() -> soter::Result<()> {
/// use soter::rand;
///
/// let mut key = [0; 64];
///
/// rand::bytes(&mut key);
/// # Ok(())
/// # }
/// ```
pub fn bytes(buffer: &mut [u8]) {
    if let Err(error) = boringssl::RAND_bytes(buffer) {
        // Normally, BoringSSL will abort on failure, but double-tap just in case.
        // One possible case is that the system does not have a CSPRNG available,
        // which is equally fatal for the application.
        panic!(format!("failed to generate random bytes: {}", error))
    }
}
