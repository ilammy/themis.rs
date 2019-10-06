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

use std::os::raw::c_int;
use std::result;

/// Result of BoringSSL function calls.
///
/// `Err` contains result code returned by BoringSSL. Normally it is zero,
/// but negative values may indicate individual errors. Consult BoringSSL
/// documentation for individual functions.
pub type Result = result::Result<(), i32>;

/// Handles BoringSSL’s default error code convention.
pub fn default_error(result: c_int) -> Result {
    match result {
        1 => Ok(()),
        _ => Err(result),
    }
}
