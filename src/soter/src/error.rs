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

use std::{error, fmt, result};

/// Result type for Soter operations.
pub type Result<T> = result::Result<T, Error>;

/// Error type for Soter operations.
///
/// Normally you should not look too deep into errors returned by a cryptography library.
/// Bad error handling is an infamous source of security vulnerabilities. Error handling
/// path is often the last consideration for programmers, and it is rarely exercised and
/// verified in tests. Thankfully, Rust makes is hard to accidentally ignore errors, and
/// you should not intentionally ignore _these_ errors. Wrap it into a `Box<dyn Error>`
/// and move on.
///
/// You can inspect the error kind and additional information, but this should be treated
/// more as a debugging aid than anything. A proper response to errors is to abort the
/// high-level operation you are performing, do not trust the source of the input data,
/// and report this incident to the authorities.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

/// List of Soter error categories.
#[derive(Debug)]
pub enum ErrorKind {
    /// General failure.
    ///
    /// This is the most common error you’ll encounter. It means that something somewhere
    /// has gone wrong, probably something is not quite right with the arguments, or the
    /// state, or the environment. You may or may not be compromised, or be in the process
    /// of being compromised, or being tricked into doing something that might compromise
    /// security of the application.
    Failure,
    /// Invalid parameter.
    ///
    /// Static type system should catch most of these, but sometimes we double-check with
    /// runtime validation, or have no other choice but to verify invariants at runtime.
    ///
    /// Note that this kind is **not used** to indicate malformed input data in parameters.
    /// This should have been a compilation error. Typically a programmer’s error is the
    /// cause of this failure, and it might indicate a bug in the application. Study the
    /// call site and reread the API documentation for additional insight.
    InvalidParameter,
    /// Buffer is too small.
    ///
    /// Some APIs require you to provide an output buffer of a sufficient size.
    /// If the buffer does not have a sufficient size, you get this error which contains
    /// a suitable size for the buffer in bytes. Reallocate and try again.
    BufferTooSmall(usize),
    /// Operation is not supported.
    ///
    /// Typically this means that the crytographic backend seems to be misconfigured and
    /// does not support a required operation.
    ///
    /// Usually these are not recoverable at the application level. Consulting with your
    /// system administrator might help to avoid this failure.
    NotSupported,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::Failure => write!(f, "failure"),
            ErrorKind::InvalidParameter => write!(f, "invalid parameter"),
            ErrorKind::BufferTooSmall(min) => write!(f, "buffer too small, need {} bytes", min),
            ErrorKind::NotSupported => write!(f, "operation not supported"),
        }
    }
}

impl Error {
    /// Constructs a new error of given kind.
    pub(crate) fn with_kind(kind: ErrorKind) -> Error {
        Error { kind }
    }

    /// Returns the corresponding `ErrorKind` for this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

impl From<boringssl::Error> for Error {
    fn from(other: boringssl::Error) -> Error {
        // The mapping is mostly one-to-one.
        let kind = match other.kind() {
            boringssl::ErrorKind::Failure => ErrorKind::Failure,
            boringssl::ErrorKind::InvalidParameter => ErrorKind::InvalidParameter,
            boringssl::ErrorKind::BufferTooSmall(s) => ErrorKind::BufferTooSmall(s),
            boringssl::ErrorKind::NotSupported => ErrorKind::NotSupported,
        };
        Error::with_kind(kind)
    }
}
