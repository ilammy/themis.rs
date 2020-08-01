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

use std::error;
use std::fmt;
use std::os::raw::c_int;
use std::result;

/// Result of BoringSSL function calls.
pub type Result<T> = result::Result<T, Error>;

/// BoringSSL error.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
}

/// List of BoringSSL error categories.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ErrorKind {
    /// General failure.
    Failure,
    /// Invalid parameter.
    InvalidParameter,
    /// Buffer is too small.
    BufferTooSmall(usize),
    /// Operation not supported.
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
    /// Creates a new error with given kind.
    pub(crate) fn new(kind: ErrorKind) -> Error {
        Error { kind }
    }

    /// Returns the corresponding `ErrorKind` for this error.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

/// Conversions to BoringSSL error codes.
pub trait ResultExt {
    /// Default BoringSSL error code convention.
    fn default_error(self) -> Result<()>;
    /// Operation may not be supported by the system.
    fn maybe_not_supported(self) -> Result<()>;
}

impl ResultExt for c_int {
    fn default_error(self) -> Result<()> {
        match self {
            1 => Ok(()),
            _ => Err(Error::new(ErrorKind::Failure)),
        }
    }

    fn maybe_not_supported(self) -> Result<()> {
        match self {
            -1 => Err(Error::new(ErrorKind::NotSupported)),
            _ => self.default_error(),
        }
    }
}
