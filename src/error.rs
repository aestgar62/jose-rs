// Copyright 2023 Antonio Estevez <aestevez@opencanarias.es>

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing
// permissions and limitations under the License.

//! # Errors
//!

/// Errors enumeration
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid URI
    InvalidUri,
    /// RSA error
    RSA(String),
}

impl Error {
    /// Returns a description of the error
    pub fn description(&self) -> &str {
        match self {
            Self::InvalidUri => "Invalid URI",
            Self::RSA(err) => err,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(self.description(), f)
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        self.description()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error() {
        let err = Error::InvalidUri;
        assert_eq!(err.description(), "Invalid URI");
        assert_eq!(err.to_string(), "Invalid URI");
    }
}
