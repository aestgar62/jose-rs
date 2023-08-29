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

#![deny(missing_docs)]
use std::error::Error as StdError;

/// Errors enumeration
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Invalid URI
    InvalidUri,
    /// RSA error
    RSA(String),
    /// Curve not implemented
    CurveNotImplemented(String),
    /// OKP error
    OKP(String),
    /// EC error
    EC(String),
    /// OCT error
    OCT(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidUri => write!(f, "Invalid URI"),
            Error::RSA(string) => write!(f, "RSA Error: {}", string),
            Error::CurveNotImplemented(string) => {
                write!(f, "Curve not implemented: {}", string)
            }
            Error::OKP(string) => write!(f, "OKP Error: {}", string),
            Error::EC(string) => write!(f, "EC Error: {}", string),
            Error::OCT(string) => write!(f, "OCT Error: {}", string),
        }
    }
}

impl StdError for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_uri() {
        let err = Error::InvalidUri;
        assert_eq!(err.to_string(), "Invalid URI");
    }

    #[test]
    fn test_rsa() {
        let err = Error::RSA("RSA Error".to_owned());
        assert_eq!(err.to_string(), "RSA Error: RSA Error");
    }

    #[test]
    fn test_curve_not_implemented() {
        let err = Error::CurveNotImplemented("Ed25519".to_owned());
        assert_eq!(err.to_string(), "Curve not implemented: Ed25519");
    }

    #[test]
    fn test_okp() {
        let err = Error::OKP("missing secret key".to_owned());
        assert_eq!(err.to_string(), "OKP Error: missing secret key");
    }

    #[test]
    fn test_ec() {
        let err = Error::EC("missing secret key".to_owned());
        assert_eq!(err.to_string(), "EC Error: missing secret key");
    }

    #[test]
    fn test_oct() {
        let err = Error::OCT("missing secret key".to_owned());
        assert_eq!(err.to_string(), "OCT Error: missing secret key");
    }
}
