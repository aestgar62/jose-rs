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

//! # Utilities
//!

#![deny(missing_docs)]

use crate::Error;

use base64::{engine::general_purpose, Engine as _};
use serde::{de::DeserializeOwned, Serialize};

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Serialize to base64 encoded json.
pub fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)
        .map_err(|_| Error::Encode("serde json serialize error".to_owned()))?;
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(json))
}

/// Deserialize from base64 encoded json.
pub fn base64_decode_json<T: DeserializeOwned>(input: &str) -> Result<T, Error> {
    let json = general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| Error::Decode("Base64 decode error".to_owned()))?;
    serde_json::from_slice(&json)
        .map_err(|_| Error::Decode("serde json deserialize error".to_owned()))
}

/// Generate HMAC.
pub fn generate_hmac(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
    mac.update(msg);
    let result = mac.finalize().into_bytes();
    Ok(result[..16].to_vec())
}

/// Validate HMAC.
pub fn validate_hmac(key: &[u8], msg: &[u8], at: &[u8]) -> Result<(), Error> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
    mac.update(msg);
    let result = mac.finalize().into_bytes();
    if result[..16] != at[..] {
        return Err(Error::Decrypt("Invalid Authentication Tag".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_base64_encode_json() {
        let object = vec![1, 2, 3];
        let encoded = base64_encode_json(&object).unwrap();
        assert_eq!(encoded, "WzEsMiwzXQ");
    }

    #[test]
    fn test_base64_decode_json() {
        let encoded = "WzEsMiwzXQ";
        let decoded: Vec<u8> = base64_decode_json(encoded).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn test_hmac() {}
}
