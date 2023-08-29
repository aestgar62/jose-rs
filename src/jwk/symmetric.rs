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

//! # Symmetric keys data parameter for JWK
//!
//! [RFC 7518 Section 6.4](https://datatracker.ietf.org/doc/html/rfc7518#section-6.4)
//!

#![deny(missing_docs)]

use ptypes::Base64urlUInt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Symmetric keys Parameters
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct SymmetricKeysData {
    /// The symmetric key as a Base64urlUInt- encoded.
    #[serde(rename = "k")]
    pub key: Base64urlUInt,
}

impl Default for SymmetricKeysData {
    fn default() -> Self {
        Self {
            key: Base64urlUInt(Vec::new()),
        }
    }
}

impl From<&[u8]> for SymmetricKeysData {
    fn from(key: &[u8]) -> Self {
        Self {
            key: Base64urlUInt(key.to_vec()),
        }
    }
}

impl From<Vec<u8>> for SymmetricKeysData {
    fn from(key: Vec<u8>) -> Self {
        Self {
            key: Base64urlUInt(key),
        }
    }
}

impl From<SymmetricKeysData> for Vec<u8> {
    fn from(key: SymmetricKeysData) -> Self {
        key.key.0
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_symmetric_keys_data() {
        let key = SymmetricKeysData {
            key: Base64urlUInt(vec![0x01, 0x02, 0x03, 0x04]),
        };
        let key_json = serde_json::to_string(&key).unwrap();
        assert_eq!(key_json, r#"{"k":"AQIDBA"}"#);
        let key_de: SymmetricKeysData = serde_json::from_str(&key_json).unwrap();
        assert_eq!(key, key_de);

        let key1 = SymmetricKeysData::from(vec![0x01, 0x02, 0x03, 0x04]);
        let value: &[u8] = &[0x01, 0x02, 0x03, 0x04];
        let key2 = SymmetricKeysData::from(value);
        assert_eq!(key1, key2);
        let value2 = Vec::<u8>::from(key1);
        assert_eq!(value.to_vec(), value2);
    }
}
