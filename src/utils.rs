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

/// Generate a random 32-byte array.
pub fn generate_random_bytes() -> Result<[u8; 32], Error> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random("getrandom error".to_owned()))?;
    Ok(bytes)
}
