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

//! # PBKDF2 Key Derivation.
//! https://datatracker.ietf.org/doc/html/rfc7518#section-4.8
//!

#![deny(missing_docs)]

use crate::{
    error::Error,
    jwa::JweAlgorithm,
    jwk::{Jwk, KeyType},
};

use pbkdf2::pbkdf2;

use super::JweHeader;

/// PBKDF2 Key Derivation.
pub fn derive_key(header: &JweHeader, jwk: &Jwk) -> Result<Vec<u8>, Error> {
    let p2s = header
        .p2_salt_input
        .as_ref()
        .ok_or(Error::InvalidAlgorithm(
            "missing p2s parameter in PBKDF2".to_string(),
        ))?;

    let p2c = header.p2_count.ok_or(Error::InvalidAlgorithm(
        "missing p2c parameter in PBKDF2".to_string(),
    ))?;
    let password = if let KeyType::OCT(key_data) = &jwk.key_type {
        key_data.key.0.clone()
    } else {
        return Err(Error::InvalidKey(jwk.key_type.to_string()));
    };
    let alg = header.algorithm.to_string();
    let salt = [alg.as_bytes(), &[0u8; 1], &p2s.0].concat();
    let key = match header.algorithm {
        JweAlgorithm::PBES2HS256A128KW => {
            let mut key = vec![0u8; 16];
            pbkdf2::<hmac::Hmac<sha2::Sha256>>(&password, &salt, p2c, &mut key)
                .map_err(|_| Error::InvalidKey(header.algorithm.to_string()))?;
            key
        }
        JweAlgorithm::PBES2HS384A192KW => {
            let mut key = vec![0u8; 24];
            pbkdf2::<hmac::Hmac<sha2::Sha384>>(&password, &salt, p2c, &mut key)
                .map_err(|_| Error::InvalidKey(header.algorithm.to_string()))?;
            key
        }
        JweAlgorithm::PBES2HS512A256KW => {
            let mut key = vec![0u8; 32];
            pbkdf2::<hmac::Hmac<sha2::Sha512>>(&password, &salt, p2c, &mut key)
                .map_err(|_| Error::InvalidKey(header.algorithm.to_string()))?;
            key
        }
        _ => return Err(Error::InvalidAlgorithm(header.algorithm.to_string())),
    };
    Ok(key)
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::jwa::JweAlgorithm;

    #[test]
    fn test_derive_key() {
        // Example from https://tools.ietf.org/html/rfc7518#appendix-C.1
        let salt: Vec<u8> = vec![
            217, 96, 147, 112, 150, 117, 70, 247, 127, 8, 155, 137, 174, 42, 80, 215,
        ];
        let mut header = JweHeader {
            algorithm: JweAlgorithm::PBES2HS256A128KW,
            p2_count: Some(4096),
            p2_salt_input: Some(ptypes::Base64urlUInt(salt)),
            ..Default::default()
        };

        let passphrase: [u8; 46] = [
            84, 104, 117, 115, 32, 102, 114, 111, 109, 32, 109, 121, 32, 108, 105, 112, 115, 44,
            32, 98, 121, 32, 121, 111, 117, 114, 115, 44, 32, 109, 121, 32, 115, 105, 110, 32, 105,
            115, 32, 112, 117, 114, 103, 101, 100, 46,
        ];
        let jwk = Jwk::create_oct(&passphrase).unwrap();
        let key = derive_key(&header, &jwk).unwrap();
        let expected: [u8; 16] = [
            110, 171, 169, 92, 129, 92, 109, 117, 233, 242, 116, 233, 170, 14, 24, 75,
        ];
        assert_eq!(&key, &expected);

        header.algorithm = JweAlgorithm::PBES2HS384A192KW;
        let key = derive_key(&header, &jwk).unwrap();
        assert_eq!(key.len(), 24);

        header.algorithm = JweAlgorithm::PBES2HS512A256KW;
        let key = derive_key(&header, &jwk).unwrap();
        assert_eq!(key.len(), 32);

        header.p2_salt_input = None;
        let key = derive_key(&header, &jwk);
        assert!(key.is_err());

        header.p2_count = None;
        let key = derive_key(&header, &jwk);
        assert!(key.is_err());
    }
}
