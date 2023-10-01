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

//! AES Key Wrapping.
//! https://tools.ietf.org/html/rfc3394
//!

#![deny(missing_docs)]

use super::{JweHeader, KeyWrapOrEncrypt};

use crate::{
    jwa::JweAlgorithm,
    jwk::{Jwk, KeyType},
    Error,
};

use aes::{Aes128, Aes192, Aes256};

use aes_kw::Kek;

/// AES Key Wrapper.
/// https://tools.ietf.org/html/rfc3394
///
pub struct AesKw;

impl KeyWrapOrEncrypt for AesKw {
    fn wrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        aeskw_wrap(&header.algorithm, cek, key)
    }

    fn unwrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        aeskw_unwrap(&header.algorithm, cek, key)
    }
}

/// AES Key Wrap.
pub fn aeskw_wrap(alg: &JweAlgorithm, payload: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    match alg {
        JweAlgorithm::A128KW | JweAlgorithm::ECDHESA128KW | JweAlgorithm::PBES2HS256A128KW => {
            let wrapper = Kek::<Aes128>::try_from(key)
                .map_err(|_| Error::InvalidKey("size != 16".to_string()))?;
            Ok(wrapper
                .wrap_vec(payload)
                .map_err(|_| Error::Encrypt("AESKW wrap".to_string()))?)
        }
        JweAlgorithm::A192KW | JweAlgorithm::ECDHESA192KW | JweAlgorithm::PBES2HS384A192KW => {
            let wrapper = Kek::<Aes192>::try_from(key)
                .map_err(|_| Error::InvalidKey("size != 24".to_string()))?;
            Ok(wrapper
                .wrap_vec(payload)
                .map_err(|_| Error::Encrypt("AESKW wrap".to_string()))?)
        }
        JweAlgorithm::A256KW | JweAlgorithm::ECDHESA256KW | JweAlgorithm::PBES2HS512A256KW => {
            let wrapper = Kek::<Aes256>::try_from(key)
                .map_err(|_| Error::InvalidKey("size != 32".to_string()))?;
            Ok(wrapper
                .wrap_vec(payload)
                .map_err(|_| Error::Encrypt("AESKW wrap".to_string()))?)
        }
        _ => Err(Error::InvalidAlgorithm(alg.to_string())),
    }
}

/// AES Key Unwrap.
pub fn aeskw_unwrap(alg: &JweAlgorithm, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, Error> {
    match alg {
        JweAlgorithm::A128KW | JweAlgorithm::ECDHESA128KW | JweAlgorithm::PBES2HS256A128KW => {
            let wrapper = Kek::<Aes128>::try_from(key)
                .map_err(|_| Error::InvalidKey("size != 16".to_string()))?;
            Ok(wrapper
                .unwrap_vec(ciphertext)
                .map_err(|_| Error::Decrypt("AESKW unwrap".to_string()))?)
        }
        JweAlgorithm::A192KW | JweAlgorithm::ECDHESA192KW | JweAlgorithm::PBES2HS384A192KW => {
            let wrapper = Kek::<Aes192>::try_from(key)
                .map_err(|_| Error::InvalidKey("size != 24".to_string()))?;
            Ok(wrapper
                .unwrap_vec(ciphertext)
                .map_err(|_| Error::Decrypt("AESKW unwrap".to_string()))?)
        }
        JweAlgorithm::A256KW | JweAlgorithm::ECDHESA256KW | JweAlgorithm::PBES2HS512A256KW => {
            let wrapper = Kek::<Aes256>::try_from(key)
                .map_err(|_| Error::InvalidKey("size != 32".to_string()))?;
            Ok(wrapper
                .unwrap_vec(ciphertext)
                .map_err(|_| Error::Decrypt("AESKW unwrap".to_string()))?)
        }
        _ => Err(Error::InvalidAlgorithm(alg.to_string())),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_wrap_unwrap_aes_kw() {
        let mut header = JweHeader::new(JweAlgorithm::A128KW, Default::default());

        let cek = b"0123456789abcdef";

        let key = b"0123456789abcdef";

        let jwk = Jwk::create_oct(key).unwrap();
        let wk = AesKw::wrap_key(&mut header, cek, &jwk).unwrap();
        let cek2 = AesKw::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());

        header.algorithm = JweAlgorithm::A192KW;
        let key = b"0123456789abcdef01234567";
        let jwk = Jwk::create_oct(key).unwrap();
        let wk = AesKw::wrap_key(&mut header, cek, &jwk).unwrap();
        let cek2 = AesKw::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());

        header.algorithm = JweAlgorithm::A256KW;
        let key = b"0123456789abcdef0123456789abcdef";
        let jwk = Jwk::create_oct(key).unwrap();
        let wk = AesKw::wrap_key(&mut header, cek, &jwk).unwrap();
        let cek2 = AesKw::unwrap_key(&mut header, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());

        let key = b"0123456789abcdef0123456789abcdef0123456789abcdef";
        let jwk = Jwk::create_oct(key).unwrap();
        header.algorithm = JweAlgorithm::A128KW;
        let wk = AesKw::wrap_key(&mut header, cek, &jwk);
        assert!(wk.is_err());
        let cek2 = AesKw::unwrap_key(&mut header, cek, &jwk);
        assert!(cek2.is_err());
        header.algorithm = JweAlgorithm::A192KW;
        let wk = AesKw::wrap_key(&mut header, cek, &jwk);
        assert!(wk.is_err());
        let cek2 = AesKw::unwrap_key(&mut header, cek, &jwk);
        assert!(cek2.is_err());
        header.algorithm = JweAlgorithm::A256KW;
        let wk = AesKw::wrap_key(&mut header, cek, &jwk);
        assert!(wk.is_err());
        let cek2 = AesKw::unwrap_key(&mut header, cek, &jwk);
        assert!(cek2.is_err());
    }
}
