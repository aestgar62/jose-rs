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

use super::KeyWrapper;

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

impl KeyWrapper for AesKw {
    fn wrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let wk = match alg {
            JweAlgorithm::A128KW => {
                let wrapper = Kek::<Aes128>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 16".to_string()))?;
                wrapper
                    .wrap_vec(cek)
                    .map_err(|_| Error::Encrypt("AESKW wrap".to_string()))?
            }
            JweAlgorithm::A192KW => {
                let wrapper = Kek::<Aes192>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 24".to_string()))?;
                wrapper
                    .wrap_vec(cek)
                    .map_err(|_| Error::Encrypt("AESKW wrap".to_string()))?
            }
            JweAlgorithm::A256KW => {
                let wrapper = Kek::<Aes256>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 32".to_string()))?;
                wrapper
                    .wrap_vec(cek)
                    .map_err(|_| Error::Encrypt("AESKW wrap".to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(alg.to_string())),
        };
        Ok(wk)
    }

    fn unwrap_key(alg: JweAlgorithm, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let cek = match alg {
            JweAlgorithm::A128KW => {
                let wrapper = Kek::<Aes128>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 16".to_string()))?;
                wrapper
                    .unwrap_vec(cek)
                    .map_err(|_| Error::Decrypt("AESKW unwrap".to_string()))?
            }
            JweAlgorithm::A192KW => {
                let wrapper = Kek::<Aes192>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 24".to_string()))?;
                wrapper
                    .unwrap_vec(cek)
                    .map_err(|_| Error::Decrypt("AESKW unwrap".to_string()))?
            }
            JweAlgorithm::A256KW => {
                let wrapper = Kek::<Aes256>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey("size != 32".to_string()))?;
                wrapper
                    .unwrap_vec(cek)
                    .map_err(|_| Error::Decrypt("AESKW unwrap".to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(alg.to_string())),
        };
        Ok(cek)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_wrap_unwrap_aes_kw() {
        let cek = b"0123456789abcdef";

        let key = b"0123456789abcdef";
        let jwk = Jwk::create_oct(key).unwrap();
        let wk = AesKw::wrap_key(JweAlgorithm::A128KW, cek, &jwk).unwrap();
        let cek2 = AesKw::unwrap_key(JweAlgorithm::A128KW, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());

        let key = b"0123456789abcdef01234567";
        let jwk = Jwk::create_oct(key).unwrap();
        let wk = AesKw::wrap_key(JweAlgorithm::A192KW, cek, &jwk).unwrap();
        let cek2 = AesKw::unwrap_key(JweAlgorithm::A192KW, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());

        let key = b"0123456789abcdef0123456789abcdef";
        let jwk = Jwk::create_oct(key).unwrap();
        let wk = AesKw::wrap_key(JweAlgorithm::A256KW, cek, &jwk).unwrap();
        let cek2 = AesKw::unwrap_key(JweAlgorithm::A256KW, &wk, &jwk).unwrap();
        assert_eq!(cek.as_slice(), cek2.as_slice());

        let key = b"0123456789abcdef0123456789abcdef0123456789abcdef";
        let jwk = Jwk::create_oct(key).unwrap();
        let wk = AesKw::wrap_key(JweAlgorithm::A128KW, cek, &jwk);
        assert!(wk.is_err());
        let cek2 = AesKw::unwrap_key(JweAlgorithm::A128KW, cek, &jwk);
        assert!(cek2.is_err());
        let wk = AesKw::wrap_key(JweAlgorithm::A192KW, cek, &jwk);
        assert!(wk.is_err());
        let cek2 = AesKw::unwrap_key(JweAlgorithm::A192KW, cek, &jwk);
        assert!(cek2.is_err());
        let wk = AesKw::wrap_key(JweAlgorithm::A256KW, cek, &jwk);
        assert!(wk.is_err());
        let cek2 = AesKw::unwrap_key(JweAlgorithm::A256KW, cek, &jwk);
        assert!(cek2.is_err());
    }
}
