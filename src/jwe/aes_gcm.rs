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

//! AES GCM Encryption.
//! https://tools.ietf.org/html/rfc7518#section-5.3
//!

use super::{JweEncryption, JweHeader, KeyWrapOrEncrypt};

use crate::{
    jwa::{EncryptionAlgorithm, JweAlgorithm},
    jwk::Jwk,
    Error,
};

use ptypes::Base64urlUInt;

use aead::AeadCore;
use aes::{Aes128, Aes192, Aes256};

use ::aes_gcm::{
    aead::generic_array::typenum::U12,
    aead::{Aead, Payload},
    AesGcm, Key, KeyInit, Nonce,
};

use zeroize::Zeroize;

type AesGcm128 = AesGcm<Aes128, U12>;
type AesGcm192 = AesGcm<Aes192, U12>;
type AesGcm256 = AesGcm<Aes256, U12>;

/// AES GCM Encryptor.
/// [AES_GCM](https://www.rfc-editor.org/rfc/rfc7518#section-5.3)
#[derive(Clone, Debug, Zeroize)]
pub struct AesGcmEncryptor {
    /// Encryption algorithm.
    alg: EncryptionAlgorithm,
    /// AES key.
    pub key: Vec<u8>,
    /// AES initialization vector.
    pub iv: Vec<u8>,
}

impl JweEncryption for AesGcmEncryptor {
    fn from_slice(alg: EncryptionAlgorithm, cek: &[u8], iv: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let enc = match alg {
            EncryptionAlgorithm::A128GCM => {
                if cek.len() != 16 || iv.len() != 12 {
                    return Err(Error::InvalidKey("slice size".to_string()));
                }
                Self {
                    alg,
                    key: cek.to_owned(),
                    iv: iv.to_owned(),
                }
            }
            EncryptionAlgorithm::A192GCM => {
                if cek.len() != 24 || iv.len() != 12 {
                    return Err(Error::InvalidKey("slice size".to_string()));
                }
                Self {
                    alg,
                    key: cek.to_owned(),
                    iv: iv.to_owned(),
                }
            }
            EncryptionAlgorithm::A256GCM => {
                if cek.len() != 32 || iv.len() != 12 {
                    return Err(Error::InvalidKey("slice size".to_string()));
                }
                Self {
                    alg,
                    key: cek.to_owned(),
                    iv: iv.to_owned(),
                }
            }
            _ => return Err(Error::InvalidAlgorithm(alg.to_string())),
        };
        Ok(enc)
    }

    /// AES GCM encryption.
    fn encrypt(&self, content: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let payload = Payload { msg: content, aad };
        let mut ct = match self.alg {
            EncryptionAlgorithm::A128GCM => {
                let key = Key::<AesGcm128>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let cipher = AesGcm128::new(key);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("AES GCM".to_string()))?
            }
            EncryptionAlgorithm::A192GCM => {
                let key = Key::<AesGcm192>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let cipher = AesGcm192::new(key);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("AES GCM".to_string()))?
            }
            EncryptionAlgorithm::A256GCM => {
                let key = Key::<AesGcm256>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let cipher = AesGcm256::new(key);
                cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("AES GCM".to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(self.alg.to_string())),
        };
        let ct_len = ct.len() - 16;
        let tag = ct.split_off(ct_len);
        Ok((ct, tag))
    }

    /// AES GCM decryption.
    fn decrypt(&self, content: &[u8], aad: &[u8], at: &[u8]) -> Result<Vec<u8>, Error> {
        let ciphertext = [content, at].concat();
        let payload = Payload {
            msg: &ciphertext,
            aad,
        };
        match self.alg {
            EncryptionAlgorithm::A128GCM => {
                let key = Key::<AesGcm128>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let cipher = AesGcm128::new(key);
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::Decrypt("AES GCM".to_string()))
            }
            EncryptionAlgorithm::A192GCM => {
                let key = Key::<AesGcm192>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let cipher = AesGcm192::new(key);
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::Decrypt("AES GCM".to_string()))
            }
            EncryptionAlgorithm::A256GCM => {
                let key = Key::<AesGcm256>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let cipher = AesGcm256::new(key);
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::Decrypt("AES GCM".to_string()))
            }
            _ => Err(Error::InvalidAlgorithm(self.alg.to_string())),
        }
    }
}

impl Drop for AesGcmEncryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

/// AES GCM Key Wrapper.
pub struct AesGcmKw;

impl KeyWrapOrEncrypt for AesGcmKw {
    fn wrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        use rand_core::OsRng;
        let key = if let crate::jwk::KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let iv = AesGcm128::generate_nonce(&mut OsRng);
        let payload = Payload { msg: cek, aad: b"" };
        let mut ct = match header.algorithm {
            JweAlgorithm::A128GCMKW => {
                let cipher = AesGcm128::new(Key::<AesGcm128>::from_slice(key));
                cipher
                    .encrypt(&iv, payload)
                    .map_err(|_| Error::Encrypt(header.algorithm.to_string()))?
            }
            JweAlgorithm::A192GCMKW => {
                let cipher = AesGcm192::new(Key::<AesGcm192>::from_slice(key));
                cipher
                    .encrypt(&iv, payload)
                    .map_err(|_| Error::Encrypt(header.algorithm.to_string()))?
            }
            JweAlgorithm::A256GCMKW => {
                let cipher = AesGcm256::new(Key::<AesGcm256>::from_slice(key));
                cipher
                    .encrypt(&iv, payload)
                    .map_err(|_| Error::Encrypt(header.algorithm.to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(header.algorithm.to_string())),
        };
        let ct_len = ct.len() - 16;
        let tag = ct.split_off(ct_len);
        header.initialization_vector = Some(Base64urlUInt(iv.to_vec()));
        header.authentication_tag = Some(Base64urlUInt(tag));
        Ok(ct)
    }

    fn unwrap_key(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) -> Result<Vec<u8>, Error> {
        let key = if let crate::jwk::KeyType::OCT(key_data) = &jwk.key_type {
            &key_data.key.0
        } else {
            return Err(Error::InvalidKey(jwk.key_type.to_string()));
        };
        let iv = if let Some(iv) = &header.initialization_vector {
            Nonce::from_slice(&iv.0)
        } else {
            return Err(Error::InvalidHeader(
                "missing initialization vector for AESGMCKW".to_owned(),
            ));
        };
        let tag = if let Some(tag) = &header.authentication_tag {
            &tag.0
        } else {
            return Err(Error::InvalidHeader(
                "missing authentication tag for AESGMCKW".to_owned(),
            ));
        };
        let cipher_text = [cek, tag].concat();
        let payload = Payload {
            msg: &cipher_text,
            aad: b"",
        };
        let ct = match header.algorithm {
            JweAlgorithm::A128GCMKW => {
                let cipher = AesGcm128::new(Key::<AesGcm128>::from_slice(key));
                cipher
                    .decrypt(iv, payload)
                    .map_err(|_| Error::Decrypt(header.algorithm.to_string()))?
            }
            JweAlgorithm::A192GCMKW => {
                let cipher = AesGcm192::new(Key::<AesGcm192>::from_slice(key));
                cipher
                    .decrypt(iv, payload)
                    .map_err(|_| Error::Decrypt(header.algorithm.to_string()))?
            }
            JweAlgorithm::A256GCMKW => {
                let cipher = AesGcm256::new(Key::<AesGcm256>::from_slice(key));
                cipher
                    .decrypt(iv, payload)
                    .map_err(|_| Error::Decrypt(header.algorithm.to_string()))?
            }
            _ => return Err(Error::InvalidAlgorithm(header.algorithm.to_string())),
        };
        Ok(ct)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_aes_gcm_128() {
        use crate::{
            jwa::{EncryptionAlgorithm, JweAlgorithm},
            jwe::JweHeader,
        };

        let mut header = JweHeader {
            algorithm: JweAlgorithm::A128KW,
            encryption: EncryptionAlgorithm::A128GCM,
            ..Default::default()
        };
        let aad = header.to_aad().unwrap();
        let cek = b"0123456789abcdef";
        let iv = b"0123456789ab";
        let content = b"Hello world!";
        let enc = AesGcmEncryptor::from_slice(header.encryption, cek, iv).unwrap();
        let (ct, tag) = enc.encrypt(content, &aad).unwrap();
        let ct2 = enc.decrypt(&ct, &aad, &tag).unwrap();
        assert_eq!(content, ct2.as_slice());
        let result = enc.decrypt(&ct, &aad, b"1234567890123456");
        assert!(result.is_err());

        header.encryption = EncryptionAlgorithm::A192GCM;
        let cek = b"0123456789abcdef01234567";
        let enc = AesGcmEncryptor::from_slice(header.encryption, cek, iv).unwrap();
        let (ct, tag) = enc.encrypt(content, &aad).unwrap();
        let ct2 = enc.decrypt(&ct, &aad, &tag).unwrap();
        assert_eq!(content, ct2.as_slice());
        let result = enc.decrypt(&ct, &aad, b"1234567890123456");
        assert!(result.is_err());

        header.encryption = EncryptionAlgorithm::A256GCM;
        let cek = b"0123456789abcdef0123456789abcdef";
        let enc = AesGcmEncryptor::from_slice(header.encryption, cek, iv).unwrap();
        let (ct, tag) = enc.encrypt(content, &aad).unwrap();
        let ct2 = enc.decrypt(&ct, &aad, &tag).unwrap();
        assert_eq!(content, ct2.as_slice());
        let result = enc.decrypt(&ct, &aad, b"1234567890123456");
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_gcm_kw() {
        use crate::{
            jwa::{EncryptionAlgorithm, JweAlgorithm},
            jwe::JweHeader,
            jwk::Jwk,
        };

        let mut header = JweHeader {
            algorithm: JweAlgorithm::A128GCMKW,
            encryption: EncryptionAlgorithm::None,
            ..Default::default()
        };
        let cek = b"0123456789abcdef";
        let jwk = Jwk::create_oct(b"0123456789abcdef").unwrap();
        test_aesgcmkw(&mut header, cek, &jwk);

        header.algorithm = JweAlgorithm::A192GCMKW;
        let jwk = Jwk::create_oct(b"0123456789abcdef01234567").unwrap();
        test_aesgcmkw(&mut header, cek, &jwk);

        header.algorithm = JweAlgorithm::A256GCMKW;
        let jwk = Jwk::create_oct(b"0123456789abcdef0123456789abcdef").unwrap();
        test_aesgcmkw(&mut header, cek, &jwk);
    }

    fn test_aesgcmkw(header: &mut JweHeader, cek: &[u8], jwk: &Jwk) {
        let ct = AesGcmKw::wrap_key(header, cek, jwk).unwrap();
        assert!(header.initialization_vector.is_some());
        assert!(header.authentication_tag.is_some());
        let cek2 = AesGcmKw::unwrap_key(header, &ct, jwk).unwrap();
        assert_eq!(cek, cek2.as_slice());
    }
}
