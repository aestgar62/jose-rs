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

use super::JweEncryption;

use crate::{jwa::EncryptionAlgorithm, Error};

use aes::{Aes128, Aes192, Aes256};

use ::aes_gcm::{
    aead::{Aead, Payload},
    AesGcm, Key, KeyInit, Nonce,
    aead::generic_array::typenum::U12,
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
        match self.alg {
            EncryptionAlgorithm::A128GCM => {
                let key = Key::<AesGcm128>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let payload = Payload { msg: content, aad };
                let cipher = AesGcm128::new(key);
                let mut ct = cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("AES GCM".to_string()))?;
                let ct_len = ct.len() - 16;
                let tag = ct.split_off(ct_len);
                Ok((ct, tag))
            }
            EncryptionAlgorithm::A192GCM => {
                let key = Key::<AesGcm192>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let payload = Payload { msg: content, aad };
                let cipher = AesGcm192::new(key);
                let mut ct = cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("AES GCM".to_string()))?;
                let ct_len = ct.len() - 16;
                let tag = ct.split_off(ct_len);
                Ok((ct, tag))
            }
            EncryptionAlgorithm::A256GCM => {
                let key = Key::<AesGcm256>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let payload = Payload { msg: content, aad };
                let cipher = AesGcm256::new(key);
                let mut ct = cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| Error::Encrypt("AES GCM".to_string()))?;
                let ct_len = ct.len() - 16;
                let tag = ct.split_off(ct_len);
                Ok((ct, tag))
            }
            _ => Err(Error::InvalidAlgorithm(self.alg.to_string())),
        }
    }

    /// AES GCM decryption.
    fn decrypt(&self, content: &[u8], aad: &[u8], at: &[u8]) -> Result<Vec<u8>, Error> {
        match self.alg {
            EncryptionAlgorithm::A128GCM => {
                let key = Key::<AesGcm128>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let ciphertext = [content, at].concat();
                let payload = Payload {
                    msg: &ciphertext,
                    aad,
                };
                let cipher = AesGcm128::new(key);
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::Decrypt("AES GCM".to_string()))
            }
            EncryptionAlgorithm::A192GCM => {
                let key = Key::<AesGcm192>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let ciphertext = [content, at].concat();
                let payload = Payload {
                    msg: &ciphertext,
                    aad,
                };
                let cipher = AesGcm192::new(key);
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| Error::Decrypt("AES GCM".to_string()))
            }
            EncryptionAlgorithm::A256GCM => {
                let key = Key::<AesGcm256>::from_slice(&self.key);
                let nonce = Nonce::from_slice(&self.iv);
                let ciphertext = [content, at].concat();
                let payload = Payload {
                    msg: &ciphertext,
                    aad,
                };
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
}
