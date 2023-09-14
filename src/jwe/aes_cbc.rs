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

//! AES_CBC_HMAC_SHA2 Algorithms.
//!
//! AES [AES] in Cipher Block Chaining (CBC) mode [NIST.800-38A] with PKCS #7 padding operations
//! per Section 6.3 of [RFC5652] and HMAC ([RFC2104] and [SHS]) operations
//!
//! https://tools.ietf.org/html/rfc7518#section-5.2
//!

use super::{JweEncryption, RandomGenerator};

use crate::{jwa::EncryptionAlgorithm, Error};

use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Aes128, Aes192, Aes256,
};

use hmac::{Hmac, Mac};

use generic_array::typenum::{U16, U32, U48, U64};
use sha2::{Sha256, Sha384, Sha512};

use zeroize::Zeroize;

// AES CBC types.
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes192CbcEnc = cbc::Encryptor<Aes192>;
type Aes192CbcDec = cbc::Decryptor<Aes192>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// AES CBC HMAC SHA2 Encryptor.
/// [AES_CBC_HMAC_SHA2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2)
#[derive(Clone, Debug, Zeroize)]
pub struct AesCbcEncryptor {
    /// Encryption algorithm.
    alg: EncryptionAlgorithm,
    /// AES key.
    pub key: Vec<u8>,
    /// AES initialization vector.
    pub iv: Vec<u8>,
}

impl JweEncryption for AesCbcEncryptor {
    fn from_random(alg: EncryptionAlgorithm) -> Result<Self, Error> {
        let enc = match alg {
            EncryptionAlgorithm::A128CBCHS256 => {
                let rg = RandomGenerator::<U32, U16>::generate()?;
                Self {
                    alg,
                    key: rg.enc_key.to_vec(),
                    iv: rg.iv.to_vec(),
                }
            }
            EncryptionAlgorithm::A192CBCHS384 => {
                let rg = RandomGenerator::<U48, U16>::generate()?;
                Self {
                    alg,
                    key: rg.enc_key.to_vec(),
                    iv: rg.iv.to_vec(),
                }
            }
            EncryptionAlgorithm::A256CBCHS512 => {
                let rg = RandomGenerator::<U64, U16>::generate()?;
                Self {
                    alg,
                    key: rg.enc_key.to_vec(),
                    iv: rg.iv.to_vec(),
                }
            }
            _ => return Err(Error::InvalidAlgorithm(alg.to_string())),
        };
        Ok(enc)
    }

    fn from_slice(alg: EncryptionAlgorithm, cek: &[u8], iv: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let enc = match alg {
            EncryptionAlgorithm::A128CBCHS256 => {
                if cek.len() != 32 || iv.len() != 16 {
                    return Err(Error::InvalidKey("slide size".to_string()));
                }
                Self {
                    alg,
                    key: cek.to_owned(),
                    iv: iv.to_owned(),
                }
            }
            EncryptionAlgorithm::A192CBCHS384 => {
                if cek.len() != 48 || iv.len() != 16 {
                    return Err(Error::InvalidKey("slice size".to_string()));
                }
                Self {
                    alg,
                    key: cek.to_owned(),
                    iv: iv.to_owned(),
                }
            }
            EncryptionAlgorithm::A256CBCHS512 => {
                if cek.len() != 64 || iv.len() != 16 {
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

    /// AES CBC encryption.
    /// [AES_CBC_HMAC_SHA2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.1)
    fn encrypt(&self, content: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match self.alg {
            EncryptionAlgorithm::A128CBCHS256 => {
                let key = generic_array::GenericArray::from_slice(&self.key[16..]);
                let iv = generic_array::GenericArray::from_slice(&self.iv);
                let ct = Aes128CbcEnc::new(key, iv).encrypt_padded_vec_mut::<Pkcs7>(content);
                let al = ((aad.len() * 8) as u64).to_be_bytes();
                let input_hmac = [aad, iv, &ct, &al].concat();
                let mut mac = Hmac::<Sha256>::new_from_slice(&key[0..16])
                    .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
                mac.update(&input_hmac);
                let result = mac.finalize().into_bytes();
                Ok((ct, result[..16].to_vec()))
            }
            EncryptionAlgorithm::A192CBCHS384 => {
                let key = generic_array::GenericArray::from_slice(&self.key[24..]);
                let iv = generic_array::GenericArray::from_slice(&self.iv);
                let ct = Aes192CbcEnc::new(key, iv).encrypt_padded_vec_mut::<Pkcs7>(content);
                let al = ((aad.len() * 8) as u64).to_be_bytes();
                let input_hmac = [aad, iv, &ct, &al].concat();
                let mut mac = Hmac::<Sha384>::new_from_slice(&key[..24])
                    .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
                mac.update(&input_hmac);
                let result = mac.finalize().into_bytes();
                Ok((ct, result[..24].to_vec()))
            }
            EncryptionAlgorithm::A256CBCHS512 => {
                let key = generic_array::GenericArray::from_slice(&self.key[32..]);
                let iv = generic_array::GenericArray::from_slice(&self.iv);
                let ct = Aes256CbcEnc::new(key, iv).encrypt_padded_vec_mut::<Pkcs7>(content);
                let al = ((aad.len() * 8) as u64).to_be_bytes();
                let input_hmac = [aad, iv, &ct, &al].concat();
                let mut mac = Hmac::<Sha512>::new_from_slice(&key[..32])
                    .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
                mac.update(&input_hmac);
                let result = mac.finalize().into_bytes();
                Ok((ct, result[..32].to_vec()))
            }
            _ => Err(Error::InvalidAlgorithm(self.alg.to_string())),
        }
    }

    /// AES CBC decryption.
    /// [AES_CBC_HMAC_SHA2](https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.2)
    fn decrypt(&self, content: &[u8], aad: &[u8], at: &[u8]) -> Result<Vec<u8>, Error> {
        match self.alg {
            EncryptionAlgorithm::A128CBCHS256 => {
                let key = generic_array::GenericArray::from_slice(&self.key[16..]);
                let iv = generic_array::GenericArray::from_slice(&self.iv);
                let ct = Aes128CbcDec::new(key, iv)
                    .decrypt_padded_vec_mut::<Pkcs7>(content)
                    .map_err(|_| Error::Decrypt("AES CBC".to_string()))?;
                let al = ((aad.len() * 8) as u64).to_be_bytes();
                let input_hmac = [aad, iv, content, &al].concat();
                let mut mac = Hmac::<Sha256>::new_from_slice(&key[0..16])
                    .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
                mac.update(&input_hmac);
                let result = mac.finalize().into_bytes();
                if result[..16] != at[..] {
                    return Err(Error::Decrypt("AES CBC HMAC invalid".to_string()));
                }
                Ok(ct)
            }
            EncryptionAlgorithm::A192CBCHS384 => {
                let key = generic_array::GenericArray::from_slice(&self.key[24..]);
                let iv = generic_array::GenericArray::from_slice(&self.iv);
                let ct = Aes192CbcDec::new(key, iv)
                    .decrypt_padded_vec_mut::<Pkcs7>(content)
                    .map_err(|_| Error::Decrypt("AES CBC".to_string()))?;
                let al = ((aad.len() * 8) as u64).to_be_bytes();
                let input_hmac = [aad, iv, &ct, &al].concat();
                let mut mac = Hmac::<Sha384>::new_from_slice(&key[0..24])
                    .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
                mac.update(&input_hmac);
                let result = mac.finalize().into_bytes();
                if result[..24] != at[..] {
                    return Err(Error::Decrypt("AES CBC HMAC invalid".to_string()));
                }
                Ok(ct)
            }
            EncryptionAlgorithm::A256CBCHS512 => {
                let key = generic_array::GenericArray::from_slice(&self.key[32..]);
                let iv = generic_array::GenericArray::from_slice(&self.iv);
                let ct = Aes256CbcDec::new(key, iv)
                    .decrypt_padded_vec_mut::<Pkcs7>(content)
                    .map_err(|_| Error::Decrypt("AES CBC".to_string()))?;
                let al = ((aad.len() * 8) as u64).to_be_bytes();
                let input_hmac = [aad, iv, &ct, &al].concat();
                let mut mac = Hmac::<Sha512>::new_from_slice(&key[0..32])
                    .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
                mac.update(&input_hmac);
                let result = mac.finalize().into_bytes();
                if result[..32] != at[..] {
                    return Err(Error::Decrypt("AES CBC HMAC invalid".to_string()));
                }

                Ok(ct)
            }
            _ => Err(Error::InvalidAlgorithm(self.alg.to_string())),
        }
    }
}

impl Drop for AesCbcEncryptor {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_aes_cbc() {
        use crate::{
            jwa::{EncryptionAlgorithm, JweAlgorithm},
            jwe::JweHeader,
        };

        let mut header = JweHeader {
            algorithm: JweAlgorithm::A128KW,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };
        let aad = header.to_aad().unwrap();
        let cek = b"0123456789abcdef0123456789abcdef";
        let iv = b"0123456789abcdef";
        let content = b"Hello world!";
        let alg = EncryptionAlgorithm::A128CBCHS256;
        let enc = AesCbcEncryptor::from_slice(alg, cek, iv).unwrap();
        let (ct, at) = enc.encrypt(content, &aad).unwrap();
        let dec = enc.decrypt(&ct, &aad, &at).unwrap();
        assert_eq!(content, dec.as_slice());

        header.encryption = EncryptionAlgorithm::A192CBCHS384;
        let (ct, at) = enc.encrypt(content, &aad).unwrap();
        let dec = enc.decrypt(&ct, &aad, &at).unwrap();
        assert_eq!(content, dec.as_slice());

        header.encryption = EncryptionAlgorithm::A256CBCHS512;
        let (ct, at) = enc.encrypt(content, &aad).unwrap();
        let dec = enc.decrypt(&ct, &aad, &at).unwrap();
        assert_eq!(content, dec.as_slice());
    }
}
