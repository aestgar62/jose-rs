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

//! # Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC) Mode
//!

#![deny(missing_docs)]

use crate::Error;

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{
        block_padding::Pkcs7, 
        BlockDecryptMut, 
        BlockEncryptMut, 
        KeyIvInit, 
    },
};


/// Wrap the given key with A128KW algorithm.
#[cfg(feature = "jwe-aes-kw")]
pub fn wrap_a128kw(key: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_kw::KekAes128;
    let kek = KekAes128::new(kw.into());
    kek.wrap_vec(key).map_err(|_| Error::Encrypt("A128KW".to_string()))
}

/// Unwrap the given cipherkey with A128KW algorithm.
#[cfg(feature = "jwe-aes-kw")]
pub fn unwrap_a128kw(cipherkey: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_kw::KekAes128;
    let kek = KekAes128::new(kw.into());
    kek.unwrap_vec(cipherkey).map_err(|_| Error::Decrypt("A128KW".to_string()))
}

/// Wrap the given key with A192KW algorithm.
#[cfg(feature = "jwe-aes-kw")]
pub fn wrap_a192kw(key: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_kw::KekAes192;
    let kek = KekAes192::new(kw.into());
    kek.wrap_vec(key).map_err(|_| Error::Encrypt("A192KW".to_string()))
}

/// Unwrap the given cipherkey with A192KW algorithm.
#[cfg(feature = "jwe-aes-kw")]
pub fn unwrap_a192kw(cipherkey: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_kw::KekAes192;
    let kek = KekAes192::new(kw.into());
    kek.unwrap_vec(cipherkey).map_err(|_| Error::Decrypt("A192KW".to_string()))
}

/// Wrap the given key with A256KW algorithm.
#[cfg(feature = "jwe-aes-kw")]
pub fn wrap_a256kw(key: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_kw::KekAes256;
    let kek = KekAes256::new(kw.into());
    kek.wrap_vec(key).map_err(|_| Error::Encrypt("A256KW".to_string()))
}

/// Unwrap the given cipherkey with A256KW algorithm.
#[cfg(feature = "jwe-aes-kw")]
pub fn unwrap_a256kw(cipherkey: &[u8], kw: &[u8]) -> Result<Vec<u8>, Error> {
    use aes_kw::KekAes256;
    let kek = KekAes256::new(kw.into());
    kek.unwrap_vec(cipherkey).map_err(|_| Error::Decrypt("A256KW".to_string()))
}


/// Encrypt the given plaintext with A128CBC-HS256 algorithm.
pub fn encrypt_a128cbchs256(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    type Aes128CbcEnc = cbc::Encryptor<Aes128>;
    if key.len() != 32 {
        return Err(Error::Encrypt("A128CBC-HS256 requires 32 bytes key length".to_string()));
    }
    let mac_key = &key[..16];
    let enc_key = &key[16..];    
    //let ct = Aes128CbcEnc::new(&enc_key.into(), &iv.into())
        //.encrypt_padded_mut::<Pkcs7>(&mut buf, pt_leletn);
    unimplemented!()
}

/// Decrypts the given ciphertext with Aes128Cbc algorithm.
pub fn decrypt_aes_128_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    type Aes128CbcDec = cbc::Decryptor<Aes128>;
    Aes128CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::Decrypt("Aes128Cbc".to_string()))
}

type Aes192CbcEnc = cbc::Encryptor<Aes192>;
type Aes192CbcDec = cbc::Decryptor<Aes192>;

/// Encrypts the given plaintext with Aes192Cbc algorithm.
pub fn encryp_aes_192_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    Aes192CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// Decrypts the given ciphertext with Aes192Cbc algorithm.
pub fn decrypt_aes_192_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    Aes192CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::Decrypt("Aes192Cbc".to_string()))
}

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Encrypts the given plaintext with Aes256Cbc algorithm.
pub fn encryp_aes_256_cbc(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    Aes256CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// Decrypts the given ciphertext with Aes256Cbc algorithm.
pub fn decrypt_aes_256_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| Error::Decrypt("Aes256Cbc".to_string()))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_wrap_a128kw() {
        let key = b"0123456789abcdef0123456789abcdef";
        let kw = b"0123456789abcdef";

        let cipherkey = wrap_a128kw(key, kw).unwrap();
        let decrypted = unwrap_a128kw(&cipherkey, kw).unwrap();

        assert_eq!(key, decrypted.as_slice());
    }   

    #[test]
    fn test_wrap_a192kw() {
        let key = b"0123456789abcdef0123456789abcdef";
        let kw = b"0123456789abcdef01234567";

        let cipherkey = wrap_a192kw(key, kw).unwrap();
        let decrypted = unwrap_a192kw(&cipherkey, kw).unwrap();

        assert_eq!(key, decrypted.as_slice());
    }

    #[test]
    fn test_wrap_a256kw() {
        let key = b"0123456789abcdef0123456789abcdef";
        let kw = b"0123456789abcdef0123456789abcdef";

        let cipherkey = wrap_a256kw(key, kw).unwrap();
        let decrypted = unwrap_a256kw(&cipherkey, kw).unwrap();

        assert_eq!(key, decrypted.as_slice());
    }

/*     #[test]
    fn test_aes_128_cbc() {
        let plaintext = b"Hello world!";
        let key = b"0123456789abcdef";
        let iv = b"0123456789abcdef";

        let ciphertext = encrypt_a128cbchs256(plaintext, key, iv).unwrap();
        let decrypted = decrypt_aes_128_cbc(&ciphertext, key, iv).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
*/
    #[test]
    fn test_aes_192_cbc() {
        let plaintext = b"Hello world!";
        let key = b"0123456789abcdef01234567";
        let iv = b"0123456789abcdef";

        let ciphertext = encryp_aes_192_cbc(plaintext, key, iv);
        let decrypted = decrypt_aes_192_cbc(&ciphertext, key, iv).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes_256_cbc() {
        let plaintext = b"Hello world!";
        let key = b"0123456789abcdef0123456789abcdef";
        let iv = b"0123456789abcdef";

        let ciphertext = encryp_aes_256_cbc(plaintext, key, iv);
        let decrypted = decrypt_aes_256_cbc(&ciphertext, key, iv).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }
        
}
