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

//! # JSON Web Encryption (JWE)
//!
//! JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.
//!

#![deny(missing_docs)]

#[cfg(feature = "jwe-aes")]
pub mod aes;

use crate::{
    jwa::{EncryptionAlgorithm, JweAlgorithm},
    jwk::{Jwk, KeyType},
    utils::base64_encode_json,
    Error,
};

use ptypes::Uri;

use rsa::{Pkcs1v15Encrypt, Oaep, RsaPublicKey, RsaPrivateKey};
use serde::{Deserialize, Serialize};

/// For JWE, describe the encryption applied to the plaintext and optionally additional properties
/// of the JWE.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweHeader {
    /// The "alg" (algorithm) Header Parameter identifies the cryptographic algorithm used to
    /// encrypt or determine the value of the Content Encryption Key (CEK).
    #[serde(rename = "alg")]
    pub algorithm: JweAlgorithm,
    /// The "enc" (encryption algorithm) Header Parameter identifies the content encryption algorithm
    /// used to perform authenticated encryption on the plaintext to produce the ciphertext and the
    /// Authentication Tag.
    #[serde(rename = "enc")]
    pub encryption: EncryptionAlgorithm,
    /// The "zip" (compression algorithm) Header Parameter indicates whether the plaintext
    /// has been compressed before encryption.
    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,
    /// The "jku" (JWK Set URL) Header Parameter is a URI that refers to a resource for a set of
    /// JSON-encoded public keys, one of which corresponds to the key used to encrypt the JWE.
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub jwk_set_url: Option<Uri>,
    /// The "jwk" (JSON Web Key) Header Parameter is the public key that corresponds to the key
    /// used to encrypt the JWE.
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure the
    /// JWE.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The "x5u" (X.509 URL) Header Parameter is a URI that refers to a resource for the X.509
    /// public key certificate or certificate chain corresponding to the key used to encrypt the
    /// JWE.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<Uri>,
    /// The "x5c" (X.509 Certificate Chain) Header Parameter contains the X.509 public key  
    /// certificate or certificate chain corresponding to the key used to encrypt the JWE.
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_certificate_chain: Option<Vec<String>>,
    /// The "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter is a base64url-encoded
    /// SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(rename = "x5t", skip_serializing_if = "Option::is_none")]
    pub x509_certificate_sha1_thumbprint: Option<String>,
    /// The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter is a base64url-
    /// encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x509_certificate_sha256_thumbprint: Option<String>,
    /// The "typ" (type) Header Parameter is used by JWE applications to declare the media type
    /// [IANA.MediaTypes] of this complete JWE.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// The "cty" (content type) Header Parameter is used by JWE applications to declare the media
    /// type [IANA.MediaTypes] of the secured content (the plaintext) or to declare nested
    /// JWE objects.
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// The "crit" (critical) Header Parameter indicates that extensions to this specification
    /// and/or [JWA] are being used that MUST be understood and processed.
    #[serde(rename = "crit", skip_serializing_if = "Option::is_none")]
    pub critical: Option<Vec<String>>,
}

/// Encode JWE
pub fn encode_jwe(
    alg: JweAlgorithm,
    enc: EncryptionAlgorithm,
    jwk: Jwk,
    _payload: &[u8],
) -> Result<String, Error> {
    let header = JweHeader {
        algorithm: alg,
        encryption: enc,
        ..Default::default()
    };
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random("getrandom error".to_owned()))?;
    let _cek_encrypted = wrap_cek(&header, &jwk, &bytes)?;
    let protected = base64_encode_json(&header)?;

    Ok(protected)
}

/// Wrap Content Encryption Key (CEK).
fn wrap_cek(header: &JweHeader, jwk: &Jwk, key: &[u8]) -> Result<Vec<u8>, Error> {
    match header.algorithm {
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSA1_5 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                let pk = RsaPublicKey::try_from(rsa_data)?;
                let mut rng = rand::thread_rng();
                Ok(pk
                    .encrypt(&mut rng, Pkcs1v15Encrypt, key)
                    .map_err(|_| Error::Encrypt(JweAlgorithm::RSA1_5.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                use sha2::Sha256;
                let pk = RsaPublicKey::try_from(rsa_data)?;
                let mut rng = rand::thread_rng();
                let padding = Oaep::new::<Sha256>();
                Ok(pk
                    .encrypt(&mut rng, padding, key)
                    .map_err(|_| Error::Encrypt(JweAlgorithm::RSAOAEP.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP256 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                use sha2::Sha256;
                use sha1::Sha1;
                let pk = RsaPublicKey::try_from(rsa_data)?;
                let mut rng = rand::thread_rng();
                let padding = Oaep::new_with_mgf_hash::<Sha256, Sha1>();
                Ok(pk
                    .encrypt(&mut rng, padding, key)
                    .map_err(|_| Error::Encrypt(JweAlgorithm::RSAOAEP256.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A128KW => {
            use self::aes::wrap_a128kw;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                Ok(wrap_a128kw(key, &kw)?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A192KW => {
            use self::aes::wrap_a192kw;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                Ok(wrap_a192kw(key, &kw)?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A256KW => {
            use self::aes::wrap_a256kw;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                Ok(wrap_a256kw(key, &kw)?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        _ => Err(Error::UnimplementedAlgorithm(header.algorithm.to_string())),
    }
}

/// Unwrap Content Encryption Key (CEK).
pub fn unwrap_cek(header: &JweHeader, jwk: &Jwk, cek: &[u8]) -> Result<Vec<u8>, Error> {
    match header.algorithm {
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSA1_5 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                let sk = RsaPrivateKey::try_from(rsa_data)?;
                Ok(sk
                    .decrypt(Pkcs1v15Encrypt, cek)
                    .map_err(|_| Error::Decrypt(JweAlgorithm::RSA1_5.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                use sha2::Sha256;
                let sk = RsaPrivateKey::try_from(rsa_data)?;
                let padding = Oaep::new::<Sha256>();
                Ok(sk
                    .decrypt(padding, cek)
                    .map_err(|_| Error::Decrypt(JweAlgorithm::RSAOAEP.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwk-rsa")]
        JweAlgorithm::RSAOAEP256 => {
            if let KeyType::RSA(rsa_data) = &jwk.key_type {
                use sha2::Sha256;
                use sha1::Sha1;
                let sk = RsaPrivateKey::try_from(rsa_data)?;
                let padding = Oaep::new_with_mgf_hash::<Sha256, Sha1>();
                Ok(sk
                    .decrypt(padding, cek)
                    .map_err(|_| Error::Decrypt(JweAlgorithm::RSAOAEP256.to_string()))?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A128KW => {
            use self::aes::unwrap_a128kw;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                Ok(unwrap_a128kw(cek, &kw)?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A192KW => {
            use self::aes::unwrap_a192kw;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                Ok(unwrap_a192kw(cek, &kw)?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        #[cfg(feature = "jwe-aes-kw")]
        JweAlgorithm::A256KW => {
            use self::aes::unwrap_a256kw;
            if let KeyType::OCT(data) = &jwk.key_type {
                let kw = data.key.0.clone();
                Ok(unwrap_a256kw(cek, &kw)?)
            } else {
                Err(Error::InvalidKey("Invalid Key".to_string()))
            }
        }
        _ => Err(Error::UnimplementedAlgorithm(header.algorithm.to_string())),
    }
}


#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::base64_encode_json;

    #[test]
    fn test_jwe_header_default() {
        let header = JweHeader::default();
        assert_eq!(header.algorithm, JweAlgorithm::None);
        assert_eq!(header.encryption, EncryptionAlgorithm::None);
    }

    #[test]
    fn test_jwe_protected_header() {
        let protected = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".to_owned();
        let header = JweHeader {
            algorithm: JweAlgorithm::RSA1_5,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };
        assert_eq!(header.algorithm, JweAlgorithm::RSA1_5);
        assert_eq!(header.encryption, EncryptionAlgorithm::A128CBCHS256);
        let result = base64_encode_json(&header).unwrap();
        assert_eq!(result, protected);
    }

/*     #[test]
    #[cfg(feature = "jwe-aes-hmac")]
    fn test_a128_cbchs256() {
        use crate::utils::generate_random_bytes;
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
        type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

        let bytes = generate_random_bytes().unwrap();
        let mac_key = &bytes[..16];
        let enc_key = &bytes[16..];
        let mac_key: [u8; 16] = [
            4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206,
        ];

        let enc_key: [u8; 16] = [
            107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
        ];
        let iv: [u8; 16] = [
            3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
        ];
        //let iv = [0x24; 16];
        let plain: [u8; 22] = [
            76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115,
            112, 101, 114, 46,
        ];

        let pt_len = plain.len();
        let mut buf = [0u8; 48];
        buf[..pt_len].copy_from_slice(&plain);

        let ct = Aes128CbcEnc::new(&enc_key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len);

        let result: [u8; 32] = [
            40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223, 127,
            19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56, 102,
        ];

        assert_eq!(ct.unwrap(), result);

        let data: &[u8] = &[
            101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105,
            76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76,
            85, 104, 84, 77, 106, 85, 50, 73, 110, 48, 3, 22, 60, 12, 43, 67, 104, 105, 108, 108,
            105, 99, 111, 116, 104, 101, 40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24,
            152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56,
            102, 0, 0, 0, 0, 0, 0, 1, 152,
        ];

        let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
        mac.update(data);
        let mac_bytes = mac.finalize().into_bytes();

        println!("mac_bytes: {:?}", mac_bytes);
    }*/

    #[test]
    #[cfg(feature = "jwe-aes-hmac")]
    fn test_encrypt_cek() {
        use crate::jwk::Jwk;

        let msg = b"0123456789abcdef0123456789abcdef";

        let kp = Jwk::create_rsa().unwrap();
        let mut header = JweHeader {
            algorithm: JweAlgorithm::RSA1_5,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };

        let key = wrap_cek(&header, &kp, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &kp, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        header.algorithm = JweAlgorithm::RSAOAEP;
        let key = wrap_cek(&header, &kp, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &kp, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        header.algorithm = JweAlgorithm::RSAOAEP256;
        let key = wrap_cek(&header, &kp, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &kp, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());
        
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).unwrap();
        let sym = Jwk::create_oct(&bytes).unwrap();
        header.algorithm = JweAlgorithm::A128KW;
        let key = wrap_cek(&header, &sym, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &sym, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        let mut bytes = [0u8; 24];
        getrandom::getrandom(&mut bytes).unwrap();
        let sym = Jwk::create_oct(&bytes).unwrap();
        header.algorithm = JweAlgorithm::A192KW;
        let key = wrap_cek(&header, &sym, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &sym, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).unwrap();
        let sym = Jwk::create_oct(&bytes).unwrap();
        header.algorithm = JweAlgorithm::A256KW;
        let key = wrap_cek(&header, &sym, msg).unwrap();
        let unwrap_msg = unwrap_cek(&header, &sym, &key).unwrap();
        assert_eq!(msg, unwrap_msg.as_slice());

    }
}
