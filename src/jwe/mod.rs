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

#[cfg(feature = "aes-cbc")]
pub mod aes_cbc;

use crate::{
    jwa::{EncryptionAlgorithm, JweAlgorithm},
    jwk::Jwk,
    utils::base64_encode_json,
    Error,
};

use ptypes::Uri;

use serde::{Deserialize, Serialize};

/// For JWE, describe the encryption applied to the plaintext and optionally additional properties
/// of the JWE.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweHeader {
    /// The "alg" (algorithm) Header Parameter identifies the cryptographic algorithm used to
    /// encrypt or determine the value of the Content Encryption Key (CEK).
    #[serde(rename = "alg")]
    pub algorithms: JweAlgorithm,
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

impl Default for JweHeader {
    fn default() -> Self {
        Self {
            algorithms: JweAlgorithm::default(),
            encryption: EncryptionAlgorithm::default(),
            compression: None,
            jwk_set_url: None,
            jwk: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            media_type: None,
            content_type: None,
            critical: None,
        }
    }
}

/// Encode JWE Protected Header
pub fn encode_jwe_protected_header(header: &JweHeader) -> Result<String, Error> {
    let protected = base64_encode_json(&header)?;
    Ok(protected)
}

/// Encode JWE
pub fn encode_jwe(
    alg: JweAlgorithm,
    enc: EncryptionAlgorithm,
    kwy: Jwk,
    payload: &[u8],
) -> Result<String, Error> {
    let header = JweHeader {
        algorithms: alg,
        encryption: enc,
        ..Default::default()
    };
    let protected = base64_encode_json(&header)?;

    Ok(protected)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::utils::base64_encode_json;

    #[test]
    fn test_jwe_header_default() {
        let header = JweHeader::default();
        assert_eq!(header.algorithms, JweAlgorithm::None);
        assert_eq!(header.encryption, EncryptionAlgorithm::None);
    }

    #[test]
    fn test_jwe_protected_header() {
        let protected = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0".to_owned();
        let header = JweHeader {
            algorithms: JweAlgorithm::RSA1_5,
            encryption: EncryptionAlgorithm::A128CBCHS256,
            ..Default::default()
        };
        assert_eq!(header.algorithms, JweAlgorithm::RSA1_5);
        assert_eq!(header.encryption, EncryptionAlgorithm::A128CBCHS256);
        let result = base64_encode_json(&header).unwrap();
        assert_eq!(result, protected);
    }

    #[test]
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
    }
}
