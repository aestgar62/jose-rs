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
pub mod wrap;

#[cfg(feature = "jwe-aes")]
pub use self::aes::{make_aes_cbc, make_aes_gcm};

use crate::{
    jwa::{EncryptionAlgorithm, JweAlgorithm},
    jwk::Jwk,
    utils::base64_decode_json,
    Error,
};

use generic_array::{
    typenum::{U12, U16, U32, U40, U48},
    ArrayLength, GenericArray,
};
use ptypes::{Base64urlUInt, Uri};

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

/// Encode JWE with default header
pub fn encode_compact_jwe_default(
    alg: JweAlgorithm,
    enc: EncryptionAlgorithm,
    jwk: &Jwk,
    payload: &[u8],
) -> Result<String, Error> {
    // create header
    let header = JweHeader {
        algorithm: alg,
        encryption: enc,
        ..Default::default()
    };

    encode_compact_jwe(&header, jwk, payload)
}

/// Encode JWE content
pub fn encode_compact_jwe(header: &JweHeader, jwk: &Jwk, payload: &[u8]) -> Result<String, Error> {
    let jwe_content = generate_jwe_content(header, jwk, payload)?;
    let b64_cek: Base64urlUInt = Base64urlUInt(jwe_content.1);
    let b64_iv = Base64urlUInt(jwe_content.2);
    let b64_ciphertext = Base64urlUInt(jwe_content.3);
    let b64_at = Base64urlUInt(jwe_content.4);

    let compact = format!(
        "{}.{}.{}.{}.{}",
        jwe_content.0, b64_cek, b64_iv, b64_ciphertext, b64_at
    );
    Ok(compact)
}

/// Decode compact JWE.
pub fn decode_compact_jwe(jwk: Jwk, jwe: &str) -> Result<Vec<u8>, Error> {
    let content = parse_jwe_content(jwe)?;
    extract_jwe_content(content)
    /*
    // get header bytes for AAD (Additional Authenticated Data)
    let header_bytes = parts[0].as_bytes();
    // get encoded header length bytes for Authenticated Tag
    let al_bytes = aad_length(header_bytes.len())?;

    let cek = unwrap_cek(&header, &jwk, &b64_cek.0)?;
    // concatenate header, iv, ciphertext and al_bytes for AAD
    let at = [header_bytes, &b64_iv.0, &b64_ciphertext.0, &al_bytes].concat();
    // Create a Sha256 HMAC instance
    let mut mac = Hmac::<Sha256>::new_from_slice(&cek[..16])
        .map_err(|_| Error::Decrypt("create HMAC".to_owned()))?;
    // Write input data
    mac.update(&at);
    // Read result (mac value) into result variable
    let result = mac.finalize().into_bytes();

    if result[..16] != b64_at.0[..] {
        return Err(Error::Decrypt("Invalid Authentication Tag".to_owned()));
    }

    let plaintext = decrypt_content(&header, &cek[16..], &b64_iv.0, &b64_ciphertext.0)?;

    //let plaintext =

    Ok(plaintext)*/
}

/// Parse JWE Content.
fn parse_jwe_content(content: &str) -> Result<JweContent, Error> {
    let parts: Vec<&str> = content.splitn(5, '.').collect();
    //let header: JweHeader = base64_decode_json(parts[0])?;
    let b64_cek = Base64urlUInt::try_from(parts[1].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
    let b64_iv = Base64urlUInt::try_from(parts[2].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
    let b64_ciphertext = Base64urlUInt::try_from(parts[3].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;
    let b64_at = Base64urlUInt::try_from(parts[4].to_owned())
        .map_err(|_| Error::Decode("base64url decode".to_owned()))?;

    Ok((
        parts[0].to_owned(),
        b64_cek.0,
        b64_iv.0,
        b64_ciphertext.0,
        b64_at.0,
    ))
}

/// JSON Web Encryption (JWE) represents encrypted content using JSON-based data structures.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweJson {
    /// The "protected" member contains the JWE Protected Header.
    #[serde(rename = "protected")]
    pub protected: String,
    /// The "unprotected" member contains the JWE Unprotected Header.
    #[serde(rename = "unprotected", skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<JweHeader>,
    /// The "recipients" member contains an array of JWE Encrypted Key values.
    #[serde(rename = "recipients")]
    pub recipients: Vec<JweRecipient>,
    /// The "aad" member contains the Additional Authenticated Data.
    #[serde(rename = "aad", skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
    /// The "iv" member contains the Initialization Vector.
    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    /// The "ciphertext" member contains the Ciphertext.
    #[serde(rename = "ciphertext", skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    /// The "tag" member contains the Authentication Tag.
    #[serde(rename = "tag", skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// The "recipients" member contains an array of JWE Encrypted Key values.
#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct JweRecipient {
    /// The "header" member contains the per-Recipient Header.
    #[serde(rename = "header", skip_serializing_if = "Option::is_none")]
    pub header: Option<JweHeader>,
    /// The "encrypted_key" member contains the Encrypted Key value.
    #[serde(rename = "encrypted_key", skip_serializing_if = "Option::is_none")]
    pub encrypted_key: Option<String>,
}

type JweContent = (String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Generates JWE Content.
pub fn generate_jwe_content(
    header: &JweHeader,
    jwk: &Jwk,
    content: &[u8],
) -> Result<JweContent, Error> {
    match header.encryption {
        #[cfg(feature = "jwe-aes-cbc")]
        EncryptionAlgorithm::A128CBCHS256 => {
            let rg = RandomGenerator::<U32, U16>::generate()?;
            make_aes_cbc(rg, header, jwk, content)
        }
        #[cfg(feature = "jwe-aes-cbc")]
        EncryptionAlgorithm::A192CBCHS384 => {
            let rg = RandomGenerator::<U40, U16>::generate()?;
            make_aes_cbc(rg, header, jwk, content)
        }
        #[cfg(feature = "jwe-aes-cbc")]
        EncryptionAlgorithm::A256CBCHS512 => {
            let rg = RandomGenerator::<U48, U16>::generate()?;
            make_aes_cbc(rg, header, jwk, content)
        }
        _ => Err(Error::UnimplementedAlgorithm(header.encryption.to_string())),
    }
}

/// Extract JWE Content.
pub fn extract_jwe_content(jwe_content: JweContent) -> Result<Vec<u8>, Error> {
    let header: JweHeader = base64_decode_json(&jwe_content.0)?;
    match &header.encryption {
        #[cfg(feature = "jwe-aes-cbc")]
        EncryptionAlgorithm::A128CBCHS256 |
        EncryptionAlgorithm::A192CBCHS384 |
        EncryptionAlgorithm::A256CBCHS512 => {
            Ok(Vec::new())
        }

        _ => Err(Error::UnimplementedAlgorithm(header.encryption.to_string())),

    }
}

/// Random Generator
#[derive(Default, Debug)]
pub struct RandomGenerator<K: ArrayLength<u8>, I: ArrayLength<u8>> {
    /// Encription Key array
    pub enc_key: GenericArray<u8, K>,
    /// Initilization vector array
    pub iv: GenericArray<u8, I>,
}

impl<K: ArrayLength<u8>, I: ArrayLength<u8>> RandomGenerator<K, I> {
    /// Create new Random Generator and generate random values.
    ///
    /// # Arguments
    ///
    /// * `with_mac` - Generate Mac Key or not.
    ///
    pub fn generate() -> Result<Self, Error> {
        let mut rg = Self::default();
        getrandom::getrandom(&mut rg.enc_key)
            .map_err(|_| Error::Random("getrandom for Encryption Key".to_owned()))?;
        getrandom::getrandom(&mut rg.iv)
            .map_err(|_| Error::Random("getrandom for Initialization Vector".to_owned()))?;
        Ok(rg)
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
    /*
        #[test]
        #[cfg(feature = "jwe-aes-hmac")]
        fn test_example_rfc7516_a3() {
            let msg = b"Live long and prosper.";
            let key = r#"
            {
                "kty":"oct",
                "k":"GawgguFyGrWKav7AX4VKUg"
            }"#;

            let key: Jwk = serde_json::from_str(key).unwrap();
            let compact = encode_compact_jwe(
                JweAlgorithm::A128KW,
                EncryptionAlgorithm::A128CBCHS256,
                &key,
                msg,
            );
            //let result = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ".to_owned();
            assert!(compact.is_ok());

            let compact = compact.unwrap();
            let result = decode_compact_jwe(key, &compact);
            assert!(result.is_ok());
            let result = result.unwrap();
            let text = String::from_utf8(result.clone()).unwrap();
            assert_eq!(text, "Live long and prosper.");
            assert_eq!(msg.to_vec(), result);
        }
    */
    #[test]
    fn test_random_generation() {
        use generic_array::typenum::{U16, U32};

        let generator = RandomGenerator::<U32, U16>::generate().unwrap();
        assert_eq!(generator.enc_key.len(), 32);
        assert_eq!(generator.iv.len(), 16);
    }
}
