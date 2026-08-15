//! COSE public keys, in the two shapes passkeys are minted with (RFC 8152).
//!
//! A COSE key is a CBOR map with negative and small positive integer labels
//! rather than names: `1` is the key type, `3` the algorithm, and the negative
//! labels are type-specific parameters. Only what registration produces is
//! handled here — an EC2 key on P-256 (ES256) or an OKP key on Ed25519
//! (EdDSA).

use ed25519_dalek::Verifier as _;

use crate::Refusal;

/// COSE key type label (RFC 8152 §7.1).
const LABEL_KTY: i128 = 1;
/// COSE algorithm label.
const LABEL_ALG: i128 = 3;
/// EC2 / OKP curve label.
const LABEL_CRV: i128 = -1;
/// EC2 x coordinate, or OKP public key.
const LABEL_X: i128 = -2;
/// EC2 y coordinate.
const LABEL_Y: i128 = -3;

const KTY_OKP: i128 = 1;
const KTY_EC2: i128 = 2;

const ALG_ES256: i128 = -7;
const ALG_EDDSA: i128 = -8;

const CRV_P256: i128 = 1;
const CRV_ED25519: i128 = 6;

/// A credential's public key.
///
/// Stored parsed rather than as raw COSE bytes: a key that cannot be parsed
/// should be rejected at registration, when the user is present to be told,
/// not at unlock time when they are trying to get at their credentials.
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialPublicKey {
    /// ECDSA on P-256 with SHA-256 — what platform authenticators produce.
    Es256(Box<p256::ecdsa::VerifyingKey>),
    /// Ed25519 — what several password-manager authenticators produce.
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
}

impl CredentialPublicKey {
    /// Parse a COSE key from the tail of attested credential data.
    ///
    /// The input is the remainder of the buffer, which may have extension data
    /// after the key; CBOR is self-delimiting, so the decoder stops at the end
    /// of the map and the trailing bytes are ignored.
    pub fn from_cose(bytes: &[u8]) -> Result<Self, Refusal> {
        let value: ciborium::value::Value =
            ciborium::from_reader(bytes).map_err(|_| Refusal::UnsupportedAlgorithm)?;

        let kty = map_get_int(&value, LABEL_KTY).ok_or(Refusal::UnsupportedAlgorithm)?;
        let alg = map_get_int(&value, LABEL_ALG).ok_or(Refusal::UnsupportedAlgorithm)?;
        let crv = map_get_int(&value, LABEL_CRV).ok_or(Refusal::UnsupportedAlgorithm)?;

        match (kty, alg, crv) {
            (KTY_EC2, ALG_ES256, CRV_P256) => {
                let x =
                    map_get_label_bytes(&value, LABEL_X).ok_or(Refusal::UnsupportedAlgorithm)?;
                let y =
                    map_get_label_bytes(&value, LABEL_Y).ok_or(Refusal::UnsupportedAlgorithm)?;
                if x.len() != 32 || y.len() != 32 {
                    return Err(Refusal::UnsupportedAlgorithm);
                }
                // SEC1 uncompressed point: 0x04 ‖ x ‖ y.
                let mut sec1 = Vec::with_capacity(65);
                sec1.push(0x04);
                sec1.extend_from_slice(x);
                sec1.extend_from_slice(y);
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map_err(|_| Refusal::UnsupportedAlgorithm)?;
                Ok(CredentialPublicKey::Es256(Box::new(key)))
            }
            (KTY_OKP, ALG_EDDSA, CRV_ED25519) => {
                let x =
                    map_get_label_bytes(&value, LABEL_X).ok_or(Refusal::UnsupportedAlgorithm)?;
                let bytes: [u8; 32] = x.try_into().map_err(|_| Refusal::UnsupportedAlgorithm)?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| Refusal::UnsupportedAlgorithm)?;
                Ok(CredentialPublicKey::Ed25519(Box::new(key)))
            }
            _ => Err(Refusal::UnsupportedAlgorithm),
        }
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Refusal> {
        match self {
            CredentialPublicKey::Es256(key) => {
                // WebAuthn ES256 signatures are DER-encoded (W3C §6.5.6).
                let sig = p256::ecdsa::Signature::from_der(signature)
                    .map_err(|_| Refusal::BadSignature)?;
                key.verify(message, &sig).map_err(|_| Refusal::BadSignature)
            }
            CredentialPublicKey::Ed25519(key) => {
                let bytes: [u8; 64] = signature.try_into().map_err(|_| Refusal::BadSignature)?;
                let sig = ed25519_dalek::Signature::from_bytes(&bytes);
                key.verify(message, &sig).map_err(|_| Refusal::BadSignature)
            }
        }
    }

    /// The key as it should be stored alongside a vault slot: the COSE-free
    /// minimal encoding this module can read back.
    ///
    /// A fixed one-byte algorithm tag followed by the raw key, rather than
    /// re-encoding COSE — the vault stores what this crate parses, so the
    /// round trip stays inside one module instead of depending on an
    /// authenticator re-emitting an identical map.
    pub fn to_stored_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(66);
        match self {
            CredentialPublicKey::Es256(key) => {
                out.push(1);
                out.extend_from_slice(key.to_encoded_point(false).as_bytes());
            }
            CredentialPublicKey::Ed25519(key) => {
                out.push(2);
                out.extend_from_slice(key.as_bytes());
            }
        }
        out
    }

    /// Read back what [`CredentialPublicKey::to_stored_bytes`] wrote.
    pub fn from_stored_bytes(bytes: &[u8]) -> Result<Self, Refusal> {
        match bytes.split_first() {
            Some((1, rest)) => p256::ecdsa::VerifyingKey::from_sec1_bytes(rest)
                .map(|k| CredentialPublicKey::Es256(Box::new(k)))
                .map_err(|_| Refusal::UnsupportedAlgorithm),
            Some((2, rest)) => {
                let b: [u8; 32] = rest.try_into().map_err(|_| Refusal::UnsupportedAlgorithm)?;
                ed25519_dalek::VerifyingKey::from_bytes(&b)
                    .map(|k| CredentialPublicKey::Ed25519(Box::new(k)))
                    .map_err(|_| Refusal::UnsupportedAlgorithm)
            }
            _ => Err(Refusal::UnsupportedAlgorithm),
        }
    }
}

/// Look up a text-keyed entry in a CBOR map and return its bytes.
pub(crate) fn map_get_bytes<'a>(value: &'a ciborium::value::Value, key: &str) -> Option<&'a [u8]> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .and_then(|(_, v)| v.as_bytes())
        .map(Vec::as_slice)
}

/// Look up an integer-labelled entry and return it as an integer.
fn map_get_int(value: &ciborium::value::Value, label: i128) -> Option<i128> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(label))
        .and_then(|(_, v)| v.as_integer())
        .map(i128::from)
}

/// Look up an integer-labelled entry and return its bytes.
fn map_get_label_bytes(value: &ciborium::value::Value, label: i128) -> Option<&[u8]> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(label))
        .and_then(|(_, v)| v.as_bytes())
        .map(Vec::as_slice)
}
