//! A software authenticator, for testing a ceremony without a browser.
//!
//! Shipped in the crate rather than kept in its test module because the
//! ceremony this crate verifies is driven by the daemon, and the daemon's own
//! tests need an authenticator to drive it with (DR-0034 Open Q5 names this as
//! the automated test path: the assertion and its PRF are constructed from
//! public specifications, so a stand-in built from raw key material is
//! indistinguishable from a real one to everything downstream).
//!
//! It is a **test double, not an authenticator**: keys live in ordinary
//! memory, nothing is user-verified for real, and the PRF is a hash rather
//! than the CTAP2 hmac-secret construction. Its value is that the *shapes* are
//! exact — the same byte layouts, the same signature input, the same
//! per-credential PRF separation — so code that satisfies it is code that
//! satisfies a real authenticator, up to the key material's provenance.

use ciborium::value::Value;
use p256::ecdsa::signature::Signer as _;
use sha2::{Digest, Sha256};

use crate::AssertionResponse;

/// Which signature algorithm a test credential uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA P-256 with SHA-256, as platform authenticators produce.
    Es256,
    /// Ed25519, as several password-manager authenticators produce.
    Ed25519,
}

/// One assertion, in the pieces the browser hands to a page.
pub struct SoftAssertion {
    /// The credential that produced it.
    pub credential_id: Vec<u8>,
    /// Raw authenticator data.
    pub authenticator_data: Vec<u8>,
    /// Raw client data JSON.
    pub client_data_json: Vec<u8>,
    /// The signature, in this algorithm's wire encoding.
    pub signature: Vec<u8>,
}

impl SoftAssertion {
    /// Borrow this as the verifier's input type.
    pub fn as_ref(&self) -> AssertionResponse<'_> {
        AssertionResponse {
            credential_id: &self.credential_id,
            authenticator_data: &self.authenticator_data,
            client_data_json: &self.client_data_json,
            signature: &self.signature,
        }
    }
}

enum KeyPair {
    Es256(Box<p256::ecdsa::SigningKey>),
    Ed25519(Box<ed25519_dalek::SigningKey>),
}

/// A stand-in authenticator holding exactly one credential.
pub struct SoftAuthenticator {
    key: KeyPair,
    credential_id: Vec<u8>,
    /// Seed for the PRF. Per-credential, so two authenticators never produce
    /// the same PRF output for the same salt — the property the real
    /// extension has and that vault slot separation relies on.
    prf_seed: [u8; 32],
    sign_count: u32,
    user_verified: bool,
}

impl SoftAuthenticator {
    /// Every algorithm a test should sweep over.
    pub fn algorithms() -> [Algorithm; 2] {
        [Algorithm::Es256, Algorithm::Ed25519]
    }

    /// Mint a fresh credential.
    pub fn new(algorithm: Algorithm) -> Self {
        let mut credential_id = vec![0u8; 32];
        let mut prf_seed = [0u8; 32];
        fill_random(&mut credential_id);
        fill_random(&mut prf_seed);
        let key = match algorithm {
            Algorithm::Es256 => KeyPair::Es256(Box::new(p256::ecdsa::SigningKey::random(
                &mut p256::elliptic_curve::rand_core::OsRng,
            ))),
            Algorithm::Ed25519 => {
                let mut seed = [0u8; 32];
                fill_random(&mut seed);
                KeyPair::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(&seed)))
            }
        };
        SoftAuthenticator {
            key,
            credential_id,
            prf_seed,
            sign_count: 0,
            user_verified: true,
        }
    }

    /// This credential's id.
    pub fn credential_id(&self) -> Vec<u8> {
        self.credential_id.clone()
    }

    /// Whether responses claim the user was verified. Set false to produce the
    /// response a "user present but not authenticated" touch would give.
    pub fn set_user_verified(&mut self, verified: bool) {
        self.user_verified = verified;
    }

    /// The PRF output for `salt` — the key material a real ceremony would
    /// return to the page, and the input a vault slot's key is derived from.
    ///
    /// A hash of the seed and the salt: not the CTAP2 construction, but with
    /// the two properties that matter downstream — a different salt gives an
    /// unrelated output, and no other credential can produce this one.
    pub fn prf_output(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.prf_seed);
        hasher.update((salt.len() as u64).to_be_bytes());
        hasher.update(salt);
        hasher.finalize().into()
    }

    /// Produce a registration response: `(clientDataJSON, attestationObject)`.
    ///
    /// The attestation format is `none`, which is what an authenticator
    /// returns when no attestation was asked for — and what cache-warden asks
    /// for, since it gates registration on local approval instead
    /// (DR-0034 §1c).
    pub fn register(&mut self, rp_id: &str, challenge: &[u8], origin: &str) -> (Vec<u8>, Vec<u8>) {
        let client_data = client_data_json("webauthn.create", challenge, origin);
        let auth_data = self.authenticator_data(rp_id, true);

        let attestation = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&attestation, &mut out).expect("in-memory write");
        (client_data, out)
    }

    /// Produce an assertion response.
    pub fn assert(&mut self, rp_id: &str, challenge: &[u8], origin: &str) -> SoftAssertion {
        let client_data_json = client_data_json("webauthn.get", challenge, origin);
        let authenticator_data = self.authenticator_data(rp_id, false);

        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature = match &self.key {
            KeyPair::Es256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(&signed);
                sig.to_der().as_bytes().to_vec()
            }
            KeyPair::Ed25519(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(&signed).to_bytes().to_vec()
            }
        };

        SoftAssertion {
            credential_id: self.credential_id.clone(),
            authenticator_data,
            client_data_json,
            signature,
        }
    }

    /// Build authenticator data (W3C §6.1), with attested credential data
    /// appended when this is a registration.
    fn authenticator_data(&mut self, rp_id: &str, attested: bool) -> Vec<u8> {
        self.sign_count += 1;
        let mut out = Vec::new();
        out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));

        let mut flags = 0x01u8; // user present
        if self.user_verified {
            flags |= 0x04;
        }
        if attested {
            flags |= 0x40;
        }
        out.push(flags);
        out.extend_from_slice(&self.sign_count.to_be_bytes());

        if attested {
            out.extend_from_slice(&[0u8; 16]); // aaguid: none, for `none` attestation
            out.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.credential_id);
            out.extend_from_slice(&self.cose_public_key());
        }
        out
    }

    /// This credential's public key as a COSE map (RFC 8152).
    fn cose_public_key(&self) -> Vec<u8> {
        let value = match &self.key {
            KeyPair::Es256(k) => {
                let point = p256::ecdsa::VerifyingKey::from(k.as_ref()).to_encoded_point(false);
                Value::Map(vec![
                    (Value::Integer(1.into()), Value::Integer(2.into())), // kty: EC2
                    (Value::Integer(3.into()), Value::Integer((-7).into())), // alg: ES256
                    (Value::Integer((-1).into()), Value::Integer(1.into())), // crv: P-256
                    (
                        Value::Integer((-2).into()),
                        Value::Bytes(point.x().expect("uncompressed point").to_vec()),
                    ),
                    (
                        Value::Integer((-3).into()),
                        Value::Bytes(point.y().expect("uncompressed point").to_vec()),
                    ),
                ])
            }
            KeyPair::Ed25519(k) => Value::Map(vec![
                (Value::Integer(1.into()), Value::Integer(1.into())), // kty: OKP
                (Value::Integer(3.into()), Value::Integer((-8).into())), // alg: EdDSA
                (Value::Integer((-1).into()), Value::Integer(6.into())), // crv: Ed25519
                (
                    Value::Integer((-2).into()),
                    Value::Bytes(k.verifying_key().as_bytes().to_vec()),
                ),
            ]),
        };
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).expect("in-memory write");
        out
    }
}

/// The client data a browser builds for a ceremony (W3C §5.8.1).
fn client_data_json(ceremony: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    let value = serde_json::json!({
        "type": ceremony,
        "challenge": crate::b64(challenge),
        "origin": origin,
        "crossOrigin": false,
    });
    serde_json::to_vec(&value).expect("in-memory write")
}

fn fill_random(buf: &mut [u8]) {
    use rand_core::RngCore as _;
    rand_core::OsRng.fill_bytes(buf);
}
