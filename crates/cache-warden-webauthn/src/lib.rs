//! The relying-party half of a WebAuthn ceremony (DR-0034 §10).
//!
//! # What this is, and what it deliberately is not
//!
//! This verifies two things: that a registration response describes a
//! credential this daemon asked for, and that an assertion response was
//! produced by that credential, for a challenge this daemon issued, on an
//! origin this daemon allows, with the user verified.
//!
//! It is **not** a general WebAuthn library. Three simplifications make it a
//! bounded amount of code rather than an ongoing specification-tracking
//! effort, and each is a decision recorded in DR-0034 rather than a corner cut:
//!
//! - **Attestation is not verified** (DR-0034 §1c). Registration is gated on a
//!   local human approval instead, so there is no question of deciding whether
//!   a remote authenticator model is trustworthy — the person at the machine
//!   already said yes. The attestation object is parsed only for the
//!   credential id and public key inside it.
//! - **One credential per verification.** There is no credential database,
//!   user handle resolution, or discoverable-credential flow; a caller looks a
//!   vault slot up by credential id and passes that slot's key here.
//! - **Two algorithms**, ES256 and Ed25519, which is what platform
//!   authenticators and password managers actually mint.
//!
//! Section references in the comments below are to the W3C Web Authentication
//! Level 3 recommendation, §7.1 (registering) and §7.2 (authenticating),
//! whose numbered verification steps this file follows.
//!
//! # Where the security actually rests
//!
//! For cache-warden's vault this verification is a **gate**, not the
//! confidentiality boundary. The key that opens a vault slot is derived from
//! the authenticator's PRF output, which never travels through an assertion —
//! it is returned to the page by the browser and posted separately. An
//! attacker who defeated every check in this file would still hold no key
//! material. That is not a licence for these checks to be sloppy (they are
//! what stops a local process from driving a ceremony it was never granted),
//! but it is why this file is not the last line of defence.

use base64::Engine as _;
use sha2::{Digest, Sha256};

mod cose;
pub mod testing;

pub use cose::CredentialPublicKey;
pub use testing::{Algorithm, SoftAuthenticator};

/// Base64url without padding — the encoding the WebAuthn JS API uses for every
/// binary field it hands to a page.
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, accepting both padded and unpadded input.
///
/// Both appear in practice: `btoa`-derived helpers pad, the `toBase64` methods
/// do not. Rejecting one of them would be a compatibility bug that looks like
/// a security failure to whoever hits it.
pub fn decode_b64(s: &str) -> Option<Vec<u8>> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine
        .decode(s.trim_end_matches('='))
        .ok()
        .filter(|_| !s.is_empty())
}

/// Who the daemon claims to be, and where its ceremony page is served from.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// The RP id. Appears hashed in every signed authenticator data blob,
    /// which is what stops another site's assertion from being replayed here.
    pub rp_id: String,
    /// Every origin the ceremony page may legitimately be served from.
    ///
    /// Matched **exactly**, never by prefix or suffix. A prefix match would
    /// accept `https://vault.example.com.evil.test`; a suffix match would
    /// accept `https://evil-vault.example.com`. Both are the classic way an
    /// origin check is defeated, so the comparison is string equality against
    /// an explicit list.
    pub allowed_origins: Vec<String>,
}

/// Why a response was refused.
///
/// Each variant names one check. They are distinct so a daemon log can say
/// which one failed — the reply to the browser deliberately does not, since a
/// prober should not learn which of its guesses was closest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `clientDataJSON` was not JSON, or not an object.
    ClientDataUnparseable,
    /// W3C §7.1 step 7 / §7.2 step 11: `type` must be `webauthn.create` for a
    /// registration and `webauthn.get` for an assertion. Without this check a
    /// registration response could be replayed as an assertion.
    WrongCeremonyType,
    /// W3C §7.1 step 8 / §7.2 step 12: the challenge must be the one this
    /// daemon issued. This is the replay check.
    ChallengeMismatch,
    /// W3C §7.1 step 9 / §7.2 step 13: the origin must be one this daemon
    /// allows.
    OriginNotAllowed,
    /// The attestation object was not CBOR, or not shaped like one.
    AttestationUnparseable,
    /// W3C §6.1: authenticator data is at least 37 bytes (32 rp id hash, one
    /// flags byte, four counter bytes). Anything shorter cannot be parsed
    /// without reading past the end.
    AuthenticatorDataTooShort,
    /// W3C §7.1 step 13 / §7.2 step 15: the rp id hash must be SHA-256 of our
    /// RP id. This is what binds an assertion to this relying party.
    RpIdHashMismatch,
    /// W3C §7.1 step 14 / §7.2 step 16: the user-present flag must be set.
    UserNotPresent,
    /// W3C §7.1 step 15 / §7.2 step 17: the user-verified flag must be set.
    ///
    /// Requesting `userVerification: "required"` is not enough on its own —
    /// that request lives in client-side options a hostile page can edit. The
    /// flag checked here is inside the data the authenticator signed
    /// (DR-0034 §10).
    UserNotVerified,
    /// The attested credential data was absent (the AT flag was clear) or
    /// truncated. A registration that carries no credential is not one.
    NoAttestedCredential,
    /// The credential's public key was not a COSE key in an algorithm this
    /// build verifies.
    UnsupportedAlgorithm,
    /// W3C §7.2 step 19: the signature did not verify.
    BadSignature,
    /// The assertion came from a different credential than the one expected.
    WrongCredential,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Refusal::ClientDataUnparseable => "client data was not readable",
            Refusal::WrongCeremonyType => "the response was for a different kind of ceremony",
            Refusal::ChallengeMismatch => "the challenge did not match",
            Refusal::OriginNotAllowed => "the origin is not allowed",
            Refusal::AttestationUnparseable => "the attestation object was not readable",
            Refusal::AuthenticatorDataTooShort => "the authenticator data was truncated",
            Refusal::RpIdHashMismatch => "the response was for a different relying party",
            Refusal::UserNotPresent => "the authenticator reported no user presence",
            Refusal::UserNotVerified => "the authenticator did not verify the user",
            Refusal::NoAttestedCredential => "the response carried no credential",
            Refusal::UnsupportedAlgorithm => "the credential uses an unsupported algorithm",
            Refusal::BadSignature => "the signature did not verify",
            Refusal::WrongCredential => "the response came from a different credential",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Refusal {}

/// A credential this daemon has registered.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisteredCredential {
    /// The credential id, as the authenticator issued it.
    pub id: Vec<u8>,
    /// Its public key, for verifying later assertions.
    pub key: CredentialPublicKey,
}

/// What an accepted assertion establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assertion {
    /// The authenticator's signature counter, for a caller that tracks clones.
    /// Not enforced here: passkeys synced across devices legitimately report
    /// zero or non-monotonic counters, so refusing on it would break the
    /// common case to catch a case this design does not defend against.
    pub sign_count: u32,
}

/// Parsed authenticator data (W3C §6.1).
struct AuthenticatorData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    /// Everything after the fixed header — attested credential data and
    /// extensions, when the flags say they are there.
    rest: &'a [u8],
}

impl<'a> AuthenticatorData<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, Refusal> {
        if bytes.len() < 37 {
            return Err(Refusal::AuthenticatorDataTooShort);
        }
        Ok(AuthenticatorData {
            rp_id_hash: &bytes[..32],
            flags: bytes[32],
            sign_count: u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]),
            rest: &bytes[37..],
        })
    }

    fn user_present(&self) -> bool {
        self.flags & 0x01 != 0
    }

    fn user_verified(&self) -> bool {
        self.flags & 0x04 != 0
    }

    /// Whether attested credential data follows the header (the AT flag).
    fn has_attested_credential(&self) -> bool {
        self.flags & 0x40 != 0
    }
}

/// Check the parts of the client data that both ceremonies share
/// (W3C §7.1 steps 7-9, §7.2 steps 11-13).
fn check_client_data(
    rp: &RelyingParty,
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
) -> Result<(), Refusal> {
    let client: serde_json::Value =
        serde_json::from_slice(client_data_json).map_err(|_| Refusal::ClientDataUnparseable)?;

    if client["type"].as_str() != Some(expected_type) {
        return Err(Refusal::WrongCeremonyType);
    }
    // Compared as the encoded string rather than by decoding the response's
    // challenge: two encodings of the same bytes should not both pass, and
    // there is no reason to accept an encoding the browser would not have
    // produced.
    if client["challenge"].as_str() != Some(b64(expected_challenge).as_str()) {
        return Err(Refusal::ChallengeMismatch);
    }
    let origin = client["origin"].as_str().unwrap_or_default();
    if !rp.allowed_origins.iter().any(|o| o == origin) {
        return Err(Refusal::OriginNotAllowed);
    }
    Ok(())
}

/// Check the parts of the authenticator data that both ceremonies share
/// (W3C §7.1 steps 13-15, §7.2 steps 15-17).
fn check_authenticator_data(
    rp: &RelyingParty,
    auth_data: &AuthenticatorData<'_>,
) -> Result<(), Refusal> {
    if auth_data.rp_id_hash != Sha256::digest(rp.rp_id.as_bytes()).as_slice() {
        return Err(Refusal::RpIdHashMismatch);
    }
    if !auth_data.user_present() {
        return Err(Refusal::UserNotPresent);
    }
    if !auth_data.user_verified() {
        return Err(Refusal::UserNotVerified);
    }
    Ok(())
}

/// Verify a registration response and extract the credential it describes
/// (W3C §7.1).
///
/// Attestation is intentionally not examined beyond reading the credential out
/// of it: see the module documentation, and DR-0034 §1c for why the local
/// approval gate stands in its place.
pub fn verify_registration(
    rp: &RelyingParty,
    expected_challenge: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<RegisteredCredential, Refusal> {
    check_client_data(rp, client_data_json, "webauthn.create", expected_challenge)?;

    // W3C §7.1 step 12: the attestation object is CBOR carrying `authData`.
    let value: ciborium::value::Value =
        ciborium::from_reader(attestation_object).map_err(|_| Refusal::AttestationUnparseable)?;
    let auth_data_bytes = cose::map_get_bytes(&value, "authData")
        .ok_or(Refusal::AttestationUnparseable)?
        .to_vec();

    let auth_data = AuthenticatorData::parse(&auth_data_bytes)?;
    check_authenticator_data(rp, &auth_data)?;

    if !auth_data.has_attested_credential() {
        return Err(Refusal::NoAttestedCredential);
    }
    // W3C §6.5.1 attested credential data: aaguid(16) ‖ credential id
    // length(2) ‖ credential id ‖ COSE public key.
    let rest = auth_data.rest;
    if rest.len() < 18 {
        return Err(Refusal::NoAttestedCredential);
    }
    let id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
    let id_end = 18usize
        .checked_add(id_len)
        .ok_or(Refusal::NoAttestedCredential)?;
    if rest.len() < id_end {
        return Err(Refusal::NoAttestedCredential);
    }
    let id = rest[18..id_end].to_vec();
    let key = CredentialPublicKey::from_cose(&rest[id_end..])?;

    Ok(RegisteredCredential { id, key })
}

/// What the browser returned from `navigator.credentials.get()`.
pub struct AssertionResponse<'a> {
    /// The credential id that produced it.
    pub credential_id: &'a [u8],
    /// Raw authenticator data.
    pub authenticator_data: &'a [u8],
    /// Raw client data JSON.
    pub client_data_json: &'a [u8],
    /// The signature: DER for ES256, 64 raw bytes for Ed25519.
    pub signature: &'a [u8],
}

/// Verify an assertion against a credential registered earlier (W3C §7.2).
pub fn verify_assertion(
    rp: &RelyingParty,
    expected_challenge: &[u8],
    credential: &RegisteredCredential,
    response: &AssertionResponse<'_>,
) -> Result<Assertion, Refusal> {
    // W3C §7.2 step 6: the assertion must come from the credential whose key
    // we are about to verify with. Comparing here rather than trusting the
    // lookup means a mismatch is a refusal, not a signature failure that
    // looks like tampering.
    if response.credential_id != credential.id {
        return Err(Refusal::WrongCredential);
    }
    check_client_data(
        rp,
        response.client_data_json,
        "webauthn.get",
        expected_challenge,
    )?;

    let auth_data = AuthenticatorData::parse(response.authenticator_data)?;
    check_authenticator_data(rp, &auth_data)?;

    // W3C §7.2 step 19: the signature is over the authenticator data
    // concatenated with the hash of the client data — which is what binds the
    // two halves together. Verifying either one alone would leave the other
    // free to be swapped.
    let mut signed = Vec::with_capacity(response.authenticator_data.len() + 32);
    signed.extend_from_slice(response.authenticator_data);
    signed.extend_from_slice(&Sha256::digest(response.client_data_json));
    credential.key.verify(&signed, response.signature)?;

    Ok(Assertion {
        sign_count: auth_data.sign_count,
    })
}

#[cfg(test)]
mod tests;
