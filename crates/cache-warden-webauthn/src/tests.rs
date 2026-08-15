//! Verification tests, driven by a software authenticator.
//!
//! The authenticator below constructs its responses the same way a real one
//! does — the same byte layouts, the same signature input — which is what
//! makes it usable for the whole ceremony without a browser or a fingerprint
//! (DR-0034 Open Q5's software-authenticator test path). Its being a stand-in
//! is also the point of the refusal tests: every check below is one that, if
//! skipped, would let this fake stand in for a real credential somewhere it
//! should not.

use super::*;
use crate::testing::SoftAuthenticator;

fn rp() -> RelyingParty {
    RelyingParty {
        rp_id: "vault.example.test".to_string(),
        allowed_origins: vec!["https://vault.example.test".to_string()],
    }
}

#[test]
fn a_registration_yields_a_credential_that_its_own_assertions_verify_against() {
    for algorithm in SoftAuthenticator::algorithms() {
        let mut auth = SoftAuthenticator::new(algorithm);
        let challenge = b"registration-challenge";
        let (client_data, attestation) =
            auth.register(&rp().rp_id, challenge, "https://vault.example.test");

        let credential = verify_registration(&rp(), challenge, &client_data, &attestation)
            .unwrap_or_else(|e| panic!("{algorithm:?} registration: {e}"));
        assert_eq!(credential.id, auth.credential_id());

        let challenge = b"assertion-challenge";
        let response = auth.assert(&rp().rp_id, challenge, "https://vault.example.test");
        verify_assertion(&rp(), challenge, &credential, &response.as_ref())
            .unwrap_or_else(|e| panic!("{algorithm:?} assertion: {e}"));
    }
}

/// The five checks whose absence would each let someone else's ceremony, or no
/// ceremony at all, stand in for this one.
#[test]
fn each_assertion_check_refuses_what_it_exists_for() {
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    let challenge = b"the-challenge-we-issued";
    let (client_data, attestation) =
        auth.register(&rp().rp_id, b"reg", "https://vault.example.test");
    let credential = verify_registration(&rp(), b"reg", &client_data, &attestation).unwrap();

    // A replayed assertion: right credential, wrong (old) challenge.
    let response = auth.assert(
        &rp().rp_id,
        b"a-different-challenge",
        "https://vault.example.test",
    );
    assert_eq!(
        verify_assertion(&rp(), challenge, &credential, &response.as_ref()),
        Err(Refusal::ChallengeMismatch)
    );

    // A lookalike origin — what a prefix match would have let through.
    let response = auth.assert(
        &rp().rp_id,
        challenge,
        "https://vault.example.test.evil.test",
    );
    assert_eq!(
        verify_assertion(&rp(), challenge, &credential, &response.as_ref()),
        Err(Refusal::OriginNotAllowed)
    );

    // Another relying party's assertion, forwarded here.
    let response = auth.assert("evil.test", challenge, "https://vault.example.test");
    assert_eq!(
        verify_assertion(&rp(), challenge, &credential, &response.as_ref()),
        Err(Refusal::RpIdHashMismatch)
    );

    // Touched but not authenticated: user present, user not verified.
    auth.set_user_verified(false);
    let response = auth.assert(&rp().rp_id, challenge, "https://vault.example.test");
    assert_eq!(
        verify_assertion(&rp(), challenge, &credential, &response.as_ref()),
        Err(Refusal::UserNotVerified)
    );
    auth.set_user_verified(true);

    // A different credential's signature, presented under the right id.
    let mut other = SoftAuthenticator::new(Algorithm::Es256);
    other.register(&rp().rp_id, b"reg", "https://vault.example.test");
    let forged = other.assert(&rp().rp_id, challenge, "https://vault.example.test");
    let response = AssertionResponse {
        credential_id: &credential.id,
        authenticator_data: &forged.authenticator_data,
        client_data_json: &forged.client_data_json,
        signature: &forged.signature,
    };
    assert_eq!(
        verify_assertion(&rp(), challenge, &credential, &response),
        Err(Refusal::BadSignature)
    );
}

/// A credential id the caller did not look up must be refused before any
/// cryptography runs, so a mismatch reads as a mismatch rather than as a
/// signature failure.
#[test]
fn an_assertion_from_another_credential_id_is_refused_as_such() {
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    let (client_data, attestation) =
        auth.register(&rp().rp_id, b"reg", "https://vault.example.test");
    let mut credential = verify_registration(&rp(), b"reg", &client_data, &attestation).unwrap();
    let response = auth.assert(&rp().rp_id, b"c", "https://vault.example.test");
    credential.id = b"some-other-credential".to_vec();
    assert_eq!(
        verify_assertion(&rp(), b"c", &credential, &response.as_ref()),
        Err(Refusal::WrongCredential)
    );
}

/// A registration response replayed as an assertion, and the reverse. Without
/// the `type` check both would reach the signature verification, where one of
/// them would pass.
#[test]
fn a_response_for_one_ceremony_is_refused_by_the_other() {
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    let (reg_client_data, attestation) =
        auth.register(&rp().rp_id, b"c", "https://vault.example.test");
    let credential = verify_registration(&rp(), b"c", &reg_client_data, &attestation).unwrap();

    let assertion = auth.assert(&rp().rp_id, b"c", "https://vault.example.test");
    // The assertion's client data, offered to the registration verifier.
    assert_eq!(
        verify_registration(&rp(), b"c", &assertion.client_data_json, &attestation),
        Err(Refusal::WrongCeremonyType)
    );
    // And the registration's client data, offered to the assertion verifier.
    let crossed = AssertionResponse {
        credential_id: &credential.id,
        authenticator_data: &assertion.authenticator_data,
        client_data_json: &reg_client_data,
        signature: &assertion.signature,
    };
    assert_eq!(
        verify_assertion(&rp(), b"c", &credential, &crossed),
        Err(Refusal::WrongCeremonyType)
    );
}

/// Registration has the same user-verification requirement as assertion: a
/// credential registered without it would be one the user never authenticated
/// to create.
#[test]
fn a_registration_without_user_verification_is_refused() {
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    auth.set_user_verified(false);
    let (client_data, attestation) = auth.register(&rp().rp_id, b"c", "https://vault.example.test");
    assert_eq!(
        verify_registration(&rp(), b"c", &client_data, &attestation),
        Err(Refusal::UserNotVerified)
    );
}

#[test]
fn malformed_input_is_refused_rather_than_panicking() {
    assert_eq!(
        verify_registration(&rp(), b"c", b"not json", b""),
        Err(Refusal::ClientDataUnparseable)
    );
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    let (client_data, _) = auth.register(&rp().rp_id, b"c", "https://vault.example.test");
    assert_eq!(
        verify_registration(&rp(), b"c", &client_data, b"\xff\xff not cbor"),
        Err(Refusal::AttestationUnparseable)
    );
    // Truncated authenticator data, at every length shorter than the header.
    for len in 0..37 {
        let mut cbor = Vec::new();
        ciborium::into_writer(
            &ciborium::value::Value::Map(vec![(
                ciborium::value::Value::Text("authData".into()),
                ciborium::value::Value::Bytes(vec![0u8; len]),
            )]),
            &mut cbor,
        )
        .unwrap();
        assert_eq!(
            verify_registration(&rp(), b"c", &client_data, &cbor),
            Err(Refusal::AuthenticatorDataTooShort),
            "authenticator data of {len} bytes must be refused, not read past"
        );
    }
}

/// Both encodings of the same challenge appear in the wild depending on which
/// JS helper produced them; neither is a security difference.
#[test]
fn base64url_decoding_accepts_padded_and_unpadded() {
    assert_eq!(decode_b64("YWJj").as_deref(), Some(b"abc".as_slice()));
    assert_eq!(decode_b64("YWJj=").as_deref(), Some(b"abc".as_slice()));
    assert_eq!(decode_b64(""), None);
    assert_eq!(decode_b64("!!!not base64!!!"), None);
}

/// A stored key must come back as the same key, or every slot registered by a
/// previous process becomes unusable.
#[test]
fn a_stored_public_key_round_trips() {
    for algorithm in SoftAuthenticator::algorithms() {
        let mut auth = SoftAuthenticator::new(algorithm);
        let (client_data, attestation) =
            auth.register(&rp().rp_id, b"c", "https://vault.example.test");
        let credential = verify_registration(&rp(), b"c", &client_data, &attestation).unwrap();

        let stored = credential.key.to_stored_bytes();
        let back = CredentialPublicKey::from_stored_bytes(&stored).expect("round trips");

        let challenge = b"round-trip";
        let response = auth.assert(&rp().rp_id, challenge, "https://vault.example.test");
        let restored = RegisteredCredential {
            id: credential.id.clone(),
            key: back,
        };
        verify_assertion(&rp(), challenge, &restored, &response.as_ref())
            .expect("the restored key verifies the same assertions");
    }
}
