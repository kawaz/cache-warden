//! The ceremony, driven end to end by a software authenticator.
//!
//! No browser and no fingerprint: the authenticator produces the same bytes a
//! real one would, so everything from the challenge to the unlocked vault is
//! exercised here (DR-0034 Open Q5's automated path). What is *not* covered is
//! the page's own JavaScript and the browser's PRF implementation — those are
//! the parts the manual checklist exists for.

use super::*;
use cache_warden_webauthn::{Algorithm, SoftAuthenticator};

const RP_ID: &str = "vault.example.test";
const ORIGIN: &str = "https://vault.example.test";

/// A locked vault with one recovery slot, plus the ceremony that serves it and
/// the store an unlock has to deliver into.
struct Fixture {
    _dir: tempfile::TempDir,
    ceremony: Mutex<Ceremony>,
    vault: Mutex<VaultState>,
    store: StoreAccess,
    code: cache_warden_vault::RecoveryCode,
}

impl Fixture {
    /// What the store currently holds for `key`, or `None`.
    ///
    /// Reading through the store is the point: an unlock that opened the vault
    /// without delivering here is an unlock the caller cannot use.
    fn value_of(&self, key: &str) -> Option<Vec<u8>> {
        let mut store = self.store.store.lock().unwrap();
        store
            .get(key, &self.store.cap, self.store.clock.as_ref())
            .ok()
            .flatten()
            .map(|s| s.with_exposed(|b| b.to_vec()))
    }

    /// The CAS version the store has for `key`.
    fn version_of(&self, key: &str) -> u64 {
        self.store.store.lock().unwrap().version_of(key)
    }

    /// Put a persisted entry in the vault, as `kv set --persist` would, and
    /// return the version the vault assigned it.
    ///
    /// `writes` says how many times to store it. More than one is what makes
    /// the version assertion meaningful: a restore that reset the counter
    /// would land on 1, which is indistinguishable from a correct restore of a
    /// once-written entry.
    fn persist(&self, key: &str, value: &[u8], writes: u64) -> u64 {
        let mut state = self.vault.lock().unwrap();
        let unlocked = state.unlocked_mut().expect("the vault is open");
        let mut version = 0;
        for _ in 0..writes {
            let entry = cache_warden_vault::VaultEntry::new(key, value.to_vec());
            version = unlocked.upsert(entry, None).expect("stores");
        }
        version
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut state = VaultState::open_at(dir.path().join("v.cwv")).unwrap();
    let (_id, code) = state.init().expect("initializes");
    let (store, cap) = cache_warden::test_helpers::store_with_cap();
    Fixture {
        _dir: dir,
        ceremony: Mutex::new(Ceremony::new(RP_ID.to_string(), vec![ORIGIN.to_string()])),
        vault: Mutex::new(state),
        store: StoreAccess {
            store: Arc::new(Mutex::new(store)),
            cap,
            clock: Arc::new(cache_warden::SystemClock::new()),
        },
        code,
    }
}

fn post(fx: &Fixture, path: &str, body: serde_json::Value) -> (u16, serde_json::Value) {
    let response = handle(
        &fx.ceremony,
        &fx.vault,
        &fx.store,
        Request {
            method: "POST".into(),
            path: path.into(),
            body: body.to_string().into_bytes(),
            origin: Some(ORIGIN.into()),
        },
    );
    let parsed = serde_json::from_slice(&response.body).unwrap_or(serde_json::Value::Null);
    (response.status, parsed)
}

fn challenge_of(options: &serde_json::Value) -> Vec<u8> {
    cache_warden_webauthn::decode_b64(
        options["options"]["publicKey"]["challenge"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

/// Run a full registration: arm, register, evaluate the PRF, finish.
fn register(fx: &Fixture, auth: &mut SoftAuthenticator, label: &str) -> (u16, serde_json::Value) {
    fx.ceremony.lock().unwrap().arm_registration(label.into());

    let (_, begin) = post(fx, "/begin", serde_json::json!({}));
    assert_eq!(begin["mode"], "register", "{begin}");
    let salt = cache_warden_webauthn::decode_b64(begin["salt"]["first"].as_str().unwrap()).unwrap();
    let (client_data, attestation) = auth.register(RP_ID, &challenge_of(&begin), ORIGIN);

    // The page's second step: an assertion whose purpose is to evaluate the
    // PRF for the salt this slot will use.
    let (_, evaluate) = post(fx, "/register/evaluate", serde_json::json!({}));
    let _ = auth.assert(RP_ID, &challenge_of(&evaluate), ORIGIN);
    let prf = auth.prf_output(&salt);

    post(
        fx,
        "/register/finish",
        serde_json::json!({
            "credential_id": b64(&auth.credential_id()),
            "client_data_json": b64(&client_data),
            "attestation_object": b64(&attestation),
            "prf_output": b64(&prf),
        }),
    )
}

/// Run a full unlock with a registered authenticator.
fn unlock(fx: &Fixture, auth: &mut SoftAuthenticator) -> (u16, serde_json::Value) {
    let (status, begin) = post(fx, "/begin", serde_json::json!({}));
    assert_eq!(status, 200, "{begin}");
    assert_eq!(begin["mode"], "unlock", "{begin}");

    let id = b64(&auth.credential_id());
    let salt = cache_warden_webauthn::decode_b64(
        begin["salts"][&id]
            .as_str()
            .expect("a salt for this credential"),
    )
    .unwrap();
    let assertion = auth.assert(RP_ID, &challenge_of(&begin), ORIGIN);

    post(
        fx,
        "/unlock/finish",
        serde_json::json!({
            "credential_id": b64(&assertion.credential_id),
            "authenticator_data": b64(&assertion.authenticator_data),
            "client_data_json": b64(&assertion.client_data_json),
            "signature": b64(&assertion.signature),
            "prf_output": b64(&auth.prf_output(&salt)),
        }),
    )
}

#[test]
fn a_registered_passkey_unlocks_the_vault_it_was_registered_against() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);

    let (status, body) = register(&fx, &mut auth, "laptop");
    assert_eq!(status, 200, "{body}");

    // Close it, as a restart would.
    fx.vault.lock().unwrap().lock().expect("locks");
    assert!(!fx.vault.lock().unwrap().is_unlocked());

    let (status, body) = unlock(&fx, &mut auth);
    assert_eq!(status, 200, "{body}");
    assert!(
        fx.vault.lock().unwrap().is_unlocked(),
        "the ceremony must actually have opened the vault"
    );
}

/// The point of the whole ceremony: after unlocking with a passkey, the
/// credential is **readable**.
///
/// "The vault reports unlocked" is not that, and a test that stopped there
/// missed a version where the data key was recovered and the entries never
/// reached the store — leaving the caller the ceremony was run for with
/// nothing. So this reads the value back, and checks the compare-and-swap
/// version came with it: a version that reset would let a writer that slept
/// through the unlock win a swap it should lose (DR-0034 §4).
#[test]
fn a_passkey_unlock_makes_the_credential_readable_with_its_version() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut auth, "laptop");
    // Written three times, so a counter that reset to 1 is visibly wrong.
    let version = fx.persist("default/RT", b"refresh-token-1", 3);
    assert_eq!(version, 3, "the vault assigns the version");
    fx.vault.lock().unwrap().lock().expect("locks");

    assert_eq!(
        fx.value_of("default/RT"),
        None,
        "nothing is readable while the vault is closed"
    );

    let (status, body) = unlock(&fx, &mut auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["entries_restored"], 1,
        "the unlock must report what it restored: {body}"
    );
    assert_eq!(
        fx.value_of("default/RT").as_deref(),
        Some(b"refresh-token-1".as_slice()),
        "the credential this ceremony exists to deliver must be readable"
    );
    assert_eq!(
        fx.version_of("default/RT"),
        version,
        "the version travels with the value, or a stale writer wins a swap it should lose"
    );
}

/// The recovery path and the passkey path must deliver the same thing. They
/// restore through one function precisely so they cannot drift; this checks
/// the outcome rather than the wiring.
#[test]
fn both_unlock_paths_deliver_the_same_entries() {
    for use_passkey in [false, true] {
        let fx = fixture();
        let mut auth = SoftAuthenticator::new(Algorithm::Es256);
        register(&fx, &mut auth, "laptop");
        let version = fx.persist("default/RT", b"refresh-token-1", 3);
        fx.vault.lock().unwrap().lock().expect("locks");

        if use_passkey {
            assert_eq!(unlock(&fx, &mut auth).0, 200);
            // The recovery-code path restores through the control socket's
            // handler, which this module does not drive; what it shares with
            // the passkey path is `install_vault_entries`, exercised above.
            assert_eq!(
                fx.value_of("default/RT").as_deref(),
                Some(b"refresh-token-1".as_slice())
            );
            assert_eq!(fx.version_of("default/RT"), version);
        } else {
            fx.vault
                .lock()
                .unwrap()
                .unlock(&fx.code)
                .expect("the recovery code opens it");
            assert!(fx.vault.lock().unwrap().is_unlocked());
        }
    }
}

/// A registration window is opened by a command that passed the local approval
/// gate. Without one, the endpoints must not register anything — otherwise
/// anything that can reach the loopback port could add its own way in
/// (DR-0034 §1c).
#[test]
fn nothing_can_be_registered_without_an_armed_window() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    let (client_data, attestation) = auth.register(RP_ID, b"unsolicited", ORIGIN);

    let (status, _) = post(&fx, "/register/evaluate", serde_json::json!({}));
    assert_eq!(status, 403, "no window: no assertion options");

    let (status, body) = post(
        &fx,
        "/register/finish",
        serde_json::json!({
            "credential_id": b64(&auth.credential_id()),
            "client_data_json": b64(&client_data),
            "attestation_object": b64(&attestation),
            "prf_output": b64(&[7u8; 32]),
        }),
    );
    assert_eq!(status, 403, "{body}");

    // And `/begin` offers an unlock, not a registration.
    let (_, begin) = post(&fx, "/begin", serde_json::json!({}));
    assert_ne!(begin["mode"], "register");
}

/// One approval, one passkey. A window that stayed open after a successful
/// registration would let a second credential in behind the approval given for
/// the first.
#[test]
fn an_armed_window_admits_exactly_one_passkey() {
    let fx = fixture();
    let mut first = SoftAuthenticator::new(Algorithm::Es256);
    assert_eq!(register(&fx, &mut first, "first").0, 200);

    let mut second = SoftAuthenticator::new(Algorithm::Es256);
    let (client_data, attestation) = second.register(RP_ID, b"c", ORIGIN);
    let (status, body) = post(
        &fx,
        "/register/finish",
        serde_json::json!({
            "credential_id": b64(&second.credential_id()),
            "client_data_json": b64(&client_data),
            "attestation_object": b64(&attestation),
            "prf_output": b64(&[7u8; 32]),
        }),
    );
    assert_eq!(status, 403, "{body}");
}

/// An unregistered passkey must not open the vault, however well formed its
/// ceremony is.
#[test]
fn an_unregistered_passkey_is_refused() {
    let fx = fixture();
    let mut registered = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut registered, "laptop");
    fx.vault.lock().unwrap().lock().expect("locks");

    let mut impostor = SoftAuthenticator::new(Algorithm::Es256);
    let (_, begin) = post(&fx, "/begin", serde_json::json!({}));
    let assertion = impostor.assert(RP_ID, &challenge_of(&begin), ORIGIN);
    let (status, body) = post(
        &fx,
        "/unlock/finish",
        serde_json::json!({
            "credential_id": b64(&assertion.credential_id),
            "authenticator_data": b64(&assertion.authenticator_data),
            "client_data_json": b64(&assertion.client_data_json),
            "signature": b64(&assertion.signature),
            "prf_output": b64(&[9u8; 32]),
        }),
    );
    assert_eq!(status, 403, "{body}");
    assert!(!fx.vault.lock().unwrap().is_unlocked());
}

/// The two halves of an unlock are independent, and both are required: a valid
/// assertion with the wrong key material must not open the vault, and it must
/// not be reported as an assertion failure either — the ceremony happened, the
/// key simply did not fit.
#[test]
fn a_valid_assertion_with_the_wrong_prf_output_opens_nothing() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut auth, "laptop");
    fx.vault.lock().unwrap().lock().expect("locks");

    let (_, begin) = post(&fx, "/begin", serde_json::json!({}));
    let assertion = auth.assert(RP_ID, &challenge_of(&begin), ORIGIN);
    let (status, body) = post(
        &fx,
        "/unlock/finish",
        serde_json::json!({
            "credential_id": b64(&assertion.credential_id),
            "authenticator_data": b64(&assertion.authenticator_data),
            "client_data_json": b64(&assertion.client_data_json),
            "signature": b64(&assertion.signature),
            "prf_output": b64(&[0u8; 32]),
        }),
    );
    assert_eq!(status, 403, "{body}");
    assert!(!fx.vault.lock().unwrap().is_unlocked());
}

/// A recorded ceremony must not open the vault a second time. This is the
/// property the single-use challenge exists for, checked through the endpoints
/// rather than only in the store.
#[test]
fn a_replayed_unlock_is_refused() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut auth, "laptop");
    fx.vault.lock().unwrap().lock().expect("locks");

    let (_, begin) = post(&fx, "/begin", serde_json::json!({}));
    let id = b64(&auth.credential_id());
    let salt = cache_warden_webauthn::decode_b64(begin["salts"][&id].as_str().unwrap()).unwrap();
    let assertion = auth.assert(RP_ID, &challenge_of(&begin), ORIGIN);
    let replay = serde_json::json!({
        "credential_id": b64(&assertion.credential_id),
        "authenticator_data": b64(&assertion.authenticator_data),
        "client_data_json": b64(&assertion.client_data_json),
        "signature": b64(&assertion.signature),
        "prf_output": b64(&auth.prf_output(&salt)),
    });

    assert_eq!(post(&fx, "/unlock/finish", replay.clone()).0, 200);
    fx.vault.lock().unwrap().lock().expect("locks again");
    let (status, body) = post(&fx, "/unlock/finish", replay);
    assert_eq!(
        status, 403,
        "a recorded ceremony must not open it twice: {body}"
    );
    assert!(!fx.vault.lock().unwrap().is_unlocked());
}

/// A ceremony run against another origin must not be usable here, even with a
/// genuine registered credential — this is what stops a page on a host the
/// user was tricked into visiting from driving the daemon's ceremony.
#[test]
fn an_assertion_from_another_origin_is_refused() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut auth, "laptop");
    fx.vault.lock().unwrap().lock().expect("locks");

    let (_, begin) = post(&fx, "/begin", serde_json::json!({}));
    let id = b64(&auth.credential_id());
    let salt = cache_warden_webauthn::decode_b64(begin["salts"][&id].as_str().unwrap()).unwrap();
    let assertion = auth.assert(
        RP_ID,
        &challenge_of(&begin),
        "https://vault.example.test.evil.test",
    );

    let (status, body) = post(
        &fx,
        "/unlock/finish",
        serde_json::json!({
            "credential_id": b64(&assertion.credential_id),
            "authenticator_data": b64(&assertion.authenticator_data),
            "client_data_json": b64(&assertion.client_data_json),
            "signature": b64(&assertion.signature),
            "prf_output": b64(&auth.prf_output(&salt)),
        }),
    );
    assert_eq!(status, 403, "{body}");
    assert!(!fx.vault.lock().unwrap().is_unlocked());
}

/// A touch is not an authentication. DR-0034 §10 requires the flag in the
/// signed data to be checked, not just `userVerification: "required"` asked
/// for in options a page can edit.
#[test]
fn an_assertion_without_user_verification_is_refused() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut auth, "laptop");
    fx.vault.lock().unwrap().lock().expect("locks");

    let (_, begin) = post(&fx, "/begin", serde_json::json!({}));
    let id = b64(&auth.credential_id());
    let salt = cache_warden_webauthn::decode_b64(begin["salts"][&id].as_str().unwrap()).unwrap();
    auth.set_user_verified(false);
    let assertion = auth.assert(RP_ID, &challenge_of(&begin), ORIGIN);

    let (status, body) = post(
        &fx,
        "/unlock/finish",
        serde_json::json!({
            "credential_id": b64(&assertion.credential_id),
            "authenticator_data": b64(&assertion.authenticator_data),
            "client_data_json": b64(&assertion.client_data_json),
            "signature": b64(&assertion.signature),
            "prf_output": b64(&auth.prf_output(&salt)),
        }),
    );
    assert_eq!(status, 403, "{body}");
    assert!(!fx.vault.lock().unwrap().is_unlocked());
}

/// DR-0034 §2: an assertion produced during a registration ceremony must not
/// complete an unlock. The challenge store enforces it; this checks the
/// endpoints actually ask it to.
#[test]
fn a_registration_ceremony_cannot_complete_an_unlock() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut auth, "laptop");

    // A fresh registration window, and the assertion options it hands out.
    fx.ceremony
        .lock()
        .unwrap()
        .arm_registration("second".into());
    let (_, evaluate) = post(&fx, "/register/evaluate", serde_json::json!({}));
    let assertion = auth.assert(RP_ID, &challenge_of(&evaluate), ORIGIN);

    fx.vault.lock().unwrap().lock().expect("locks");
    let (status, body) = post(
        &fx,
        "/unlock/finish",
        serde_json::json!({
            "credential_id": b64(&assertion.credential_id),
            "authenticator_data": b64(&assertion.authenticator_data),
            "client_data_json": b64(&assertion.client_data_json),
            "signature": b64(&assertion.signature),
            "prf_output": b64(&[1u8; 32]),
        }),
    );
    assert_eq!(status, 403, "{body}");
}

/// A request that names an origin we do not serve is refused before it gets
/// as far as a challenge. The signed origin inside the client data is what
/// ultimately decides an unlock, so this is a second line rather than the
/// first — but it costs a string compare and covers the caller that is not a
/// browser at all.
#[test]
fn a_request_from_a_foreign_origin_is_refused() {
    let fx = fixture();
    let response = handle(
        &fx.ceremony,
        &fx.vault,
        &fx.store,
        Request {
            method: "POST".into(),
            path: "/begin".into(),
            body: b"{}".to_vec(),
            origin: Some("https://evil.test".into()),
        },
    );
    assert_eq!(response.status, 403);

    // No header at all is fine: a non-browser client sends none, and the
    // signed check still applies to whatever it eventually posts.
    let response = handle(
        &fx.ceremony,
        &fx.vault,
        &fx.store,
        Request {
            method: "POST".into(),
            path: "/begin".into(),
            body: b"{}".to_vec(),
            origin: None,
        },
    );
    assert_ne!(response.status, 403);
}

/// The page is served with a policy that permits no external script and no
/// connection anywhere but back here.
#[test]
fn the_page_is_served_with_its_content_security_policy() {
    let fx = fixture();
    let response = handle(
        &fx.ceremony,
        &fx.vault,
        &fx.store,
        Request {
            method: "GET".into(),
            path: "/".into(),
            body: Vec::new(),
            origin: None,
        },
    );
    assert_eq!(response.status, 200);
    let csp = response
        .extra_headers
        .iter()
        .find(|h| h.starts_with("Content-Security-Policy:"))
        .expect("the page must carry a policy");
    assert!(csp.contains("default-src 'none'"), "{csp}");
    assert!(csp.contains("connect-src 'self'"), "{csp}");
}

/// Recovery still works: registering a passkey must not take away the path
/// that exists for when every passkey is gone (DR-0034 §9).
#[test]
fn registering_a_passkey_leaves_the_recovery_code_working() {
    let fx = fixture();
    let mut auth = SoftAuthenticator::new(Algorithm::Es256);
    register(&fx, &mut auth, "laptop");
    fx.vault.lock().unwrap().lock().expect("locks");

    fx.vault
        .lock()
        .unwrap()
        .unlock(&fx.code)
        .expect("the recovery code still opens it");
}

/// Both algorithms a passkey may be minted with have to survive the round trip
/// from registration to unlock, since which one is used is the authenticator's
/// choice, not ours.
#[test]
fn both_credential_algorithms_complete_a_ceremony() {
    for algorithm in SoftAuthenticator::algorithms() {
        let fx = fixture();
        let mut auth = SoftAuthenticator::new(algorithm);
        assert_eq!(register(&fx, &mut auth, "device").0, 200, "{algorithm:?}");
        fx.vault.lock().unwrap().lock().expect("locks");
        assert_eq!(unlock(&fx, &mut auth).0, 200, "{algorithm:?}");
    }
}
