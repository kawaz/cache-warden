//! The passkey ceremony the vault is unlocked and registered through
//! (DR-0034 §2 / §10).
//!
//! # The shape of a ceremony
//!
//! A browser is the only place a WebAuthn PRF can be evaluated, so the daemon
//! serves a page on loopback and the user opens it. The page asks what it is
//! for, runs the ceremony the answer describes, and posts back what the
//! authenticator produced. TLS, if the page is reached from anywhere but this
//! machine, is terminated in front of the daemon (DR-0032).
//!
//! # Two things travel back, and only one of them is verified
//!
//! An assertion is verified: challenge, origin, relying party, user
//! verification, signature (see `cache_warden_webauthn`). The **PRF output is
//! not** — it cannot be, since the daemon has no way to compute what the
//! authenticator should have produced. It does not need to be: a wrong PRF
//! output derives a wrong key, and a wrong key does not open the slot. The
//! assertion is what establishes that a ceremony happened *now*, with the user
//! verified; the PRF output is what carries the key.
//!
//! That division is why an unlock requires both. Without the assertion, a
//! replayed PRF output would open the vault with no user present. Without the
//! PRF output, a verified assertion would prove a ceremony and open nothing.

pub mod challenge;
pub mod http;
pub mod page;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use cache_warden::{Capability, Store, SystemClock};
use cache_warden_vault::{SlotKind, UnlockedVault};
use cache_warden_webauthn::{AssertionResponse, CredentialPublicKey, RelyingParty};
use zeroize::Zeroizing;

use crate::daemon::vault_state::VaultState;
use challenge::{ChallengeStore, Purpose};
use http::{Request, Response};

/// How long an armed registration stays open.
///
/// Armed by `vault add-passkey` once a local approval has been given
/// (DR-0034 §1c); if the user never gets to the browser, it closes on its own
/// rather than leaving the daemon willing to accept a new way in.
pub const REGISTRATION_WINDOW: Duration = Duration::from_secs(300);

/// A registration that has been approved locally and is waiting for a browser.
struct ArmedRegistration {
    /// The salt this slot's key will be derived from — generated when the
    /// registration was armed, because the ceremony has to evaluate it.
    salt: [u8; 32],
    /// What to label the slot.
    label: String,
    expires_at: Instant,
}

/// What finishing an unlock needs besides the vault file.
///
/// An unlock is not done when the data key is recovered: the entries have to
/// land in the store, with their versions and claims, or the whole point of
/// the ceremony — a caller reading its credential afterwards — does not
/// happen. This carries the same handles the control socket's recovery-code
/// path already has, so **both paths restore through one function**
/// (`handler::install_vault_entries`) rather than growing a second, divergent
/// copy of the restore rules.
#[derive(Clone)]
pub struct StoreAccess {
    /// The daemon's store.
    pub store: Arc<Mutex<Store>>,
    /// The capability that authorizes writing to it (DR-0024).
    pub cap: Capability,
    /// The clock entries are timed against.
    pub clock: Arc<SystemClock>,
}

/// Everything the ceremony endpoints share.
pub struct Ceremony {
    challenges: ChallengeStore,
    /// Who this daemon claims to be, and where its page may be served from.
    rp: RelyingParty,
    armed: Option<ArmedRegistration>,
}

impl Ceremony {
    /// Build a ceremony for the configured relying party.
    pub fn new(rp_id: String, allowed_origins: Vec<String>) -> Self {
        Ceremony {
            challenges: ChallengeStore::default(),
            rp: RelyingParty {
                rp_id,
                allowed_origins,
            },
            armed: None,
        }
    }

    /// Open a registration window (DR-0034 §1c).
    ///
    /// Called only after the local approval gate has passed — this type does
    /// not enforce that gate, and must not be reachable except through the
    /// command that does.
    pub fn arm_registration(&mut self, label: String) -> [u8; 32] {
        let salt = UnlockedVault::new_passkey_salt();
        self.armed = Some(ArmedRegistration {
            salt,
            label,
            expires_at: Instant::now() + REGISTRATION_WINDOW,
        });
        salt
    }

    /// Whether a registration window is currently open.
    fn armed(&mut self) -> Option<&ArmedRegistration> {
        if let Some(a) = &self.armed
            && a.expires_at <= Instant::now()
        {
            self.armed = None;
        }
        self.armed.as_ref()
    }
}

/// Why a ceremony listener could not be started.
#[derive(Debug)]
pub enum ListenError {
    /// The address is not on the loopback interface.
    ///
    /// Refused rather than honoured: the ceremony carries key material and
    /// this listener speaks plain HTTP, because TLS is terminated in front of
    /// it (DR-0032). Bound anywhere else, it would be that ceremony in the
    /// clear on the network.
    NotLoopback(String),
    /// The address could not be parsed or bound.
    Io(std::io::Error),
}

impl std::fmt::Display for ListenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenError::NotLoopback(addr) => write!(
                f,
                "the ceremony listener must bind a loopback address, not {addr}: it speaks plain \
                 HTTP because TLS belongs in a proxy in front of it. Put the proxy there and \
                 point it at 127.0.0.1"
            ),
            ListenError::Io(e) => write!(f, "the ceremony listener could not start: {e}"),
        }
    }
}

impl std::error::Error for ListenError {}

/// Bind the ceremony listener, returning it and the address it actually got.
///
/// The address is returned because the default asks for port 0: the command
/// that opens a ceremony has to tell the user a URL, and it can only do that
/// if it knows which port the kernel handed out.
pub async fn bind(
    addr: &str,
) -> Result<(tokio::net::TcpListener, std::net::SocketAddr), ListenError> {
    let parsed: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| ListenError::Io(std::io::Error::other(format!("{addr}: {e}"))))?;
    if !parsed.ip().is_loopback() {
        return Err(ListenError::NotLoopback(addr.to_string()));
    }
    let listener = tokio::net::TcpListener::bind(parsed)
        .await
        .map_err(ListenError::Io)?;
    let bound = listener.local_addr().map_err(ListenError::Io)?;
    Ok((listener, bound))
}

/// Accept ceremony connections until the process ends.
///
/// Each connection is handled on its own task and answers exactly one request.
/// An accept error is logged and the loop continues: a single failed accept
/// (a descriptor limit, a connection reset between accept and read) must not
/// take the ceremony down until the next restart.
pub async fn serve(
    listener: tokio::net::TcpListener,
    ceremony: Arc<Mutex<Ceremony>>,
    vault: Arc<Mutex<VaultState>>,
    store: StoreAccess,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let ceremony = ceremony.clone();
                let vault = vault.clone();
                let store = store.clone();
                tokio::spawn(async move {
                    http::serve_one(stream, move |request| {
                        handle(&ceremony, &vault, &store, request)
                    })
                    .await;
                });
            }
            Err(e) => {
                eprintln!("cache-warden: warning: a ceremony connection was not accepted ({e})");
            }
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn field(body: &serde_json::Value, name: &str) -> Option<Vec<u8>> {
    cache_warden_webauthn::decode_b64(body.get(name)?.as_str()?)
}

/// An error reply.
///
/// Deliberately terse and uniform: the daemon's log records which check
/// failed, the browser is told only that it did. A page that reported "wrong
/// origin" versus "wrong challenge" would be a probing oracle for whoever
/// pointed a browser at this port.
fn refuse(status: u16, message: &str) -> Response {
    Response::json(status, serde_json::json!({ "error": message }))
}

/// Handle one ceremony request.
///
/// `vault` is the daemon's vault state; unlocking through this path replaces
/// it, which is the whole point of the ceremony.
pub fn handle(
    ceremony: &Mutex<Ceremony>,
    vault: &Mutex<VaultState>,
    store: &StoreAccess,
    request: Request,
) -> Response {
    let Ok(mut cer) = ceremony.lock() else {
        return refuse(500, "the ceremony is unavailable");
    };

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => {
            let nonce = page::nonce();
            Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: page::html(&nonce).into_bytes(),
                extra_headers: vec![format!("Content-Security-Policy: {}", page::csp(&nonce))],
            }
        }
        // A cross-origin request would already be stopped by the browser (the
        // endpoints take JSON, which forces a preflight this server does not
        // answer), and the origin that actually decides an unlock is the
        // signed one inside the client data. Checking the header too costs a
        // string compare and closes the gap where neither of those applies —
        // a caller that is not a browser at all.
        ("POST", _) if !origin_allowed(&cer, request.origin.as_deref()) => {
            refuse(403, "that origin is not allowed to run this ceremony")
        }
        ("POST", "/begin") => begin(&mut cer, vault),
        ("POST", "/register/evaluate") => register_evaluate(&mut cer),
        ("POST", "/register/finish") => register_finish(&mut cer, vault, &request),
        ("POST", "/unlock/finish") => unlock_finish(&mut cer, vault, store, &request),
        ("GET", _) | ("POST", _) => refuse(404, "no such endpoint"),
        _ => refuse(405, "unsupported method"),
    }
}

/// Whether a request's `Origin` header, if it sent one, is one we serve.
///
/// An absent header is allowed: a non-browser client (the tests, `curl`) sends
/// none, and the check that actually matters — the origin inside the signed
/// client data — is applied to every ceremony response regardless.
fn origin_allowed(cer: &Ceremony, origin: Option<&str>) -> bool {
    match origin {
        None => true,
        Some(o) => cer.rp.allowed_origins.iter().any(|a| a == o),
    }
}

/// Tell the page what it is for, and give it the options to run.
fn begin(cer: &mut Ceremony, vault: &Mutex<VaultState>) -> Response {
    let Ok(state) = vault.lock() else {
        return refuse(500, "the vault is unavailable");
    };

    // A registration window takes precedence: it was opened deliberately, by
    // someone who just approved it locally.
    if cer.armed().is_some() {
        let salt = cer.armed().expect("checked above").salt;
        let challenge = match cer.challenges.issue(Purpose::RegisterPasskey) {
            Ok(c) => c,
            Err(e) => return refuse(429, &e.to_string()),
        };
        // A stable, non-identifying user handle: this vault has exactly one
        // user, and putting anything derived from the machine or the person
        // here would put it in the authenticator's storage for no benefit.
        let user_id = b64(b"cache-warden-vault");
        return Response::json(
            200,
            serde_json::json!({
                "mode": "register",
                "salt": { "first": b64(&salt), "credential_id": serde_json::Value::Null },
                "options": {
                    "publicKey": {
                        "rp": { "id": cer.rp.rp_id, "name": "cache-warden" },
                        "user": { "id": user_id, "name": "vault", "displayName": "cache-warden vault" },
                        "challenge": b64(&challenge),
                        "pubKeyCredParams": [
                            { "type": "public-key", "alg": -7 },
                            { "type": "public-key", "alg": -8 },
                        ],
                        "authenticatorSelection": {
                            "residentKey": "preferred",
                            "userVerification": "required",
                        },
                        "attestation": "none",
                        "extensions": { "prf": {} },
                        "timeout": 120_000,
                    }
                },
            }),
        );
    }

    // Otherwise this is an unlock. Every passkey slot is offered, each with
    // its own salt (DR-0034 §2): the authenticator evaluates the one belonging
    // to whichever credential the user picks.
    let slots: Vec<_> = match &*state {
        VaultState::Locked { vault } => vault
            .slots()
            .iter()
            .filter(|s| s.kind() == SlotKind::PasskeyPrf)
            .map(|s| (s.credential_id().to_vec(), s.prf_salt().to_vec()))
            .collect(),
        VaultState::Unlocked { .. } => return refuse(400, "the vault is already unlocked"),
        VaultState::NotInitialized { .. } => {
            return refuse(400, "no vault has been created yet");
        }
    };
    if slots.is_empty() {
        return refuse(
            400,
            "no passkey is registered for this vault; unlock with a recovery code and register one",
        );
    }

    let (vault_id, dek_generation) = match &*state {
        VaultState::Locked { vault } => (vault.vault_id().to_string(), vault.dek_generation()),
        _ => unreachable!("the state was matched above"),
    };
    let challenge = match cer.challenges.issue(Purpose::Unlock {
        vault_id,
        dek_generation,
    }) {
        Ok(c) => c,
        Err(e) => return refuse(429, &e.to_string()),
    };

    let allow: Vec<_> = slots
        .iter()
        .map(|(id, _)| serde_json::json!({ "type": "public-key", "id": b64(id) }))
        .collect();
    let salts: serde_json::Map<String, serde_json::Value> = slots
        .iter()
        .map(|(id, salt)| (b64(id), serde_json::json!(b64(salt))))
        .collect();

    Response::json(
        200,
        serde_json::json!({
            "mode": "unlock",
            "salts": salts,
            "options": {
                "publicKey": {
                    "rpId": cer.rp.rp_id,
                    "challenge": b64(&challenge),
                    "allowCredentials": allow,
                    "userVerification": "required",
                    "timeout": 120_000,
                }
            },
        }),
    )
}

/// Options for the assertion that evaluates a new credential's PRF.
///
/// Registration establishes only that a credential *can* derive keys; the
/// value comes from an assertion. Running that assertion here, during
/// registration, is also what proves the credential will actually open the
/// slot about to be created — a slot built from key material that could never
/// be reproduced would be a vault entry nobody can reach.
fn register_evaluate(cer: &mut Ceremony) -> Response {
    if cer.armed().is_none() {
        return refuse(403, "no registration is in progress");
    }
    let challenge = match cer.challenges.issue(Purpose::RegisterPasskey) {
        Ok(c) => c,
        Err(e) => return refuse(429, &e.to_string()),
    };
    Response::json(
        200,
        serde_json::json!({
            "options": {
                "publicKey": {
                    "rpId": cer.rp.rp_id,
                    "challenge": b64(&challenge),
                    "userVerification": "required",
                    "timeout": 120_000,
                }
            },
        }),
    )
}

/// Verify a registration and add the slot it describes.
fn register_finish(cer: &mut Ceremony, vault: &Mutex<VaultState>, request: &Request) -> Response {
    let Some(armed) = cer.armed() else {
        return refuse(403, "no registration is in progress");
    };
    let salt = armed.salt;
    let label = armed.label.clone();

    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
        return refuse(400, "the response was not readable");
    };
    let (Some(client_data), Some(attestation), Some(prf_output), Some(credential_id)) = (
        field(&body, "client_data_json"),
        field(&body, "attestation_object"),
        field(&body, "prf_output"),
        field(&body, "credential_id"),
    ) else {
        return refuse(400, "the response was incomplete");
    };
    // The same key material as an unlock's, and wiped on the same terms: this
    // is the input the new slot's key-encryption key is derived from.
    let prf_output = Zeroizing::new(prf_output);

    // The challenge is inside the client data; parse it out so the store can
    // consume the exact one this response claims.
    let Some(challenge) = challenge_in(&client_data) else {
        return refuse(400, "the response named no challenge");
    };
    if let Err(e) = cer.challenges.redeem(&challenge, &Purpose::RegisterPasskey) {
        eprintln!("cache-warden: ceremony: registration challenge refused: {e}");
        return refuse(403, "that ceremony is no longer valid");
    }

    let credential = match cache_warden_webauthn::verify_registration(
        &cer.rp,
        &challenge,
        &client_data,
        &attestation,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cache-warden: ceremony: registration refused: {e}");
            return refuse(403, "the passkey could not be registered");
        }
    };
    if credential.id != credential_id {
        return refuse(400, "the response named a different credential");
    }

    let Ok(mut state) = vault.lock() else {
        return refuse(500, "the vault is unavailable");
    };
    let Some(unlocked) = state.unlocked_mut() else {
        // Adding a slot re-wraps the data key for a new recipient, which needs
        // the data key. Being unlocked is also what proves the person adding a
        // way in already had one (DR-0034 §1c).
        return refuse(400, "the vault must be unlocked to register a passkey");
    };
    match unlocked.add_passkey_slot(
        &prf_output,
        salt,
        cer.rp.rp_id.clone(),
        credential.id.clone(),
        credential.key.to_stored_bytes(),
        label,
    ) {
        Ok(slot_id) => {
            // One registration per arming: a window that stayed open would let
            // a second, unapproved passkey in behind the first.
            cer.armed = None;
            Response::json(
                200,
                serde_json::json!({ "registered": true, "slot_id": slot_id.to_string() }),
            )
        }
        Err(e) => {
            eprintln!("cache-warden: ceremony: the slot was not written: {e}");
            refuse(500, "the passkey was not registered")
        }
    }
}

/// Verify an assertion and open the vault with the PRF output beside it.
fn unlock_finish(
    cer: &mut Ceremony,
    vault: &Mutex<VaultState>,
    store: &StoreAccess,
    request: &Request,
) -> Response {
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
        return refuse(400, "the response was not readable");
    };
    let (
        Some(credential_id),
        Some(authenticator_data),
        Some(client_data),
        Some(signature),
        Some(prf_output),
    ) = (
        field(&body, "credential_id"),
        field(&body, "authenticator_data"),
        field(&body, "client_data_json"),
        field(&body, "signature"),
        field(&body, "prf_output"),
    )
    else {
        return refuse(400, "the response was incomplete");
    };
    // The PRF output is the vault's key material in the clear. It is wiped
    // when this request ends, however the request ends — the same discipline
    // the vault crate applies to everything it derives from it.
    let prf_output = Zeroizing::new(prf_output);

    // # Lock order
    //
    // The store lock is taken **first**, before the vault's, and held across
    // the whole unlock — because every other path in the daemon takes them in
    // that order (see `HandlerCtx::vault`). Taking them the other way round
    // here would deadlock the daemon on the most ordinary sequence there is:
    // a caller blocked in `kv.get` holding the store lock and waiting on the
    // vault, while this ceremony holds the vault and waits for the store — a
    // user completing an unlock in the browser is exactly what would trigger
    // it, so it is the ordinary case rather than a rare race.
    //
    // Holding the store lock across the assertion verification costs nothing
    // that matters: the work between here and the release is bounded
    // signature checking with no I/O and no waiting on a human.
    let Ok(mut store_guard) = store.store.lock() else {
        return refuse(500, "the store is unavailable");
    };
    let Ok(mut state) = vault.lock() else {
        return refuse(500, "the vault is unavailable");
    };
    let VaultState::Locked { vault: locked } = &*state else {
        return refuse(400, "the vault is not locked");
    };

    // Find the slot this credential belongs to: its stored public key is what
    // the assertion is verified against.
    let Some(slot) = locked
        .slots()
        .iter()
        .find(|s| s.kind() == SlotKind::PasskeyPrf && s.credential_id() == credential_id)
    else {
        return refuse(403, "that passkey does not open this vault");
    };
    let Ok(key) = CredentialPublicKey::from_stored_bytes(slot.credential_public_key()) else {
        return refuse(500, "this slot's credential could not be read");
    };
    let purpose = Purpose::Unlock {
        vault_id: locked.vault_id().to_string(),
        dek_generation: locked.dek_generation(),
    };

    let Some(challenge) = challenge_in(&client_data) else {
        return refuse(400, "the response named no challenge");
    };
    if let Err(e) = cer.challenges.redeem(&challenge, &purpose) {
        eprintln!("cache-warden: ceremony: unlock challenge refused: {e}");
        return refuse(403, "that ceremony is no longer valid");
    }

    let credential = cache_warden_webauthn::RegisteredCredential {
        id: credential_id.clone(),
        key,
    };
    if let Err(e) = cache_warden_webauthn::verify_assertion(
        &cer.rp,
        &challenge,
        &credential,
        &AssertionResponse {
            credential_id: &credential_id,
            authenticator_data: &authenticator_data,
            client_data_json: &client_data,
            signature: &signature,
        },
    ) {
        eprintln!("cache-warden: ceremony: unlock refused: {e}");
        return refuse(403, "that passkey did not open this vault");
    }

    match state.unlock_with_prf_output(&prf_output) {
        Ok(()) => {
            // Recovering the data key is not the end of an unlock. The
            // entries have to reach the store — with their versions and any
            // live claim — or the caller this ceremony was run for still
            // cannot read its credential. Restored through the same function
            // the recovery-code path uses, so the two cannot drift.
            let restored = match state.unlocked() {
                // Written through the guard taken at the top of this function,
                // which is still held. Locking the store again here is what
                // the lock-order note above forbids — and, since this thread
                // already holds it, would deadlock against itself.
                Some(open) => crate::daemon::handler::install_vault_entries(
                    &mut store_guard,
                    &store.cap,
                    store.clock.as_ref(),
                    open,
                ),
                None => {
                    return refuse(
                        500,
                        "the vault opened but its entries could not be restored",
                    );
                }
            };
            Response::json(
                200,
                serde_json::json!({ "unlocked": true, "entries_restored": restored }),
            )
        }
        Err(e) => {
            eprintln!("cache-warden: ceremony: unlock failed after a valid assertion: {e}");
            refuse(403, "that passkey did not open this vault")
        }
    }
}

/// Pull the challenge out of a client data blob.
///
/// The response has to name the challenge it is answering before the store can
/// consume it, and the only place it appears is inside the signed client data.
/// Reading it here does not trust it: it is used to *look up* a challenge, and
/// the verifier then checks that the client data matches what was looked up.
fn challenge_in(client_data_json: &[u8]) -> Option<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_slice(client_data_json).ok()?;
    cache_warden_webauthn::decode_b64(value.get("challenge")?.as_str()?)
}

#[cfg(test)]
mod tests;
