//! The vault's two states and the operations that move between them.
//!
//! [`LockedVault`] is what a vault file is when nothing has opened it: the
//! header is parsed and readable (vault id, generation, which slots exist and
//! what kind they are) but the entries are ciphertext. [`UnlockedVault`] holds
//! the decrypted entries plus the DEK, in an mlock-pinned buffer that is
//! wiped when it drops.
//!
//! The asymmetry between the two is the point of DR-0034 §1b. Reading the
//! vault needs a credential. **Changing who can read it does not** — adding a
//! recipient and rotating the DEK are public-key operations, so
//! [`UnlockedVault::add_recovery_slot`] and [`UnlockedVault::remove_slot`]
//! re-wrap the DEK for every remaining slot without any of those slots'
//! credentials being present. No second passkey ceremony, no other device
//! plugged in.
//!
//! # Every mutation commits
//!
//! `upsert`, `delete`, `add_recovery_slot`, `remove_slot` and `rotate_dek`
//! each rewrite and `fsync` the whole file before returning. There is no
//! "dirty" state to flush later: DR-0034 §3 requires that a caller told a
//! write succeeded can rely on it having survived a crash, and the only way to
//! keep that promise is to make the durable write part of the operation. The
//! vault holds credentials, not bulk data, so rewriting it whole costs
//! nothing worth optimizing.
//!
//! # Commit, then install
//!
//! Each mutation builds the state it intends to write — a slot set, a
//! generation, an entry map — writes *that* to disk, and only assigns it to
//! `self` once the write has returned successfully. So a failed commit changes
//! nothing at all, in memory or on disk, and the caller can retry or carry on
//! reading without wondering which.
//!
//! The obvious alternative (mutate, write, undo on error) cannot make that
//! promise. Undoing requires knowing what the file ended up as, and a commit
//! can fail *after* its `rename` has landed — in which case rolling memory
//! back would leave it disagreeing with the file rather than matching it. The
//! worst version of that is a slot removal: it rotates the DEK, so a failed
//! removal that stayed applied in memory would have the next successful write
//! silently persist a revocation the caller was told had failed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cache_warden::SecretBytes;
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::body::{VaultBody, VaultEntry};
use crate::claim::{Claim, ClaimToken};
use crate::crypto::{self, KEY_LEN};
use crate::error::VaultError;
use crate::format::{
    AeadAlg, FORMAT_VERSION, HeaderView, KdfAlg, SALT_LEN, Slot, SlotId, SlotKind, VaultFile,
    VaultId, encode_file, now_epoch_ms,
};
use crate::recovery::RecoveryCode;
use crate::storage;

/// A vault file that has been read and validated, but not opened.
///
/// Everything reachable here is the plaintext metadata DR-0034 §7 puts
/// deliberately outside the encryption: which vault this is, how many times
/// its DEK has rotated, and which credentials can open it. Entry names, values,
/// guards and owners are not — those need [`LockedVault::unlock_with_recovery_code`].
pub struct LockedVault {
    path: PathBuf,
    file: VaultFile,
    /// The header bytes exactly as read, which authenticate the body.
    header_aad: Vec<u8>,
}

impl LockedVault {
    /// Read and validate the vault file at `path`.
    ///
    /// Fails if the file is not a vault, declares a format version this build
    /// does not support (including a *newer* one — see
    /// [`VaultError::UnsupportedVersion`]), or is structurally malformed. No
    /// decryption is attempted, so this succeeds without any credential.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, VaultError> {
        let path = path.into();
        let bytes = storage::read(&path)?;
        let (file, header_aad) = VaultFile::decode(&bytes)?;
        Ok(Self {
            path,
            file,
            header_aad,
        })
    }

    /// [`LockedVault::open`], additionally requiring the file to be the vault
    /// with `expected` as its id.
    ///
    /// Use this wherever a path is remembered across restarts: it turns "a
    /// different vault has been put at this path" — a restored backup, a
    /// development vault copied over the production one — from a silent
    /// substitution into an error.
    pub fn open_expecting(path: impl Into<PathBuf>, expected: VaultId) -> Result<Self, VaultError> {
        let v = Self::open(path)?;
        if v.vault_id() != expected {
            return Err(VaultError::VaultIdMismatch);
        }
        Ok(v)
    }

    /// This vault's permanent id.
    pub fn vault_id(&self) -> VaultId {
        self.file.vault_id
    }

    /// How many times the DEK has been rotated.
    pub fn dek_generation(&self) -> u64 {
        self.file.dek_generation
    }

    /// The format version the file declares.
    pub fn format_version(&self) -> u32 {
        self.file.format_version
    }

    /// The AEAD this vault is encrypted with.
    pub fn aead_alg(&self) -> AeadAlg {
        self.file.aead_alg
    }

    /// The KDF this vault derives slot keys with.
    pub fn kdf_alg(&self) -> KdfAlg {
        self.file.kdf_alg
    }

    /// Every recipient that can open this vault.
    pub fn slots(&self) -> &[Slot] {
        &self.file.slots
    }

    /// The file this vault was read from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether any slot was registered against a development-only WebAuthn RP
    /// (DR-0034 §7).
    ///
    /// A vault opens for *any* of its slots, so its strength is its weakest
    /// slot's. A `localhost` registration was made over a connection with no
    /// meaningful origin authentication; finding one in a production vault is
    /// a reason to warn loudly, which is what phase 4 does with this.
    pub fn has_dev_rp_slot(&self) -> bool {
        self.file.slots.iter().any(Slot::is_dev_rp)
    }

    /// Open the vault with a recovery code (DR-0034 §9).
    ///
    /// Every recovery slot is tried, so a vault with several recovery codes
    /// opens for any of them. A code that matches no slot yields
    /// [`VaultError::NoMatchingSlot`]; a code that opens a slot whose DEK or
    /// body then fails to decrypt yields [`VaultError::DecryptFailed`], which
    /// means the file was altered rather than the code being wrong.
    ///
    /// The passkey-PRF path (phase 4) derives its slot KEK through the same
    /// [`crate::crypto::derive_kek`] with the PRF output in place of the
    /// recovery secret; only the ceremony that produces that output is
    /// missing, not the format or the key schedule.
    pub fn unlock_with_recovery_code(
        self,
        code: &RecoveryCode,
    ) -> Result<UnlockedVault, VaultError> {
        self.unlock_with_secret(code.secret(), SlotKind::Recovery)
    }

    /// Open the vault with a passkey's PRF output (DR-0034 §2).
    ///
    /// The counterpart of [`UnlockedVault::add_passkey_slot`]: the ceremony
    /// evaluated a slot's salt and produced this, and the same derivation runs
    /// in reverse to reach the data key.
    ///
    /// Every passkey slot is tried, not just the one whose credential was
    /// asserted. The alternative — trusting the caller's slot id — would let a
    /// mistaken lookup report "wrong passkey" for a credential that does in
    /// fact open the vault, and trying the others costs one HKDF and one
    /// failed AEAD open each.
    pub fn unlock_with_prf_output(self, prf_output: &[u8]) -> Result<UnlockedVault, VaultError> {
        self.unlock_with_secret(prf_output, SlotKind::PasskeyPrf)
    }

    /// Open the vault directly from a data key that a predecessor process was
    /// already holding (DR-0034 §11).
    ///
    /// This is the graceful-restart path and nothing else. It takes no
    /// credential because there is none to take: the key arrived over the
    /// private socketpair from the process that had already earned it, and
    /// demanding a fresh ceremony would be the exact user-visible cost — a
    /// storm of prompts on every upgrade — that graceful restart exists to
    /// avoid.
    ///
    /// The key is still verified rather than trusted: it has to decrypt the
    /// body, authenticated against the header, or this fails. A wrong or
    /// corrupted key cannot open the vault, so a mangled handoff degrades to
    /// "stays locked" instead of "opens with garbage".
    pub fn unlock_with_dek(self, dek: &[u8]) -> Result<UnlockedVault, VaultError> {
        let key: [u8; KEY_LEN] = dek.try_into().map_err(|_| VaultError::Malformed {
            reason: "a handed-off data key was not 32 bytes",
        })?;
        let plaintext = crypto::open(&key, &self.header_aad, &self.file.sealed_body, "contents")?;
        let entries = Self::parse_entries(&plaintext)?;
        Ok(UnlockedVault {
            path: self.path,
            vault_id: self.file.vault_id,
            format_version: self.file.format_version,
            dek_generation: self.file.dek_generation,
            aead_alg: self.file.aead_alg,
            kdf_alg: self.file.kdf_alg,
            slots: self.file.slots,
            dek: SecretBytes::new(key.to_vec()),
            entries,
        })
    }

    /// Parse a decrypted body into the entry map, rejecting duplicate keys.
    fn parse_entries(plaintext: &[u8]) -> Result<BTreeMap<String, VaultEntry>, VaultError> {
        let body = VaultBody::from_plaintext(plaintext)?;
        let mut entries = BTreeMap::new();
        for entry in body.entries {
            if entries.insert(entry.key.clone(), entry).is_some() {
                return Err(VaultError::Malformed {
                    reason: "two entries share one key",
                });
            }
        }
        Ok(entries)
    }

    /// Try `input_secret` against every slot of `kind`.
    fn unlock_with_secret(
        self,
        input_secret: &[u8],
        kind: SlotKind,
    ) -> Result<UnlockedVault, VaultError> {
        let vault_id = self.file.vault_id;
        let format_version = self.file.format_version;

        for slot in &self.file.slots {
            if slot.kind() != kind {
                continue;
            }
            let aad = slot.own_binding_aad(vault_id, format_version);
            let kek = crypto::derive_kek(
                input_secret,
                slot.salt(),
                vault_id,
                format_version,
                slot.id(),
            );
            // A slot whose private key does not open is simply not this
            // credential's slot; keep looking rather than failing the unlock.
            let Ok(privkey) = crypto::open(&kek, &aad, slot.wrapped_privkey(), "slot private key")
            else {
                continue;
            };

            let secret = static_secret_from(&privkey)?;
            // Past this point the credential *is* this slot's, so a failure
            // means the file was altered, not that the wrong code was given.
            let dek = crypto::unwrap_dek(slot.wrapped_dek(), &secret, vault_id, slot.id(), &aad)?;
            let dek: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(dek.as_slice().try_into().map_err(
                |_| VaultError::Malformed {
                    reason: "a wrapped DEK decrypted to something other than a 32-byte key",
                },
            )?);
            let plaintext =
                crypto::open(&dek, &self.header_aad, &self.file.sealed_body, "contents")?;
            let entries = Self::parse_entries(&plaintext)?;

            return Ok(UnlockedVault {
                path: self.path,
                vault_id,
                format_version,
                dek_generation: self.file.dek_generation,
                aead_alg: self.file.aead_alg,
                kdf_alg: self.file.kdf_alg,
                slots: self.file.slots,
                // Held in the core's mlock-pinned, zeroize-on-drop buffer for
                // as long as the vault is open (DR-0007 / DR-0034 §6).
                dek: SecretBytes::new(dek.to_vec()),
                entries,
            });
        }

        Err(VaultError::NoMatchingSlot)
    }
}

// Hand-written and secret-free. A derive would reach the DEK, and print it.
// The fields shown are exactly the ones DR-0034 §7 already treats as public
// metadata, plus counts — never an entry name or value.
impl std::fmt::Debug for LockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedVault")
            .field("path", &self.path)
            .field("vault_id", &self.vault_id().to_string())
            .field("format_version", &self.format_version())
            .field("dek_generation", &self.dek_generation())
            .field("slots", &self.slots().len())
            .finish()
    }
}

/// An open vault: decrypted entries plus the DEK that decrypted them.
///
/// The DEK stays resident for as long as this value lives. DR-0034 §6 is
/// explicit that this residency is the design's accepted weak point — while a
/// vault is open, an attacker who can read this process's memory defeats the
/// encryption entirely, exactly as they would for any secret cache-warden
/// already holds in memory. Dropping this value (or calling
/// [`UnlockedVault::lock`]) wipes the DEK.
pub struct UnlockedVault {
    path: PathBuf,
    vault_id: VaultId,
    format_version: u32,
    dek_generation: u64,
    aead_alg: AeadAlg,
    kdf_alg: KdfAlg,
    slots: Vec<Slot>,
    dek: SecretBytes,
    entries: BTreeMap<String, VaultEntry>,
}

// See the note on `LockedVault`'s implementation. The entry *count* is shown;
// the keys are not, because an unlocked vault is the one place they exist in
// the clear and a stray `{:?}` should not be what puts them in a log.
impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("path", &self.path)
            .field("vault_id", &self.vault_id.to_string())
            .field("format_version", &self.format_version)
            .field("dek_generation", &self.dek_generation)
            .field("slots", &self.slots.len())
            .field("entries", &self.entries.len())
            .field("dek", &"[REDACTED]")
            .finish()
    }
}

impl UnlockedVault {
    /// Create a new vault at `path` and return it open, alongside its recovery
    /// code.
    ///
    /// The recovery slot is created here and cannot be skipped (DR-0034 §9).
    /// With cache-warden as the sole source of truth for the values it holds,
    /// a vault with no recovery path is a vault whose contents are one lost
    /// passkey away from being gone; making the slot optional would be
    /// offering that outcome as a configuration choice.
    ///
    /// The returned code is the only copy — show it to the user once, with
    /// [`crate::RECOVERY_STORAGE_GUIDANCE`], and let it drop.
    ///
    /// Fails with [`std::io::ErrorKind::AlreadyExists`] if a file is already at
    /// `path`. That refusal is enforced by creating the file exclusively rather
    /// than by testing for it first: an existence test followed by a write is a
    /// race two processes can both pass, and the loser of that race would have
    /// its vault — and the only copy of everything in it — replaced by an empty
    /// one. See [`crate::storage`]'s `create_new`.
    pub fn initialize(path: impl Into<PathBuf>) -> Result<(Self, RecoveryCode), VaultError> {
        let path = path.into();
        let vault_id = VaultId::random();
        let dek = crypto::random_key();
        let code = RecoveryCode::generate();
        let slot = build_slot(
            SlotKind::Recovery,
            &dek,
            vault_id,
            FORMAT_VERSION,
            code.secret(),
            random_salt(),
            String::new(),
            Vec::new(),
            Vec::new(),
            "recovery code".to_string(),
        )?;

        let vault = Self {
            path,
            vault_id,
            format_version: FORMAT_VERSION,
            dek_generation: 1,
            aead_alg: AeadAlg::XChaCha20Poly1305,
            kdf_alg: KdfAlg::HkdfSha256,
            slots: vec![slot],
            dek: SecretBytes::new(dek.to_vec()),
            entries: BTreeMap::new(),
        };
        let bytes = vault.encode(&vault.slots, vault.dek_generation, &vault.entries);
        storage::create_new(&vault.path, &bytes)?;
        Ok((vault, code))
    }

    /// This vault's permanent id.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// How many times the DEK has been rotated.
    pub fn dek_generation(&self) -> u64 {
        self.dek_generation
    }

    /// Every recipient that can open this vault.
    pub fn slots(&self) -> &[Slot] {
        &self.slots
    }

    /// See [`LockedVault::has_dev_rp_slot`].
    pub fn has_dev_rp_slot(&self) -> bool {
        self.slots.iter().any(Slot::is_dev_rp)
    }

    /// The file this vault lives in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// One entry, if present.
    pub fn entry(&self, key: &str) -> Option<&VaultEntry> {
        self.entries.get(key)
    }

    /// Every entry key, in sorted order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// How many entries the vault holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the vault holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert or replace an entry unconditionally, then commit durably.
    ///
    /// Returns only after `fsync`, so a caller that has been told this
    /// succeeded may report the value as saved (DR-0034 §3). On failure the
    /// vault is unchanged in memory as well as on disk.
    ///
    /// "Unconditionally" covers the **version** only. The claim fence still
    /// applies: if the entry has an active claim, `token` must be that claim's
    /// token, exactly as for [`UnlockedVault::upsert_cas`]. Skipping the fence
    /// here would make the entire protection optional by choosing the other
    /// method — and since a plain `set` is the natural mapping for a caller
    /// that did not ask for compare-and-swap, that is the door a refresh in
    /// flight would actually be walked through. A successful write releases
    /// the claim, as it does everywhere else.
    pub fn upsert(
        &mut self,
        entry: VaultEntry,
        token: Option<&ClaimToken>,
    ) -> Result<u64, VaultError> {
        let current = self.entries.get(&entry.key);
        let next_version = current.map_or(0, |e| e.cas_version).saturating_add(1);
        if let Some(existing) = current {
            check_claim(existing, token, now_epoch_ms())?;
        }
        self.write_entry(entry, next_version)
    }

    /// Insert or replace an entry **only if** its current version is
    /// `expected_version`, then commit durably (DR-0034 §4).
    ///
    /// Returns the entry's new version. Pass `0` as `expected_version` to mean
    /// "I expect this key not to exist yet" — versions start at 1, so zero is
    /// unambiguous and a create races safely against another create.
    ///
    /// On a version mismatch **nothing is written**: the check happens before
    /// any encoding or filesystem work, so a losing racer costs one comparison
    /// rather than a rewrite of the whole vault. [`VaultError::CasMismatch`]
    /// carries the version actually found, which is what the caller needs to
    /// re-read and decide.
    ///
    /// # Claims
    ///
    /// If the entry has an **active** claim, `token` must be that claim's
    /// token. This is the fence described in [`crate::ClaimToken`]: without it,
    /// a caller whose claim lapsed while another caller took over would still
    /// pass the version check and write. A successful write **releases the
    /// claim** — the refresh it was holding the entry for is done.
    ///
    /// A lapsed claim demands nothing: if nobody took over, the original
    /// caller's late write is the only write, and there is nothing to protect
    /// the entry from.
    ///
    /// The submitted entry's own `cas_version` and `refresh_claim` are ignored;
    /// the vault assigns both.
    pub fn upsert_cas(
        &mut self,
        entry: VaultEntry,
        expected_version: u64,
        token: Option<&ClaimToken>,
    ) -> Result<u64, VaultError> {
        let current = self.entries.get(&entry.key);
        let current_version = current.map_or(0, |e| e.cas_version);
        if current_version != expected_version {
            // Deliberately before any encoding or IO: a CAS loser must not
            // cost a vault rewrite (DR-0034 §4).
            return Err(VaultError::CasMismatch {
                current: current_version,
            });
        }
        if let Some(existing) = current {
            check_claim(existing, token, now_epoch_ms())?;
        }
        self.write_entry(entry, current_version + 1)
    }

    /// Take the refresh claim on `key`, returning the token that must be
    /// presented to write while it holds (DR-0034 §4).
    ///
    /// Guarded by the same version check as [`UnlockedVault::upsert_cas`], so a
    /// caller working from a stale read cannot claim. The claim itself does
    /// **not** advance the version: the version counts value changes, and a
    /// claim changes no value. Advancing it here would mean a claim taken and
    /// released without a refresh had silently invalidated every other holder's
    /// read.
    ///
    /// An already-claimed entry yields [`VaultError::AlreadyClaimed`] with the
    /// holder's expiry — the signal to wait for the new value instead of
    /// calling the provider. A **lapsed** claim is simply replaced; that is
    /// what the expiry is for.
    ///
    /// A zero `ttl` produces a claim that has already lapsed. That is not a
    /// special case in the code and is allowed on purpose: it makes the
    /// lapsed-claim path reachable in a test without waiting for wall-clock
    /// time to pass.
    pub fn claim_refresh(
        &mut self,
        key: &str,
        expected_version: u64,
        ttl: Duration,
    ) -> Result<ClaimToken, VaultError> {
        let entry = self.entries.get(key).ok_or(VaultError::EntryNotFound)?;
        if entry.cas_version != expected_version {
            return Err(VaultError::CasMismatch {
                current: entry.cas_version,
            });
        }
        let now = now_epoch_ms();
        if let Some(active) = entry.refresh_claim.as_ref().filter(|c| c.is_active_at(now)) {
            return Err(VaultError::AlreadyClaimed {
                expires_at_epoch_ms: active.expires_at_epoch_ms,
            });
        }

        let token = ClaimToken::generate();
        let mut next = self.entries.clone();
        next.get_mut(key).expect("looked up above").refresh_claim = Some(Claim {
            token: token.clone(),
            claimed_at_epoch_ms: now,
            // Saturating: a caller passing a TTL that overflows the epoch gets
            // a claim that never lapses rather than one that lapsed long ago.
            expires_at_epoch_ms: now.saturating_add(ttl.as_millis().min(u64::MAX.into()) as u64),
        });
        self.commit(&self.slots, self.dek_generation, &next)?;
        self.entries = next;
        Ok(token)
    }

    /// Release the claim on `key` without writing a value.
    ///
    /// For the caller that claimed, called the provider, and got nothing worth
    /// storing — an error, or a value identical to the one already held.
    /// Releasing lets the next caller start immediately instead of waiting out
    /// the expiry.
    ///
    /// Requires the active claim's token, for the same reason writing does: a
    /// caller whose claim lapsed must not be able to cancel the claim that
    /// replaced it. Releasing an entry with no active claim succeeds and does
    /// nothing, so a caller retrying a release after a crash is not punished
    /// for it.
    pub fn release_claim(&mut self, key: &str, token: &ClaimToken) -> Result<(), VaultError> {
        let entry = self.entries.get(key).ok_or(VaultError::EntryNotFound)?;
        let now = now_epoch_ms();
        match entry.refresh_claim.as_ref().filter(|c| c.is_active_at(now)) {
            None => {
                // Nothing holds the entry. If a lapsed record is still sitting
                // there, clear it so `status` stops reporting a claim nobody
                // holds; otherwise there is genuinely nothing to do.
                if entry.refresh_claim.is_none() {
                    return Ok(());
                }
            }
            Some(active) if !active.token.matches(token) => {
                return Err(VaultError::ClaimTokenMismatch);
            }
            Some(_) => {}
        }
        let mut next = self.entries.clone();
        next.get_mut(key).expect("looked up above").refresh_claim = None;
        self.commit(&self.slots, self.dek_generation, &next)?;
        self.entries = next;
        Ok(())
    }

    /// The active claim on `key`, or `None` when the entry is unclaimed, its
    /// claim has lapsed, or it does not exist.
    pub fn active_claim(&self, key: &str) -> Option<&Claim> {
        self.entries
            .get(key)?
            .refresh_claim
            .as_ref()
            .filter(|c| c.is_active_at(now_epoch_ms()))
    }

    /// Install `entry` at `version`, clearing any claim, and commit.
    ///
    /// The single place a version is assigned, so "every write advances the
    /// version by exactly one" is a property of one function rather than of
    /// every caller remembering to do it.
    fn write_entry(&mut self, mut entry: VaultEntry, version: u64) -> Result<u64, VaultError> {
        entry.cas_version = version;
        // A completed write ends the refresh the claim was held for.
        entry.refresh_claim = None;
        entry.updated_at_epoch_ms = now_epoch_ms();

        let key = entry.key.clone();
        let mut next = self.entries.clone();
        next.insert(key, entry);
        self.commit(&self.slots, self.dek_generation, &next)?;
        self.entries = next;
        Ok(version)
    }

    /// Remove an entry, then commit durably. Returns whether it was there.
    ///
    /// This removes the entry outright — value, version and claim together.
    /// It is therefore **not** the mapping for the in-memory store's
    /// value-only `delete`, which deliberately keeps the key's version alive
    /// so a stale writer cannot win a compare-and-swap against a re-created
    /// key (DR-0034 §4). The vault has no counterpart to that "value gone,
    /// counter retained" state, so phase 3 must map a value-only delete to
    /// something other than this call rather than assuming they correspond.
    pub fn delete(&mut self, key: &str) -> Result<bool, VaultError> {
        if !self.entries.contains_key(key) {
            return Ok(false);
        }
        let mut next = self.entries.clone();
        next.remove(key);
        self.commit(&self.slots, self.dek_generation, &next)?;
        self.entries = next;
        Ok(true)
    }

    /// Add a second recovery slot and return its id with a fresh code.
    ///
    /// A public-key operation on the new slot only: the DEK is wrapped to the
    /// new recipient and no existing slot is touched, so the DEK does not
    /// rotate and every existing credential keeps working unchanged.
    ///
    /// Each slot is another way in, so each one widens the attack surface —
    /// DR-0034 §1c puts slot addition behind the same local TouchID gate as
    /// passkey registration. That gate belongs to the command layer; this
    /// function is the mechanism it calls once the gate has passed.
    pub fn add_recovery_slot(
        &mut self,
        label: impl Into<String>,
    ) -> Result<(SlotId, RecoveryCode), VaultError> {
        let code = RecoveryCode::generate();
        let slot = self.dek_with_exposed(|dek| {
            build_slot(
                SlotKind::Recovery,
                dek,
                self.vault_id,
                self.format_version,
                code.secret(),
                random_salt(),
                String::new(),
                Vec::new(),
                Vec::new(),
                label.into(),
            )
        })?;
        let id = slot.id();

        let mut next = self.slots.clone();
        next.push(slot);
        self.commit(&next, self.dek_generation, &self.entries)?;
        self.slots = next;
        Ok((id, code))
    }

    /// The salt a new passkey slot's ceremony must evaluate (DR-0034 §2).
    ///
    /// Generated before the ceremony rather than after it, because the salt is
    /// an *input* to the ceremony: the page passes it to the authenticator,
    /// which evaluates its PRF over it, and the output is what this slot's key
    /// is derived from. Hand this to the ceremony, then pass it back to
    /// [`UnlockedVault::add_passkey_slot`] with the output it produced.
    ///
    /// Random per slot, and stored in the header, exactly as §2 specifies —
    /// so the same passkey registered against two vaults, or twice against
    /// one, yields unrelated key material each time.
    pub fn new_passkey_salt() -> [u8; SALT_LEN] {
        random_salt()
    }

    /// Add a passkey slot from a completed registration ceremony
    /// (DR-0034 §1c / §2).
    ///
    /// `prf_output` is what the authenticator returned for `salt`; it is the
    /// secret this slot's key-encryption key is derived from, and the reason
    /// the slot can later be opened by that passkey and nothing else.
    /// `credential_id` and `credential_public_key` are recorded so a later
    /// unlock can address the right credential and verify what it signs.
    ///
    /// Like [`UnlockedVault::add_recovery_slot`], this is a public-key
    /// operation on the new slot alone: the DEK does not rotate and no
    /// existing slot is touched, so adding a device needs no other device.
    ///
    /// **The local approval gate is the caller's job, not this function's.**
    /// Each slot is another way in (DR-0034 §1c), and the daemon gates the
    /// command that reaches here on a local human approval.
    pub fn add_passkey_slot(
        &mut self,
        prf_output: &[u8],
        salt: [u8; SALT_LEN],
        rp_id: impl Into<String>,
        credential_id: Vec<u8>,
        credential_public_key: Vec<u8>,
        label: impl Into<String>,
    ) -> Result<SlotId, VaultError> {
        if credential_id.is_empty() || credential_public_key.is_empty() {
            return Err(VaultError::Malformed {
                reason: "a passkey slot needs both a credential id and its public key",
            });
        }
        let slot = self.dek_with_exposed(|dek| {
            build_slot(
                SlotKind::PasskeyPrf,
                dek,
                self.vault_id,
                self.format_version,
                prf_output,
                salt,
                rp_id.into(),
                credential_id,
                credential_public_key,
                label.into(),
            )
        })?;
        let id = slot.id();

        let mut next = self.slots.clone();
        next.push(slot);
        self.commit(&next, self.dek_generation, &self.entries)?;
        self.slots = next;
        Ok(id)
    }

    /// Remove a slot, rotating the DEK in the same commit.
    ///
    /// **Removal always rotates** (DR-0034 §1c). Dropping the slot from the
    /// header alone would leave the same DEK protecting the vault, so anyone
    /// who ever held the removed credential — and kept a copy of the file, or
    /// the DEK itself — could still read every future version. Rotation makes
    /// the removal mean what a user reading "remove this device" expects it to
    /// mean.
    ///
    /// Rotation re-wraps the new DEK for every remaining slot using their
    /// **public keys**, so removing a device needs no other device present.
    ///
    /// Refuses to remove the last slot: the vault would become permanently
    /// unopenable.
    pub fn remove_slot(&mut self, id: SlotId) -> Result<(), VaultError> {
        let Some(index) = self.slots.iter().position(|s| s.id() == id) else {
            return Err(VaultError::SlotNotFound);
        };
        if self.slots.len() == 1 {
            return Err(VaultError::LastSlot);
        }
        let mut remaining = self.slots.clone();
        remaining.remove(index);
        self.rotate_onto(remaining)
    }

    /// Generate a new DEK, re-wrap it for every slot, and commit.
    ///
    /// The whole rotation is one atomic replacement (DR-0034 §3): the file
    /// that appears at the path carries the new generation, the new body and
    /// every slot's new wrap together, or the old file remains untouched.
    /// There is no intermediate state where some slots hold the new DEK and
    /// others the old.
    pub fn rotate_dek(&mut self) -> Result<(), VaultError> {
        self.rotate_onto(self.slots.clone())
    }

    /// Rotate the DEK onto exactly `slots` — the shared body of
    /// [`UnlockedVault::rotate_dek`] and [`UnlockedVault::remove_slot`], which
    /// differ only in whether a slot is dropped from the set first.
    fn rotate_onto(&mut self, mut slots: Vec<Slot>) -> Result<(), VaultError> {
        let new_dek = crypto::random_key();
        for slot in &mut slots {
            // Public key only — the property that makes rotation possible
            // without any slot's credential (DR-0034 §1b).
            let aad = slot.own_binding_aad(self.vault_id, self.format_version);
            let wrapped =
                crypto::wrap_dek(&new_dek, slot.pubkey(), self.vault_id, slot.id(), &aad)?;
            slot.set_wrapped_dek(wrapped);
        }
        let generation = self.dek_generation + 1;
        self.commit_with_dek(&new_dek, &slots, generation, &self.entries)?;
        self.slots = slots;
        self.dek = SecretBytes::new(new_dek.to_vec());
        self.dek_generation = generation;
        Ok(())
    }

    /// Copy the data key out, for handing to a successor process over the
    /// private graceful-restart channel (DR-0034 §11).
    ///
    /// The only way the key leaves this type, and deliberately narrow: the
    /// copy is `Zeroizing`, so it is wiped when the handoff buffer is dropped
    /// rather than lingering in an ordinary allocation. Every other use of the
    /// key stays inside `with_exposed` (DR-0028).
    pub fn export_dek(&self) -> Zeroizing<Vec<u8>> {
        self.dek.with_exposed(|k| Zeroizing::new(k.to_vec()))
    }

    /// Close the vault, wiping the DEK, and return it in its locked form.
    ///
    /// Dropping an `UnlockedVault` wipes the DEK too — this exists for the
    /// caller that wants to keep reading the header afterwards.
    pub fn lock(self) -> Result<LockedVault, VaultError> {
        let path = self.path.clone();
        drop(self);
        LockedVault::open(path)
    }

    /// Durably replace the file with the given state, under the current DEK.
    ///
    /// Every mutation goes through here **before** it touches `self`. Writing
    /// first and installing second is what makes a failed commit a no-op: the
    /// alternative — mutate, write, undo on error — has to reason about what
    /// the file looks like after a partial failure, and gets it wrong for the
    /// case where the rename landed but the directory `fsync` did not. Here
    /// there is nothing to undo, because nothing was done.
    fn commit(
        &self,
        slots: &[Slot],
        generation: u64,
        entries: &BTreeMap<String, VaultEntry>,
    ) -> Result<(), VaultError> {
        self.dek_with_exposed(|dek| self.commit_with_dek(dek, slots, generation, entries))
    }

    /// [`UnlockedVault::commit`] under an explicit DEK, for the rotation that
    /// is replacing `self.dek` and cannot use it.
    fn commit_with_dek(
        &self,
        dek: &[u8; KEY_LEN],
        slots: &[Slot],
        generation: u64,
        entries: &BTreeMap<String, VaultEntry>,
    ) -> Result<(), VaultError> {
        storage::commit(
            &self.path,
            &self.encode_with_dek(slots, generation, entries, dek),
        )
    }

    /// Encode a whole vault file: header first, then the body sealed against
    /// those exact header bytes.
    fn encode_with_dek(
        &self,
        slots: &[Slot],
        generation: u64,
        entries: &BTreeMap<String, VaultEntry>,
        dek: &[u8; KEY_LEN],
    ) -> Vec<u8> {
        let plaintext = VaultBody::new(entries.values().cloned().collect()).to_plaintext();
        let header = HeaderView {
            format_version: self.format_version,
            vault_id: self.vault_id,
            dek_generation: generation,
            aead_alg: self.aead_alg,
            kdf_alg: self.kdf_alg,
            slots,
        }
        .encode();
        let sealed_body = crypto::seal(dek, &header, &plaintext);
        encode_file(header, &sealed_body)
    }

    /// [`UnlockedVault::encode_with_dek`] under the current DEK.
    fn encode(
        &self,
        slots: &[Slot],
        generation: u64,
        entries: &BTreeMap<String, VaultEntry>,
    ) -> Vec<u8> {
        self.dek_with_exposed(|dek| self.encode_with_dek(slots, generation, entries, dek))
    }

    /// Run `f` with the DEK exposed as a fixed-size key.
    ///
    /// Every use of the DEK goes through here so the plaintext key is only
    /// ever borrowed from the pinned buffer and never copied into one that
    /// nothing wipes (DR-0028).
    fn dek_with_exposed<R>(&self, f: impl FnOnce(&[u8; KEY_LEN]) -> R) -> R {
        self.dek.with_exposed(|bytes| {
            let key: &[u8; KEY_LEN] = bytes
                .try_into()
                .expect("the DEK is always 32 bytes; it is only ever set from a 32-byte key");
            f(key)
        })
    }
}

/// Build a new slot: fresh recipient key pair, fresh salt, private key wrapped
/// under the KEK derived from `input_secret`, and the DEK wrapped to the new
/// public key.
#[allow(clippy::too_many_arguments)]
fn build_slot(
    kind: SlotKind,
    dek: &[u8; KEY_LEN],
    vault_id: VaultId,
    format_version: u32,
    input_secret: &[u8],
    salt: [u8; SALT_LEN],
    rp_id: String,
    credential_id: Vec<u8>,
    credential_public_key: Vec<u8>,
    label: String,
) -> Result<Slot, VaultError> {
    let slot_id = SlotId::random();
    let (secret, pubkey) = crypto::generate_recipient();

    let aad = Slot::binding_aad(vault_id, format_version, slot_id, kind, &pubkey);
    let kek = crypto::derive_kek(input_secret, &salt, vault_id, format_version, slot_id);
    // `to_bytes` copies the private key out of the dalek type; hold the copy in
    // a self-wiping buffer so it does not outlive this call in the clear.
    let privkey_bytes = Zeroizing::new(secret.to_bytes());
    let wrapped_privkey = crypto::seal(&kek, &aad, privkey_bytes.as_ref());
    let wrapped_dek = crypto::wrap_dek(dek, &pubkey, vault_id, slot_id, &aad)?;

    Ok(Slot::new(
        slot_id,
        kind,
        pubkey,
        salt,
        wrapped_privkey,
        wrapped_dek,
        rp_id,
        credential_id,
        credential_public_key,
        label,
    ))
}

/// A fresh per-slot HKDF salt (DR-0034 §2).
fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    crypto::fill_random(&mut salt);
    salt
}

/// Reject a write that does not satisfy the entry's active claim.
///
/// Split out so the rule reads in one place: an active claim demands its own
/// token, and a lapsed one demands nothing.
fn check_claim(
    existing: &VaultEntry,
    token: Option<&ClaimToken>,
    now: u64,
) -> Result<(), VaultError> {
    let Some(active) = existing
        .refresh_claim
        .as_ref()
        .filter(|c| c.is_active_at(now))
    else {
        return Ok(());
    };
    match token {
        None => Err(VaultError::ClaimRequired {
            expires_at_epoch_ms: active.expires_at_epoch_ms,
        }),
        Some(t) if !active.token.matches(t) => Err(VaultError::ClaimTokenMismatch),
        Some(_) => Ok(()),
    }
}

/// Rebuild a `StaticSecret` from decrypted private key bytes.
fn static_secret_from(bytes: &Zeroizing<Vec<u8>>) -> Result<StaticSecret, VaultError> {
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::Malformed {
            reason: "a slot private key decrypted to something other than 32 bytes",
        })?;
    Ok(StaticSecret::from(arr))
}
