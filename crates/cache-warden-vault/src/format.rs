//! The on-disk vault format (DR-0034 §1a / §1b): a plaintext header carrying
//! the recipient slots, followed by one AEAD-sealed body.
//!
//! ```text
//! header (plaintext, authenticated as the body's AAD)
//!   magic           8   "CWVAULT\0"
//!   format_version  4   u32 big-endian
//!   vault_id       16
//!   dek_generation  8   u64 big-endian
//!   aead_alg_id     2   u16 big-endian
//!   kdf_alg_id      2   u16 big-endian
//!   slot_count      4   u32 big-endian
//!   slots           …   slot_count × Slot
//! body
//!   body_len        8   u64 big-endian
//!   body            …   nonce ‖ AEAD(DEK, entries, aad = every header byte above)
//! ```
//!
//! ```text
//! Slot
//!   slot_id            16
//!   kind                2   u16 big-endian
//!   pubkey             32   X25519 public key
//!   salt               32   HKDF salt, public by design
//!   created_at          8   u64 big-endian, epoch milliseconds
//!   wrapped_privkey     4+n AEAD(KEK, X25519 private key)
//!   dek_ephemeral_pub  32   ECIES ephemeral public key
//!   wrapped_dek         4+n AEAD(ECIES wrap key, DEK)
//!   rp_id               4+n UTF-8, empty unless kind = passkey-prf
//!   credential_id       4+n bytes, empty unless kind = passkey-prf
//!   label               4+n UTF-8, may be empty
//!   credential_pubkey   4+n bytes, empty unless kind = passkey-prf
//! ```
//!
//! # Why every header byte is the body's AAD
//!
//! DR-0034 §1a requires that rewriting the header be detected rather than
//! tolerated. Authenticating the header's exact serialized bytes (not a
//! selection of fields) means swapping a slot, winding `dek_generation` back,
//! or downgrading `aead_alg_id` to something weaker all surface as a
//! decryption failure — including any field added by a later format version,
//! which is covered automatically because the AAD is defined by position and
//! length rather than by an enumeration someone must remember to extend.
//!
//! The two blobs *inside* a slot cannot use the whole header as their AAD
//! (they are part of it — the definition would be circular). They use
//! [`Slot::binding_aad`] instead, which pins each blob to the vault, the
//! format version, and the slot's own id, kind and public key.
//!
//! # Byte-level stability
//!
//! Serialization is deterministic: fixed field order, fixed widths,
//! big-endian, no padding. Two encodes of the same header produce identical
//! bytes, which the AAD contract depends on. `tests/format_pin.rs` pins the
//! magic, version and algorithm ids at their byte offsets so a change that
//! would make existing vaults unreadable cannot pass silently.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{NONCE_LEN, PUBKEY_LEN, TAG_LEN, WrappedDek};
use crate::error::VaultError;

/// Magic prefix identifying a cache-warden vault file.
pub(crate) const MAGIC: [u8; 8] = *b"CWVAULT\0";

/// The format version this build writes.
///
/// Monotonically increasing. Reading a file that declares a **higher** version
/// is refused (DR-0034 §1a): this build would drop the fields it does not know
/// about on the next write, silently deleting authorization records.
pub const FORMAT_VERSION: u32 = 2;

/// The oldest format version this build can still read.
///
/// Equal to [`FORMAT_VERSION`]: version 1 is not read. It existed only before
/// the vault shipped, and the one thing that could have been in a version 1
/// file — a recovery slot — could not have been carrying anything, because
/// nothing had been released to write entries with. Carrying compatibility
/// code for a file that does not exist would be a permanent cost against a
/// hypothetical; a file declaring version 1 is refused with the same clear
/// message any unsupported version gets.
pub const MIN_SUPPORTED_VERSION: u32 = 2;

/// Length of the salt stored per slot.
pub(crate) const SALT_LEN: usize = 32;

/// Length of a vault id / slot id.
pub(crate) const ID_LEN: usize = 16;

/// Upper bound on slots per vault. A vault is a set of a person's devices plus
/// a recovery code; four digits of headroom is generous. The bound exists so a
/// crafted `slot_count` read off disk cannot drive an enormous allocation
/// before anything has been authenticated.
const MAX_SLOTS: u32 = 1024;

/// Upper bound on any length-prefixed field inside a slot (labels, RP ids,
/// credential ids, wrapped blobs). All are small by construction.
const MAX_SLOT_FIELD_LEN: u64 = 64 * 1024;

/// Upper bound on the sealed body. The vault holds credentials, not files.
const MAX_BODY_LEN: u64 = 64 * 1024 * 1024;

/// Upper bound on a whole vault file, used to reject an implausibly large file
/// by its metadata *before* it is read into memory. Generous enough for the
/// largest structurally legal vault: [`MAX_BODY_LEN`] plus room for
/// [`MAX_SLOTS`] slots at [`MAX_SLOT_FIELD_LEN`]-bounded sizes.
pub(crate) const MAX_FILE_LEN: u64 = MAX_BODY_LEN + 16 * 1024 * 1024;

/// A vault's permanent identity, generated once at initialization (DR-0034
/// §1a). Lets a caller detect that the file at a given path is a *different*
/// vault — a restored backup, or a development vault dropped into the
/// production path.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct VaultId([u8; ID_LEN]);

/// A slot's identity, generated when the slot is created.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct SlotId([u8; ID_LEN]);

macro_rules! impl_id {
    ($t:ty, $name:literal) => {
        impl $t {
            /// A fresh random id.
            pub(crate) fn random() -> Self {
                let mut b = [0u8; ID_LEN];
                crate::crypto::fill_random(&mut b);
                Self(b)
            }

            /// Wrap raw bytes as an id.
            pub(crate) fn from_bytes(b: [u8; ID_LEN]) -> Self {
                Self(b)
            }

            /// The raw id bytes, as they appear in the header and in every
            /// HKDF `info` string that binds to this id.
            pub fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }
        }

        /// Lowercase hex — the form used in file names, log lines and CLI
        /// output. Ids are public metadata (DR-0034 §7), so there is nothing
        /// to redact.
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let _ = $name;
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

impl_id!(VaultId, "vault");
impl_id!(SlotId, "slot");

/// The AEAD in use. `v1` defines exactly one (DR-0034 §1a); the field exists
/// so a future algorithm can be introduced without a new magic, and so that
/// downgrading it to a weaker algorithm is caught by the header AAD.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum AeadAlg {
    /// XChaCha20-Poly1305, id `1`.
    XChaCha20Poly1305,
}

/// The KDF in use. Same reasoning as [`AeadAlg`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum KdfAlg {
    /// HKDF-SHA256, id `1`.
    HkdfSha256,
}

impl AeadAlg {
    pub(crate) fn id(self) -> u16 {
        match self {
            AeadAlg::XChaCha20Poly1305 => 1,
        }
    }

    fn from_id(id: u16) -> Result<Self, VaultError> {
        match id {
            1 => Ok(AeadAlg::XChaCha20Poly1305),
            _ => Err(VaultError::UnsupportedAlgorithm {
                field: "aead_alg_id",
                id,
            }),
        }
    }
}

impl KdfAlg {
    pub(crate) fn id(self) -> u16 {
        match self {
            KdfAlg::HkdfSha256 => 1,
        }
    }

    fn from_id(id: u16) -> Result<Self, VaultError> {
        match id {
            1 => Ok(KdfAlg::HkdfSha256),
            _ => Err(VaultError::UnsupportedAlgorithm {
                field: "kdf_alg_id",
                id,
            }),
        }
    }
}

/// What kind of credential opens a slot (DR-0034 §1b).
///
/// The wire representation is an id rather than a bitfield or a string so new
/// kinds can be added without disturbing existing files. An unrecognized id is
/// an error, never a skipped slot: a slot this build cannot describe is still
/// a recipient that can decrypt the vault, and omitting it from
/// [`crate::LockedVault::slots`] would make "who can open this vault" a lie.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SlotKind {
    /// Opened by a passkey PRF output (DR-0034 §2 / §10). The format defines
    /// it; the ceremony that produces the PRF output arrives in a later phase.
    PasskeyPrf,
    /// Opened by a recovery code (DR-0034 §9). Mandatory at initialization.
    Recovery,
}

impl SlotKind {
    pub(crate) fn id(self) -> u16 {
        match self {
            SlotKind::PasskeyPrf => 1,
            SlotKind::Recovery => 2,
        }
    }

    fn from_id(id: u16) -> Result<Self, VaultError> {
        match id {
            1 => Ok(SlotKind::PasskeyPrf),
            2 => Ok(SlotKind::Recovery),
            _ => Err(VaultError::UnknownSlotKind { id }),
        }
    }
}

/// One recipient of the vault's DEK.
///
/// Everything here is plaintext metadata except the two wrapped blobs. That
/// split is deliberate and is the privacy line DR-0034 §7 draws: someone who
/// reads the file learns *which credential opens it* (public key, RP id,
/// credential id, label) but not *what is inside it* (entry names, values,
/// guards and owners are all in the sealed body).
///
/// `Clone` so a mutation can assemble the slot set it intends to write, commit
/// it, and only then install it (see [`crate::UnlockedVault`]'s commit-then-
/// install note). A clone copies public metadata and two already-encrypted
/// blobs; no plaintext key material is duplicated.
#[derive(Clone)]
pub struct Slot {
    id: SlotId,
    kind: SlotKind,
    pubkey: [u8; PUBKEY_LEN],
    salt: [u8; SALT_LEN],
    created_at_epoch_ms: u64,
    /// `AEAD(KEK, X25519 private key)` — see [`Slot::binding_aad`].
    wrapped_privkey: Vec<u8>,
    /// The DEK wrapped to [`Slot::pubkey`]. Replaced on every DEK rotation,
    /// using the public key alone (DR-0034 §1c).
    wrapped_dek: WrappedDek,
    rp_id: String,
    credential_id: Vec<u8>,
    label: String,
    /// The WebAuthn credential's public key, in this build's stored encoding
    /// (`cache_warden_webauthn::CredentialPublicKey::to_stored_bytes`). Empty
    /// for a recovery slot, and for any slot read from a version 1 file —
    /// which can only be a recovery slot, since passkey slots could not be
    /// created before this field existed.
    ///
    /// Public metadata by the same reasoning as `credential_id`: it says which
    /// credential opens the vault, never what is inside it (DR-0034 §7). It
    /// has to be here rather than in the sealed body because it is needed to
    /// verify the assertion that opens the body.
    credential_public_key: Vec<u8>,
}

impl Slot {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: SlotId,
        kind: SlotKind,
        pubkey: [u8; PUBKEY_LEN],
        salt: [u8; SALT_LEN],
        wrapped_privkey: Vec<u8>,
        wrapped_dek: WrappedDek,
        rp_id: String,
        credential_id: Vec<u8>,
        credential_public_key: Vec<u8>,
        label: String,
    ) -> Self {
        Self {
            id,
            kind,
            pubkey,
            salt,
            created_at_epoch_ms: now_epoch_ms(),
            wrapped_privkey,
            wrapped_dek,
            rp_id,
            credential_id,
            label,
            credential_public_key,
        }
    }

    /// This slot's id.
    pub fn id(&self) -> SlotId {
        self.id
    }

    /// What kind of credential opens this slot.
    pub fn kind(&self) -> SlotKind {
        self.kind
    }

    /// The user-supplied label, empty if none was given.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The WebAuthn RP id this slot was registered against, empty for a
    /// recovery slot. Recorded per slot so changing the configured RP id never
    /// orphans existing slots (DR-0034 §10).
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The WebAuthn credential id, empty for a recovery slot.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The WebAuthn credential's public key, empty for a recovery slot.
    pub fn credential_public_key(&self) -> &[u8] {
        &self.credential_public_key
    }

    /// The salt this slot's ceremony must evaluate to reproduce its key
    /// material (DR-0034 §2).
    ///
    /// Public by design — it is one input to a derivation whose secret input
    /// is the authenticator's PRF output, and it has to be public because the
    /// page has to be told what to evaluate before anything is unlocked.
    pub fn prf_salt(&self) -> &[u8] {
        &self.salt
    }

    /// When this slot was created, in milliseconds since the Unix epoch.
    pub fn created_at_epoch_ms(&self) -> u64 {
        self.created_at_epoch_ms
    }

    /// This slot's X25519 public key — the whole input needed to re-wrap the
    /// DEK for it (DR-0034 §1b).
    pub(crate) fn pubkey(&self) -> &[u8; PUBKEY_LEN] {
        &self.pubkey
    }

    pub(crate) fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub(crate) fn wrapped_privkey(&self) -> &[u8] {
        &self.wrapped_privkey
    }

    pub(crate) fn wrapped_dek(&self) -> &WrappedDek {
        &self.wrapped_dek
    }

    /// Install a freshly wrapped DEK after a rotation.
    pub(crate) fn set_wrapped_dek(&mut self, wrapped: WrappedDek) {
        self.wrapped_dek = wrapped;
    }

    /// Whether this slot names a development-only WebAuthn RP.
    ///
    /// A vault is opened by *any* of its slots, so the weakest slot sets the
    /// vault's strength (DR-0034 §7). A slot registered against `localhost`
    /// was created over a connection with no meaningful origin authentication,
    /// and its presence in a production vault is the failure this predicate
    /// exists to surface.
    pub fn is_dev_rp(&self) -> bool {
        if self.kind != SlotKind::PasskeyPrf {
            return false;
        }
        // Only domain forms are checked: a WebAuthn RP ID is a registrable
        // domain suffix, and an IP literal cannot be one, so a slot can never
        // carry `127.0.0.1` or `::1` as its RP ID in the first place.
        let host = self.rp_id.to_ascii_lowercase();
        host == "localhost" || host.ends_with(".localhost")
    }

    /// The AAD for this slot's two wrapped blobs.
    ///
    /// Binds each blob to the vault, the format version, and the slot's own
    /// id, kind and public key, so a blob lifted from one slot and pasted into
    /// another (or into a re-labelled slot) fails to decrypt. The header
    /// cannot serve as this AAD because these blobs are part of it.
    pub(crate) fn binding_aad(
        vault_id: VaultId,
        format_version: u32,
        slot_id: SlotId,
        kind: SlotKind,
        pubkey: &[u8; PUBKEY_LEN],
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(ID_LEN + 4 + ID_LEN + 2 + PUBKEY_LEN);
        aad.extend_from_slice(vault_id.as_bytes());
        aad.extend_from_slice(&format_version.to_be_bytes());
        aad.extend_from_slice(slot_id.as_bytes());
        aad.extend_from_slice(&kind.id().to_be_bytes());
        aad.extend_from_slice(pubkey);
        aad
    }

    /// [`Slot::binding_aad`] for this slot.
    pub(crate) fn own_binding_aad(&self, vault_id: VaultId, format_version: u32) -> Vec<u8> {
        Slot::binding_aad(vault_id, format_version, self.id, self.kind, &self.pubkey)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.kind.id().to_be_bytes());
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.created_at_epoch_ms.to_be_bytes());
        put_blob(out, &self.wrapped_privkey);
        out.extend_from_slice(&self.wrapped_dek.ephemeral_pub);
        put_blob(out, &self.wrapped_dek.sealed);
        put_blob(out, self.rp_id.as_bytes());
        put_blob(out, &self.credential_id);
        put_blob(out, self.label.as_bytes());
        put_blob(out, &self.credential_public_key);
    }

    fn decode(cursor: &mut &[u8]) -> Result<Self, VaultError> {
        let id = SlotId::from_bytes(take_array::<ID_LEN>(cursor)?);
        let kind = SlotKind::from_id(take_u16(cursor)?)?;
        let pubkey = take_array::<PUBKEY_LEN>(cursor)?;
        let salt = take_array::<SALT_LEN>(cursor)?;
        let created_at_epoch_ms = take_u64(cursor)?;
        let wrapped_privkey = take_blob(cursor, "wrapped_privkey")?.to_vec();
        let ephemeral_pub = take_array::<PUBKEY_LEN>(cursor)?;
        let sealed = take_blob(cursor, "wrapped_dek")?.to_vec();
        let rp_id = take_utf8(cursor, "rp_id")?;
        let credential_id = take_blob(cursor, "credential_id")?.to_vec();
        let label = take_utf8(cursor, "label")?;
        let credential_public_key = take_blob(cursor, "credential_public_key")?.to_vec();

        Ok(Self {
            id,
            kind,
            pubkey,
            salt,
            created_at_epoch_ms,
            wrapped_privkey,
            wrapped_dek: WrappedDek {
                ephemeral_pub,
                sealed,
            },
            rp_id,
            credential_id,
            label,
            credential_public_key,
        })
    }
}

/// The plaintext header plus the sealed body, exactly as they sit on disk.
pub(crate) struct VaultFile {
    pub(crate) format_version: u32,
    pub(crate) vault_id: VaultId,
    pub(crate) dek_generation: u64,
    pub(crate) aead_alg: AeadAlg,
    pub(crate) kdf_alg: KdfAlg,
    pub(crate) slots: Vec<Slot>,
    /// `nonce ‖ AEAD(DEK, entries, aad = header)`.
    pub(crate) sealed_body: Vec<u8>,
}

/// The header fields, borrowed.
///
/// Exists so an open vault can encode its header (to seal a body against it)
/// without moving its slots into a [`VaultFile`] it does not otherwise need.
/// [`VaultFile::encode_header`] delegates here, which keeps one definition of
/// the byte layout — two would eventually disagree, and the AAD contract makes
/// any disagreement a decryption failure rather than a cosmetic one.
pub(crate) struct HeaderView<'a> {
    pub(crate) format_version: u32,
    pub(crate) vault_id: VaultId,
    pub(crate) dek_generation: u64,
    pub(crate) aead_alg: AeadAlg,
    pub(crate) kdf_alg: KdfAlg,
    pub(crate) slots: &'a [Slot],
}

impl HeaderView<'_> {
    /// The exact bytes that authenticate the body.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.format_version.to_be_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.dek_generation.to_be_bytes());
        out.extend_from_slice(&self.aead_alg.id().to_be_bytes());
        out.extend_from_slice(&self.kdf_alg.id().to_be_bytes());
        out.extend_from_slice(&(self.slots.len() as u32).to_be_bytes());
        for slot in self.slots {
            slot.encode_into(&mut out);
        }
        out
    }
}

/// Append the body framing to already-encoded header bytes, yielding the whole
/// file.
pub(crate) fn encode_file(header: Vec<u8>, sealed_body: &[u8]) -> Vec<u8> {
    let mut out = header;
    out.extend_from_slice(&(sealed_body.len() as u64).to_be_bytes());
    out.extend_from_slice(sealed_body);
    out
}

impl VaultFile {
    /// Serialize the header only — the exact bytes that authenticate the body.
    ///
    /// Production writes go through [`HeaderView`] instead (an open vault owns
    /// its slots and does not hand them to a `VaultFile`); this exists so the
    /// round-trip tests can check that a decoded file re-encodes identically.
    #[cfg(test)]
    pub(crate) fn encode_header(&self) -> Vec<u8> {
        HeaderView {
            format_version: self.format_version,
            vault_id: self.vault_id,
            dek_generation: self.dek_generation,
            aead_alg: self.aead_alg,
            kdf_alg: self.kdf_alg,
            slots: &self.slots,
        }
        .encode()
    }

    /// Serialize the whole file.
    #[cfg(test)]
    pub(crate) fn encode(&self) -> Vec<u8> {
        encode_file(self.encode_header(), &self.sealed_body)
    }

    /// Parse a vault file, returning it alongside the header bytes that must
    /// be passed as the body's AAD.
    ///
    /// The AAD is returned as the *observed* header slice rather than being
    /// re-encoded from the parsed struct. Re-encoding would mask a mismatch
    /// between what was written and what this build would write, which is
    /// exactly the class of corruption the AAD is supposed to catch.
    pub(crate) fn decode(bytes: &[u8]) -> Result<(Self, Vec<u8>), VaultError> {
        let mut cursor = bytes;

        let magic = take_array::<8>(&mut cursor)?;
        if magic != MAGIC {
            return Err(VaultError::BadMagic);
        }

        let format_version = take_u32(&mut cursor)?;
        if !(MIN_SUPPORTED_VERSION..=FORMAT_VERSION).contains(&format_version) {
            return Err(VaultError::UnsupportedVersion {
                got: format_version,
            });
        }

        let vault_id = VaultId::from_bytes(take_array::<ID_LEN>(&mut cursor)?);
        let dek_generation = take_u64(&mut cursor)?;
        let aead_alg = AeadAlg::from_id(take_u16(&mut cursor)?)?;
        let kdf_alg = KdfAlg::from_id(take_u16(&mut cursor)?)?;

        let slot_count = take_u32(&mut cursor)?;
        if slot_count == 0 {
            return Err(VaultError::Malformed {
                reason: "a vault with no slots can never be opened",
            });
        }
        if slot_count > MAX_SLOTS {
            return Err(VaultError::FieldTooLarge {
                field: "slot_count",
                len: u64::from(slot_count),
            });
        }

        let mut slots = Vec::with_capacity(slot_count as usize);
        for _ in 0..slot_count {
            slots.push(Slot::decode(&mut cursor)?);
        }
        // Slot ids key every HKDF binding; duplicates would make "which slot
        // is this" ambiguous and let one slot's blobs authenticate under
        // another's identity.
        for (i, slot) in slots.iter().enumerate() {
            if slots[..i].iter().any(|s| s.id == slot.id) {
                return Err(VaultError::Malformed {
                    reason: "two slots share one slot_id",
                });
            }
        }

        // Everything consumed so far is the header, and therefore the AAD.
        let header_len = bytes.len() - cursor.len();
        let aad = bytes[..header_len].to_vec();

        let body_len = take_u64(&mut cursor)?;
        if body_len > MAX_BODY_LEN {
            return Err(VaultError::FieldTooLarge {
                field: "body_len",
                len: body_len,
            });
        }
        let body_len = usize::try_from(body_len).map_err(|_| VaultError::FieldTooLarge {
            field: "body_len",
            len: body_len,
        })?;
        if body_len < NONCE_LEN + TAG_LEN {
            return Err(VaultError::Malformed {
                reason: "body is too short to hold a nonce and an authentication tag",
            });
        }
        let sealed_body = take(&mut cursor, body_len)?.to_vec();
        // The body is the last thing in the file. Anything after it is either
        // corruption or an attempt to smuggle data past a reader that stops at
        // `body_len`; neither is something to read and ignore.
        if !cursor.is_empty() {
            return Err(VaultError::Malformed {
                reason: "trailing bytes after the vault body",
            });
        }

        Ok((
            Self {
                format_version,
                vault_id,
                dek_generation,
                aead_alg,
                kdf_alg,
                slots,
                sealed_body,
            },
            aad,
        ))
    }
}

/// The current wall clock in milliseconds since the Unix epoch, used for slot
/// `created_at`. Clamps to 0 rather than failing if the clock predates the
/// epoch — a nonsense timestamp on a display-only field is not worth failing a
/// slot creation over.
pub(crate) fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8], VaultError> {
    if cursor.len() < n {
        return Err(VaultError::Truncated);
    }
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    Ok(head)
}

fn take_array<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], VaultError> {
    Ok(take(cursor, N)?.try_into().expect("took exactly N bytes"))
}

fn take_u16(cursor: &mut &[u8]) -> Result<u16, VaultError> {
    Ok(u16::from_be_bytes(take_array::<2>(cursor)?))
}

fn take_u32(cursor: &mut &[u8]) -> Result<u32, VaultError> {
    Ok(u32::from_be_bytes(take_array::<4>(cursor)?))
}

fn take_u64(cursor: &mut &[u8]) -> Result<u64, VaultError> {
    Ok(u64::from_be_bytes(take_array::<8>(cursor)?))
}

fn take_blob<'a>(cursor: &mut &'a [u8], field: &'static str) -> Result<&'a [u8], VaultError> {
    let len = u64::from(take_u32(cursor)?);
    if len > MAX_SLOT_FIELD_LEN {
        return Err(VaultError::FieldTooLarge { field, len });
    }
    take(cursor, len as usize)
}

fn take_utf8(cursor: &mut &[u8], field: &'static str) -> Result<String, VaultError> {
    let bytes = take_blob(cursor, field)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| VaultError::Malformed {
        reason: "a text field is not valid UTF-8",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_slot(kind: SlotKind, rp_id: &str) -> Slot {
        Slot::new(
            SlotId::from_bytes([1u8; ID_LEN]),
            kind,
            [2u8; PUBKEY_LEN],
            [3u8; SALT_LEN],
            vec![4u8; NONCE_LEN + TAG_LEN + 32],
            WrappedDek {
                ephemeral_pub: [5u8; PUBKEY_LEN],
                sealed: vec![6u8; NONCE_LEN + TAG_LEN + 32],
            },
            rp_id.to_string(),
            vec![7, 8, 9],
            vec![1, 0xAB, 0xCD],
            "laptop".to_string(),
        )
    }

    fn sample_file() -> VaultFile {
        VaultFile {
            format_version: FORMAT_VERSION,
            vault_id: VaultId::from_bytes([0xAB; ID_LEN]),
            dek_generation: 3,
            aead_alg: AeadAlg::XChaCha20Poly1305,
            kdf_alg: KdfAlg::HkdfSha256,
            slots: vec![sample_slot(SlotKind::Recovery, "")],
            sealed_body: vec![0u8; NONCE_LEN + TAG_LEN + 10],
        }
    }

    #[test]
    fn file_round_trips_through_encode_and_decode() {
        let file = sample_file();
        let bytes = file.encode();
        let (back, aad) = VaultFile::decode(&bytes).expect("decodes");
        assert_eq!(back.format_version, FORMAT_VERSION);
        assert_eq!(back.vault_id, file.vault_id);
        assert_eq!(back.dek_generation, 3);
        assert_eq!(back.aead_alg, AeadAlg::XChaCha20Poly1305);
        assert_eq!(back.kdf_alg, KdfAlg::HkdfSha256);
        assert_eq!(back.slots.len(), 1);
        assert_eq!(back.slots[0].label(), "laptop");
        assert_eq!(back.slots[0].credential_id(), &[7, 8, 9]);
        assert_eq!(back.sealed_body, file.sealed_body);
        // The AAD is the header prefix, and re-encoding reproduces it exactly
        // — the determinism the AAD contract rests on.
        assert_eq!(aad, file.encode_header());
        assert_eq!(bytes[..aad.len()], aad[..]);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = sample_file().encode();
        bytes[0] = b'X';
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::BadMagic)
        ));
    }

    /// DR-0034 §1a: a file from a newer build must be refused, not read
    /// leniently. Reading it would mean rewriting it later without the fields
    /// this build cannot represent.
    #[test]
    fn decode_refuses_a_newer_format_version() {
        let mut bytes = sample_file().encode();
        bytes[8..12].copy_from_slice(&(FORMAT_VERSION + 1).to_be_bytes());
        match VaultFile::decode(&bytes) {
            Err(VaultError::UnsupportedVersion { got }) => assert_eq!(got, FORMAT_VERSION + 1),
            other => panic!(
                "expected UnsupportedVersion, got {other:?}",
                other = other.map(|_| ()).err()
            ),
        }
    }

    #[test]
    fn decode_rejects_an_unknown_aead_algorithm() {
        let file = sample_file();
        let mut bytes = file.encode();
        // aead_alg_id sits after magic(8) + version(4) + vault_id(16) + generation(8).
        let off = 8 + 4 + ID_LEN + 8;
        bytes[off..off + 2].copy_from_slice(&99u16.to_be_bytes());
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::UnsupportedAlgorithm {
                field: "aead_alg_id",
                id: 99
            })
        ));
    }

    #[test]
    fn decode_rejects_an_unknown_kdf_algorithm() {
        let mut bytes = sample_file().encode();
        let off = 8 + 4 + ID_LEN + 8 + 2;
        bytes[off..off + 2].copy_from_slice(&77u16.to_be_bytes());
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::UnsupportedAlgorithm {
                field: "kdf_alg_id",
                id: 77
            })
        ));
    }

    #[test]
    fn decode_rejects_an_unknown_slot_kind() {
        let mut bytes = sample_file().encode();
        // The first slot's kind follows the 44-byte header prefix and the
        // 16-byte slot id.
        let off = 8 + 4 + ID_LEN + 8 + 2 + 2 + 4 + ID_LEN;
        bytes[off..off + 2].copy_from_slice(&42u16.to_be_bytes());
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::UnknownSlotKind { id: 42 })
        ));
    }

    #[test]
    fn decode_rejects_a_vault_with_no_slots() {
        let mut file = sample_file();
        file.slots.clear();
        assert!(matches!(
            VaultFile::decode(&file.encode()),
            Err(VaultError::Malformed { .. })
        ));
    }

    #[test]
    fn decode_rejects_duplicate_slot_ids() {
        let mut file = sample_file();
        file.slots.push(sample_slot(SlotKind::Recovery, ""));
        assert!(matches!(
            VaultFile::decode(&file.encode()),
            Err(VaultError::Malformed { .. })
        ));
    }

    #[test]
    fn decode_rejects_an_implausible_slot_count() {
        let mut bytes = sample_file().encode();
        let off = 8 + 4 + ID_LEN + 8 + 2 + 2;
        bytes[off..off + 4].copy_from_slice(&(MAX_SLOTS + 1).to_be_bytes());
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::FieldTooLarge {
                field: "slot_count",
                ..
            })
        ));
    }

    /// Every truncation point must produce a clean `Truncated`, never a panic
    /// from slicing past the end. Walking every prefix is cheap here and
    /// covers offsets no hand-picked case would think to try.
    #[test]
    fn every_truncated_prefix_errors_instead_of_panicking() {
        let bytes = sample_file().encode();
        for cut in 0..bytes.len() {
            assert!(
                VaultFile::decode(&bytes[..cut]).is_err(),
                "a {cut}-byte prefix must not decode"
            );
        }
    }

    #[test]
    fn decode_rejects_an_oversized_blob_length() {
        let mut bytes = sample_file().encode();
        // The first slot's wrapped_privkey length prefix.
        let off = 8 + 4 + ID_LEN + 8 + 2 + 2 + 4 + ID_LEN + 2 + PUBKEY_LEN + SALT_LEN + 8;
        bytes[off..off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::FieldTooLarge { .. })
        ));
    }

    #[test]
    fn decode_rejects_a_non_utf8_text_field() {
        let mut file = sample_file();
        // Build a slot whose label bytes are invalid UTF-8 by patching the
        // encoded form. The label is followed by the credential public key
        // blob, so skip back over that blob and its length prefix too.
        let mut bytes = file.encode();
        let slot = file.slots.pop().unwrap();
        let label_len = slot.label().len();
        let credential_key_field = 4 + slot.credential_public_key().len();
        let body_tail = 8 + file.sealed_body.len();
        let label_start = bytes.len() - body_tail - credential_key_field - label_len;
        bytes[label_start] = 0xFF;
        assert!(matches!(
            VaultFile::decode(&bytes),
            Err(VaultError::Malformed { .. })
        ));
    }

    #[test]
    fn ids_display_as_lowercase_hex() {
        let id = VaultId::from_bytes([0x0a, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(id.to_string(), "0aff0000000000000000000000000001");
    }

    #[test]
    fn only_passkey_slots_registered_on_localhost_count_as_dev() {
        assert!(sample_slot(SlotKind::PasskeyPrf, "localhost").is_dev_rp());
        assert!(sample_slot(SlotKind::PasskeyPrf, "LOCALHOST").is_dev_rp());
        assert!(sample_slot(SlotKind::PasskeyPrf, "cw.localhost").is_dev_rp());
        assert!(!sample_slot(SlotKind::PasskeyPrf, "vault.example.com").is_dev_rp());
        // A WebAuthn RP ID is a registrable domain suffix, so an IP literal
        // cannot appear as one; the predicate does not pretend to check for
        // values the format cannot hold.
        assert!(!sample_slot(SlotKind::PasskeyPrf, "127.0.0.1").is_dev_rp());
        // A hostname that merely contains "localhost" is a real, resolvable
        // name and must not be flagged.
        assert!(!sample_slot(SlotKind::PasskeyPrf, "localhost.example.com").is_dev_rp());
        // A recovery slot has no RP at all.
        assert!(!sample_slot(SlotKind::Recovery, "").is_dev_rp());
    }
}
