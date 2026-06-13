//! Local signing adapter.
//!
//! This module is a stateless adapter: it accepts a PEM-encoded private key
//! string, parses it into a transient algorithm-specific representation just
//! long enough to produce the SignResponse, then drops the key material. The
//! caller (the cache-warden core `Store`) owns key persistence and lends the
//! PEM bytes for the duration of one [`sign`] call only; this module owns
//! nothing and keeps no state between calls.
//!
//! Ported from authsock-warden `src/keystore/signer.rs`. The upstream `tracing`
//! diagnostics are dropped to keep this crate dependency-minimal (cache-warden
//! style); the one operationally useful warning (legacy ssh-rsa / SHA-1) is
//! emitted once per process via `eprintln!`.
//!
//! Design rationale: an earlier authsock-warden implementation kept
//! `ssh_key::PrivateKey` alive and converted to `rsa::RsaPrivateKey` at sign
//! time. That round-trip conversion failed for some PKCS#8 RSA keys
//! ("RSA key conversion failed: cryptographic error"). Keeping signing transient
//! and storing each algorithm in its native crate's type end-to-end avoids
//! intermediate conversions entirely.

use crate::error::{Error, Result};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::signature::SignatureEncoding;
use ssh_encoding::Encode;
use ssh_key::PrivateKey;
use ssh_key::private::Ed25519PrivateKey;
use ssh_key::public::KeyData;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// SSH agent protocol flags for RSA hash algorithm selection.
///   SSH_AGENT_RSA_SHA2_256 = 0x02
///   SSH_AGENT_RSA_SHA2_512 = 0x04
/// When both bits are zero, ssh-rsa (SHA-1) is used (legacy OpenSSH servers).
const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Sign `data` with the PEM-encoded private key and return an SSH wire
/// signature blob (`string(algorithm) + string(signature)`).
///
/// The key is parsed, used to sign, and dropped within this call. The SSH agent
/// SIGN_REQUEST / SIGN_RESPONSE wire framing lives in `message`; this module is
/// the pure crypto adapter. `pem` is borrowed for the call's duration only (the
/// caller exposes it from a `SecretBytes` under the core lock).
pub fn sign(pem: &str, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let material = KeyMaterial::from_pem(pem)?;
    material.sign(data, flags)
}

/// Derive the wire-format public-key blob (and OpenSSH comment, if any) from a
/// private-key PEM.
///
/// Reuses the same PEM parsing as [`sign`] — including the lenient 1Password
/// Ed25519 path — so a key the signer can sign with is always enumerable. The
/// returned blob is the exact `string(keytype) + key fields` framing that an
/// SSH client sends back in a SIGN_REQUEST (and that `PublicKey::from_bytes`
/// round-trips). The comment is `None` for PKCS#8 keys (which carry none).
///
/// `pem` is borrowed for the call only; no key material is retained.
pub fn public_key_blob_from_pem(pem: &str) -> Result<(Vec<u8>, Option<String>)> {
    let material = KeyMaterial::from_pem(pem)?;
    let key_data = material.public_key_data()?;
    let mut blob = Vec::new();
    Encode::encode(&key_data, &mut blob)
        .map_err(|_| Error::KeyStore("failed to encode public key blob".to_string()))?;
    // OpenSSH PEMs may carry a comment; PKCS#8 never does. Only the OpenSSH
    // branch can recover it, so derive it separately and cheaply here.
    let comment = openssh_comment(pem);
    Ok((blob, comment))
}

/// Recover the comment from an OpenSSH private-key PEM, if present and non-empty.
fn openssh_comment(pem: &str) -> Option<String> {
    if pem_kind(pem) != PemKind::OpenSsh {
        return None;
    }
    let key = PrivateKey::from_openssh(pem).ok()?;
    let c = key.comment();
    if c.is_empty() {
        None
    } else {
        Some(c.to_string())
    }
}

/// Encode an SSH signature blob: `string(algorithm) + string(signature)`.
///
/// We build this manually instead of going through `ssh_key::Signature` because
/// ssh-key 0.6 rejects `Algorithm::Rsa { hash: None }` (legacy ssh-rsa / SHA-1)
/// in `Signature::new`. The wire format is identical regardless of who builds it.
fn encode_signature_blob(algorithm_name: &str, sig_bytes: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(8 + algorithm_name.len() + sig_bytes.len());
    blob.extend_from_slice(&(algorithm_name.len() as u32).to_be_bytes());
    blob.extend_from_slice(algorithm_name.as_bytes());
    blob.extend_from_slice(&(sig_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(sig_bytes);
    blob
}

/// PEM block flavor recognized by `from_pem`.
///
/// Header detection is line-based and exact-match: substring matching
/// (`pem.contains("BEGIN PRIVATE KEY")`) would conflate the unencrypted PKCS#8
/// header with `BEGIN ENCRYPTED PRIVATE KEY` and is brittle.
#[derive(Debug, PartialEq, Eq)]
enum PemKind {
    OpenSsh,
    Pkcs8,
    EncryptedPkcs8,
    /// SEC1 `BEGIN EC PRIVATE KEY` (RFC 5915). Emitted by `openssl ec` and older
    /// tooling for ECDSA keys; carries a `namedCurve` OID inside the DER.
    Sec1Ec,
    Unknown,
}

fn pem_kind(pem: &str) -> PemKind {
    for line in pem.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("-----BEGIN ") {
            continue;
        }
        return match trimmed {
            "-----BEGIN OPENSSH PRIVATE KEY-----" => PemKind::OpenSsh,
            "-----BEGIN PRIVATE KEY-----" => PemKind::Pkcs8,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----" => PemKind::EncryptedPkcs8,
            "-----BEGIN EC PRIVATE KEY-----" => PemKind::Sec1Ec,
            _ => PemKind::Unknown,
        };
    }
    PemKind::Unknown
}

/// Algorithm-specific private key material.
///
/// Each variant holds the native signing-crate type so the sign path never
/// touches an intermediate representation. Both variants are boxed to keep the
/// enum a single pointer wide; `ed25519_dalek::SigningKey` holds an expanded
/// secret + verifying key (>100 bytes) and `rsa::RsaPrivateKey` carries
/// multi-`BigUint` state plus precomputed CRT parameters, so unboxed they would
/// force every `Result<KeyMaterial>` move to copy the larger variant.
enum KeyMaterial {
    Ed25519(Box<Ed25519SigningKey>),
    Rsa(Box<rsa::RsaPrivateKey>),
    /// ECDSA over a NIST prime curve. Each variant holds the curve-specific
    /// RustCrypto `SigningKey`, whose `Signer` impl already binds the
    /// SSH-mandated hash (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512). Boxed
    /// for the same single-pointer-wide reason as the other variants.
    Ecdsa(Box<EcdsaKey>),
}

/// Curve-tagged ECDSA signing key.
///
/// We keep the native per-curve `SigningKey` end-to-end (no intermediate
/// representation at sign time), matching the Ed25519 / RSA design rationale.
/// The SSH algorithm name and the (r,s) field width follow directly from the
/// variant.
enum EcdsaKey {
    NistP256(p256::ecdsa::SigningKey),
    NistP384(p384::ecdsa::SigningKey),
    NistP521(p521::ecdsa::SigningKey),
}

impl KeyMaterial {
    /// Parse a PEM string into key material.
    ///
    /// Supports:
    /// - OpenSSH format ("BEGIN OPENSSH PRIVATE KEY") for Ed25519 / RSA
    /// - PKCS#8 format ("BEGIN PRIVATE KEY") for Ed25519 / RSA (1Password)
    fn from_pem(pem: &str) -> Result<Self> {
        match pem_kind(pem) {
            PemKind::OpenSsh => {
                match PrivateKey::from_openssh(pem) {
                    Ok(key) => Self::from_openssh_private_key(&key),
                    // ssh-key 0.6 fails (`Encoding(Length)`) on OpenSSH ECDSA
                    // keys whose private scalar mpint is shorter than the curve's
                    // fixed field width — notably P-521 keys whose top byte is
                    // zero (~1/256 chance), where OpenSSH emits a 65-byte mpint
                    // but ssh-key demands 66. Fall back to a hand-rolled OpenSSH
                    // ECDSA decode that reads the scalar as a real mpint. This is
                    // ECDSA-specific; non-ECDSA failures are real errors.
                    Err(_) => parse_openssh_ecdsa_fallback(pem)
                        .map(|ec| KeyMaterial::Ecdsa(Box::new(ec)))
                        .ok_or_else(|| Error::KeyStore("Invalid OpenSSH private key".to_string())),
                }
            }
            PemKind::Pkcs8 => Self::from_pkcs8(pem),
            PemKind::Sec1Ec => Self::from_sec1_ec(pem),
            PemKind::EncryptedPkcs8 => Err(Error::KeyStore(
                "Encrypted PKCS#8 private keys are not supported".to_string(),
            )),
            PemKind::Unknown => Err(Error::KeyStore(
                "Unsupported PEM format. Expected \"BEGIN OPENSSH PRIVATE KEY\", \
                 \"BEGIN PRIVATE KEY\" or \"BEGIN EC PRIVATE KEY\""
                    .to_string(),
            )),
        }
    }

    fn from_openssh_private_key(key: &PrivateKey) -> Result<Self> {
        use ssh_key::private::KeypairData;
        match key.key_data() {
            KeypairData::Ed25519(kp) => {
                let seed: &[u8; 32] = kp.private.as_ref();
                Ok(KeyMaterial::Ed25519(Box::new(
                    Ed25519SigningKey::from_bytes(seed),
                )))
            }
            KeypairData::Rsa(kp) => Ok(KeyMaterial::Rsa(Box::new(rsa_keypair_to_rsa_private_key(
                kp,
            )?))),
            KeypairData::Ecdsa(kp) => Ok(KeyMaterial::Ecdsa(Box::new(
                ecdsa_keypair_to_signing_key(kp)?,
            ))),
            other => Err(Error::KeyStore(format!(
                "Unsupported key algorithm: {:?}. Only Ed25519, RSA and ECDSA are supported.",
                other.algorithm()
            ))),
        }
    }

    /// Parse a PKCS#8 PEM.
    ///
    /// Strategy:
    /// 1. Try a strict parse via the `pkcs8`/`ed25519-dalek`/`rsa` crates. This
    ///    dispatches on AlgorithmIdentifier OID, so a malformed header or a
    ///    misclassified blob fails loudly instead of silently producing a wrong
    ///    key.
    /// 2. If strict parsing fails, fall back to a targeted Ed25519 OID + offset
    ///    extraction. This exists solely for 1Password, which emits PKCS#8 with
    ///    non-canonical DER that strict parsers reject.
    /// 3. Last resort: defer to `rsa::RsaPrivateKey::from_pkcs8_pem` (which is
    ///    already lenient and gives the cleanest RSA error path).
    fn from_pkcs8(pem: &str) -> Result<Self> {
        if let Some(material) = parse_pkcs8_strict(pem)? {
            return Ok(material);
        }
        if let Ok(material) = parse_pkcs8_ed25519_lenient(pem) {
            return Ok(material);
        }
        parse_pkcs8_rsa(pem)
    }

    /// Parse a SEC1 `BEGIN EC PRIVATE KEY` PEM. ECDSA-only by definition (the
    /// SEC1 format exists solely for EC keys), so it dispatches straight to the
    /// curve probe.
    fn from_sec1_ec(pem: &str) -> Result<Self> {
        Ok(KeyMaterial::Ecdsa(Box::new(ecdsa_from_sec1_pem(pem)?)))
    }

    /// Sign and return an SSH signature blob (`string(algo) + string(sig)`).
    fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>> {
        match self {
            KeyMaterial::Ed25519(key) => Ok(sign_ed25519(key, data)),
            KeyMaterial::Rsa(key) => sign_rsa(key, data, flags),
            // ECDSA ignores the RSA SHA-2 flags entirely: the hash is fixed per
            // curve by the SSH spec (RFC 5656) and bound into each SigningKey.
            KeyMaterial::Ecdsa(key) => Ok(sign_ecdsa(key, data)),
        }
    }

    /// Derive the ssh-key public [`KeyData`] for this private key.
    ///
    /// Built from the public half of the native signing key, so it works even
    /// for the lenient 1Password Ed25519 path (where no `ssh_key::PrivateKey`
    /// ever exists). Encoding this `KeyData` yields the SSH wire public-key blob.
    fn public_key_data(&self) -> Result<KeyData> {
        match self {
            KeyMaterial::Ed25519(key) => {
                let verifying = key.verifying_key();
                let ed = ssh_key::public::Ed25519PublicKey(verifying.to_bytes());
                Ok(KeyData::Ed25519(ed))
            }
            KeyMaterial::Rsa(key) => {
                let public = rsa::RsaPublicKey::from(key.as_ref());
                let ssh_pub = ssh_key::public::RsaPublicKey::try_from(&public)
                    .map_err(|_| Error::KeyStore("failed to derive RSA public key".to_string()))?;
                Ok(KeyData::Rsa(ssh_pub))
            }
            KeyMaterial::Ecdsa(key) => Ok(KeyData::Ecdsa(ecdsa_public_key_data(key)?)),
        }
    }
}

fn sign_ed25519(key: &Ed25519SigningKey, data: &[u8]) -> Vec<u8> {
    // Ed25519 is deterministic and ignores flags. Sign with ed25519_dalek
    // directly — no ssh-key round-trip — and emit the SSH wire blob.
    let sig = ed25519_dalek::Signer::sign(key, data);
    encode_signature_blob("ssh-ed25519", &sig.to_bytes())
}

/// Whether we have already warned about a legacy `ssh-rsa` (SHA-1) signature in
/// this process. Emit at most once to avoid log spam when a session keeps
/// signing against the same legacy server.
static SSH_RSA_SHA1_WARNED: AtomicBool = AtomicBool::new(false);

fn sign_rsa(key: &rsa::RsaPrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>> {
    let (algorithm_name, sig_bytes) = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
        let signing_key = RsaSigningKey::<sha2::Sha512>::new(key.clone());
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        ("rsa-sha2-512", sig.to_vec())
    } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
        let signing_key = RsaSigningKey::<sha2::Sha256>::new(key.clone());
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        ("rsa-sha2-256", sig.to_vec())
    } else {
        // Legacy ssh-rsa (SHA-1). Required by old OpenSSH servers (e.g. CentOS 6
        // / OpenSSH 5.3) that advertise only ssh-rsa. SHA-1 is deprecated; warn
        // once per process so operators notice they are still propping up an
        // obsolete server.
        if !SSH_RSA_SHA1_WARNED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "cache-warden: producing legacy ssh-rsa (SHA-1) signature; the remote \
                 agent requested an algorithm OpenSSH deprecated in 8.2. Consider \
                 upgrading the remote sshd."
            );
        }
        let signing_key = RsaSigningKey::<sha1::Sha1>::new(key.clone());
        let sig: rsa::pkcs1v15::Signature = signature::Signer::sign(&signing_key, data);
        ("ssh-rsa", sig.to_vec())
    };

    Ok(encode_signature_blob(algorithm_name, &sig_bytes))
}

/// Sign `data` with an ECDSA key and emit the SSH wire signature blob.
///
/// Wire format (RFC 5656 §3.1.2): `string(algorithm) || string(ecdsa_sig_blob)`
/// where `ecdsa_sig_blob = mpint(r) || mpint(s)`. The hash is fixed by the curve
/// (P-256→SHA-256 etc.) and already bound into each crate's `Signer` impl, so we
/// just sign and re-encode the (r, s) field-byte pair as SSH mpints.
fn sign_ecdsa(key: &EcdsaKey, data: &[u8]) -> Vec<u8> {
    let (algorithm_name, r, s) = match key {
        EcdsaKey::NistP256(sk) => {
            let sig: p256::ecdsa::Signature = signature::Signer::sign(sk, data);
            let (r, s) = sig.split_bytes();
            ("ecdsa-sha2-nistp256", r.to_vec(), s.to_vec())
        }
        EcdsaKey::NistP384(sk) => {
            let sig: p384::ecdsa::Signature = signature::Signer::sign(sk, data);
            let (r, s) = sig.split_bytes();
            ("ecdsa-sha2-nistp384", r.to_vec(), s.to_vec())
        }
        EcdsaKey::NistP521(sk) => {
            let sig: p521::ecdsa::Signature = signature::Signer::sign(sk, data);
            let (r, s) = sig.split_bytes();
            ("ecdsa-sha2-nistp521", r.to_vec(), s.to_vec())
        }
    };
    let mut sig_blob = Vec::new();
    encode_mpint(&r, &mut sig_blob);
    encode_mpint(&s, &mut sig_blob);
    encode_signature_blob(algorithm_name, &sig_blob)
}

/// Encode a big-endian unsigned integer as an SSH `mpint` (RFC 4251 §5):
/// `string(<minimal twos-complement big-endian bytes>)`. Leading zero bytes are
/// stripped, and a single `0x00` is prepended when the high bit of the first
/// significant byte is set (so the value stays non-negative). Zero encodes as an
/// empty string.
fn encode_mpint(be_bytes: &[u8], out: &mut Vec<u8>) {
    let start = be_bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(be_bytes.len());
    let trimmed = &be_bytes[start..];
    let need_pad = trimmed.first().map(|&b| b & 0x80 != 0).unwrap_or(false);
    let len = trimmed.len() + usize::from(need_pad);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    if need_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
}

/// Build an [`EcdsaKey`] from ssh-key's parsed OpenSSH `EcdsaKeypair`.
///
/// ssh-key exposes the raw big-endian private scalar (`EcdsaPrivateKey::as_slice`)
/// per curve variant; we feed it to the matching RustCrypto `SecretKey` so the
/// curve is fixed by the variant (no curve confusion) and the scalar is range-
/// checked. `from_slice` rejects a zero / out-of-range scalar, so a malformed key
/// fails loudly here.
fn ecdsa_keypair_to_signing_key(kp: &ssh_key::private::EcdsaKeypair) -> Result<EcdsaKey> {
    use ssh_key::private::EcdsaKeypair;
    match kp {
        EcdsaKeypair::NistP256 { private, .. } => {
            let sk = p256::SecretKey::from_slice(private.as_slice())
                .map_err(|_| Error::KeyStore("Invalid ECDSA P-256 private key".to_string()))?;
            Ok(EcdsaKey::NistP256(sk.into()))
        }
        EcdsaKeypair::NistP384 { private, .. } => {
            let sk = p384::SecretKey::from_slice(private.as_slice())
                .map_err(|_| Error::KeyStore("Invalid ECDSA P-384 private key".to_string()))?;
            Ok(EcdsaKey::NistP384(sk.into()))
        }
        EcdsaKeypair::NistP521 { private, .. } => {
            let sk = p521::SecretKey::from_slice(private.as_slice())
                .map_err(|_| Error::KeyStore("Invalid ECDSA P-521 private key".to_string()))?;
            Ok(EcdsaKey::NistP521(p521_signing_key(&sk)?))
        }
    }
}

/// Build an [`EcdsaKey`] from a PKCS#8 DER blob (id-ecPublicKey).
///
/// The curve is carried in the AlgorithmIdentifier's namedCurve parameter, which
/// each `SecretKey::from_pkcs8_der` validates. We try the curves in turn; only
/// the matching one decodes, so there is no risk of curve confusion (a P-384 key
/// will not parse as P-256).
fn ecdsa_from_pkcs8_der(der: &[u8]) -> Result<EcdsaKey> {
    use pkcs8::DecodePrivateKey;
    if let Ok(sk) = p256::SecretKey::from_pkcs8_der(der) {
        return Ok(EcdsaKey::NistP256(sk.into()));
    }
    if let Ok(sk) = p384::SecretKey::from_pkcs8_der(der) {
        return Ok(EcdsaKey::NistP384(sk.into()));
    }
    if let Ok(sk) = p521::SecretKey::from_pkcs8_der(der) {
        return Ok(EcdsaKey::NistP521(p521_signing_key(&sk)?));
    }
    Err(Error::KeyStore(
        "Invalid or unsupported-curve PKCS#8 ECDSA private key".to_string(),
    ))
}

/// Parse a SEC1 `BEGIN EC PRIVATE KEY` PEM (RFC 5915) into an [`EcdsaKey`].
///
/// SEC1 carries the namedCurve OID inline, so each `SecretKey::from_sec1_pem`
/// only accepts its own curve; trying them in turn is curve-confusion-safe.
fn ecdsa_from_sec1_pem(pem: &str) -> Result<EcdsaKey> {
    if let Ok(sk) = p256::SecretKey::from_sec1_pem(pem) {
        return Ok(EcdsaKey::NistP256(sk.into()));
    }
    if let Ok(sk) = p384::SecretKey::from_sec1_pem(pem) {
        return Ok(EcdsaKey::NistP384(sk.into()));
    }
    if let Ok(sk) = p521::SecretKey::from_sec1_pem(pem) {
        return Ok(EcdsaKey::NistP521(p521_signing_key(&sk)?));
    }
    Err(Error::KeyStore(
        "Invalid or unsupported-curve SEC1 EC private key".to_string(),
    ))
}

/// Hand-rolled OpenSSH ECDSA private-key decode, used only when ssh-key 0.6
/// rejects the key (see the `from_pem` call site for why P-521 triggers this).
///
/// Parses the unencrypted `openssh-key-v1` container far enough to reach the
/// first private key's `string(curve) || string(Q) || mpint(d)` fields, reads
/// the scalar `d` as a *real* mpint (the bug is that ssh-key wants a fixed-width
/// field), and builds the matching curve's `SecretKey`. Returns `None` for
/// anything that is not a single unencrypted OpenSSH ECDSA key, so the caller
/// surfaces the original "invalid key" error.
fn parse_openssh_ecdsa_fallback(pem: &str) -> Option<EcdsaKey> {
    use base64::Engine;
    use ssh_encoding::Decode;

    let b64: Zeroizing<String> = Zeroizing::new(
        pem.lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>(),
    );
    let data: Zeroizing<Vec<u8>> = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .ok()?,
    );

    const MAGIC: &[u8] = b"openssh-key-v1\0";
    let body = data.strip_prefix(MAGIC)?;
    let mut reader: &[u8] = body;

    // ciphername, kdfname, kdfoptions. Only unencrypted keys are in scope (the
    // PKCS#8/encrypted paths are handled elsewhere); bail on anything else.
    let ciphername = Vec::<u8>::decode(&mut reader).ok()?;
    if ciphername != b"none" {
        return None;
    }
    let _kdfname = Vec::<u8>::decode(&mut reader).ok()?;
    let _kdfopts = Vec::<u8>::decode(&mut reader).ok()?;

    let nkeys = u32::decode(&mut reader).ok()?;
    if nkeys != 1 {
        return None;
    }
    let _public = Vec::<u8>::decode(&mut reader).ok()?;
    let private = Zeroizing::new(Vec::<u8>::decode(&mut reader).ok()?);

    // Private section: uint32 check1, uint32 check2, then the key fields.
    let mut p: &[u8] = &private;
    let check1 = u32::decode(&mut p).ok()?;
    let check2 = u32::decode(&mut p).ok()?;
    if check1 != check2 {
        return None;
    }
    let keytype = Vec::<u8>::decode(&mut p).ok()?;
    let curve = Vec::<u8>::decode(&mut p).ok()?;
    let _q = Vec::<u8>::decode(&mut p).ok()?;
    // The scalar is an SSH mpint (variable length): it may carry a leading
    // sign-padding zero (value's top bit set) or be *shorter* than the field
    // width (value's top bytes zero). Normalize to the curve's fixed field width
    // by stripping a sign-pad zero and then left-padding with zeros, which is
    // what `SecretKey::from_slice` expects.
    let scalar_mpint = Zeroizing::new(Vec::<u8>::decode(&mut p).ok()?);
    let magnitude: &[u8] = match scalar_mpint.split_first() {
        Some((0, rest)) => rest,
        _ => &scalar_mpint,
    };

    let field_width = match keytype.as_slice() {
        b"ecdsa-sha2-nistp256" => 32,
        b"ecdsa-sha2-nistp384" => 48,
        b"ecdsa-sha2-nistp521" => 66,
        _ => return None,
    };
    if magnitude.len() > field_width {
        return None;
    }
    let mut scalar = Zeroizing::new(vec![0u8; field_width]);
    scalar[field_width - magnitude.len()..].copy_from_slice(magnitude);

    match (keytype.as_slice(), curve.as_slice()) {
        (b"ecdsa-sha2-nistp256", b"nistp256") => {
            let sk = p256::SecretKey::from_slice(&scalar).ok()?;
            Some(EcdsaKey::NistP256(sk.into()))
        }
        (b"ecdsa-sha2-nistp384", b"nistp384") => {
            let sk = p384::SecretKey::from_slice(&scalar).ok()?;
            Some(EcdsaKey::NistP384(sk.into()))
        }
        (b"ecdsa-sha2-nistp521", b"nistp521") => {
            let sk = p521::SecretKey::from_slice(&scalar).ok()?;
            Some(EcdsaKey::NistP521(p521_signing_key(&sk).ok()?))
        }
        _ => None,
    }
}

/// Derive the ssh-key public [`EcdsaPublicKey`] from an [`EcdsaKey`].
///
/// Built from the SEC1 uncompressed point of the curve's `VerifyingKey`, so it
/// works for every parse path (OpenSSH / PKCS#8 / SEC1). Encoding the resulting
/// `KeyData::Ecdsa` yields the SSH wire public-key blob used for enumeration.
fn ecdsa_public_key_data(key: &EcdsaKey) -> Result<ssh_key::public::EcdsaPublicKey> {
    use ssh_key::public::EcdsaPublicKey;
    let sec1: Vec<u8> = match key {
        EcdsaKey::NistP256(sk) => sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        EcdsaKey::NistP384(sk) => sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        // p521's `SigningKey` wrapper lacks `verifying_key()` (no `verifying`
        // feature flag exists on the crate); derive the public key via the
        // `VerifyingKey: From<&SigningKey>` impl instead.
        EcdsaKey::NistP521(sk) => p521::ecdsa::VerifyingKey::from(sk)
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    EcdsaPublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| Error::KeyStore("failed to derive ECDSA public key".to_string()))
}

/// Build a p521 ECDSA `SigningKey` from a parsed `SecretKey`.
///
/// p521's wrapper `SigningKey` (unlike p256/p384) implements neither
/// `From<&SecretKey>` nor the PKCS#8/SEC1 decode traits, so we route through the
/// raw scalar bytes. `from_slice` re-validates the scalar (non-zero, in range).
fn p521_signing_key(sk: &p521::SecretKey) -> Result<p521::ecdsa::SigningKey> {
    p521::ecdsa::SigningKey::from_slice(&sk.to_bytes())
        .map_err(|_| Error::KeyStore("Invalid ECDSA P-521 private key".to_string()))
}

/// Convert ssh-key's RsaKeypair into rsa::RsaPrivateKey by reconstructing from
/// raw components. This avoids ssh-key's `TryFrom<RsaKeypair>` impl, whose CRT
/// validation fails on some otherwise-valid keys with "cryptographic error".
fn rsa_keypair_to_rsa_private_key(kp: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    use rsa::BigUint;
    // User-visible errors are deliberately fixed strings: the underlying crate's
    // `Display` impls may include excerpts of the offending DER / BigUint, which
    // would leak key material into logs and audit trails.
    let to_bigint = |m: &ssh_key::Mpint, _label: &str| -> Result<BigUint> {
        m.as_positive_bytes()
            .map(BigUint::from_bytes_be)
            .ok_or_else(|| Error::KeyStore("Invalid RSA key component".to_string()))
    };

    let n = to_bigint(&kp.public.n, "n")?;
    let e = to_bigint(&kp.public.e, "e")?;
    let d = to_bigint(&kp.private.d, "d")?;
    let p = to_bigint(&kp.private.p, "p")?;
    let q = to_bigint(&kp.private.q, "q")?;
    let mut key = rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q])
        .map_err(|_| Error::KeyStore("RSA key reconstruction failed".to_string()))?;
    // from_components leaves CRT parameters (dP, dQ, qInv) and Montgomery
    // precomputation empty. Without precompute() the signing path falls back to
    // a single full-modulus exponentiation per signature (~2x slower) and the
    // blinding shape diverges from a precomputed key. Always populate.
    key.precompute()
        .map_err(|_| Error::KeyStore("RSA key initialization failed".to_string()))?;
    Ok(key)
}

fn parse_pkcs8_rsa(pem: &str) -> Result<KeyMaterial> {
    use pkcs8::DecodePrivateKey;

    let mut key = rsa::RsaPrivateKey::from_pkcs8_pem(pem)
        .map_err(|_| Error::KeyStore("Invalid PKCS#8 RSA private key".to_string()))?;
    // PKCS#8 RSA carries dP/dQ/qInv on disk, but `from_pkcs8_pem` does not
    // populate the in-memory Montgomery precomputation. Trigger it so the
    // signing path matches the OpenSSH-format branch.
    key.precompute()
        .map_err(|_| Error::KeyStore("RSA key initialization failed".to_string()))?;
    Ok(KeyMaterial::Rsa(Box::new(key)))
}

/// Strict PKCS#8 parse via `pkcs8` / `ed25519-dalek` / `rsa` crates.
///
/// Returns `Ok(Some(...))` on success, `Ok(None)` when strict parsing rejected
/// the input (typically: 1Password's non-canonical DER), and `Err(...)` only
/// for an *identified-but-unsupported* algorithm.
///
/// Dispatching on AlgorithmIdentifier OID (rather than guessing by trying
/// algorithms in turn) makes silent misclassification impossible: a key whose
/// OID is neither Ed25519 nor RSA fails loudly here instead of being treated as
/// Ed25519 with random bytes as the seed.
fn parse_pkcs8_strict(pem: &str) -> Result<Option<KeyMaterial>> {
    use pkcs8::{DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo, SecretDocument};

    const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
    const RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
    // id-ecPublicKey: the AlgorithmIdentifier OID shared by every NIST ECDSA
    // curve. The specific curve is carried in the AlgorithmIdentifier parameters
    // (a namedCurve OID), which the per-curve `SecretKey::from_pkcs8_der` reads.
    const EC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

    let Ok((_label, doc)) = SecretDocument::from_pem(pem) else {
        return Ok(None);
    };
    let Ok(info) = PrivateKeyInfo::try_from(doc.as_bytes()) else {
        return Ok(None);
    };

    if info.algorithm.oid == ED25519_OID {
        let key = Ed25519SigningKey::from_pkcs8_der(doc.as_bytes())
            .map_err(|_| Error::KeyStore("Invalid PKCS#8 Ed25519 private key".to_string()))?;
        Ok(Some(KeyMaterial::Ed25519(Box::new(key))))
    } else if info.algorithm.oid == RSA_OID {
        let mut key = rsa::RsaPrivateKey::from_pkcs8_der(doc.as_bytes())
            .map_err(|_| Error::KeyStore("Invalid PKCS#8 RSA private key".to_string()))?;
        key.precompute()
            .map_err(|_| Error::KeyStore("RSA key initialization failed".to_string()))?;
        Ok(Some(KeyMaterial::Rsa(Box::new(key))))
    } else if info.algorithm.oid == EC_OID {
        Ok(Some(KeyMaterial::Ecdsa(Box::new(ecdsa_from_pkcs8_der(
            doc.as_bytes(),
        )?))))
    } else {
        Err(Error::KeyStore(
            "Unsupported PKCS#8 algorithm. Only Ed25519, RSA and ECDSA are supported.".to_string(),
        ))
    }
}

/// Lenient Ed25519 fallback for 1Password's non-canonical PKCS#8 DER.
///
/// Design rationale: 1Password emits PKCS#8 with non-canonical DER that
/// `pkcs8::PrivateKeyInfo::try_from` rejects. We scan for the Ed25519 OID
/// (1.3.101.112 = `06 03 2b 65 70`) and pull out the inner OCTET STRING holding
/// the 32-byte seed. This is reachable only after `parse_pkcs8_strict` returns
/// `None`, so a strict parse always wins when it succeeds.
fn parse_pkcs8_ed25519_lenient(pem: &str) -> Result<KeyMaterial> {
    // The base64 string and decoded DER both contain the full private key
    // (32-byte seed). Wrap in Zeroizing so they erase on drop instead of
    // lingering on the heap until reuse.
    let b64: Zeroizing<String> = Zeroizing::new(
        pem.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect(),
    );

    use base64::Engine;
    let der: Zeroizing<Vec<u8>> = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| Error::KeyStore("Invalid PKCS#8 PEM body".to_string()))?,
    );

    let seed = extract_ed25519_seed_from_pkcs8(&der)?;
    Ok(KeyMaterial::Ed25519(Box::new(
        Ed25519SigningKey::from_bytes(&seed),
    )))
}

/// Extract the 32-byte Ed25519 seed from a PKCS#8 DER blob.
///
/// Looks for the Ed25519 OID (1.3.101.112 = [06 03 2b 65 70]), then navigates
/// to the nested OCTET STRING containing the 32-byte seed.
fn extract_ed25519_seed_from_pkcs8(der: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

    let oid_pos = der
        .windows(ED25519_OID.len())
        .position(|w| w == ED25519_OID)
        .ok_or_else(|| {
            Error::KeyStore(
                "PKCS#8 key does not contain Ed25519 OID. \
                 Only Ed25519 keys in PKCS#8 format are supported."
                    .to_string(),
            )
        })?;

    let rest = &der[oid_pos + ED25519_OID.len()..];

    let outer_pos = rest.iter().position(|&b| b == 0x04).ok_or_else(|| {
        Error::KeyStore("PKCS#8: could not find private key OCTET STRING".to_string())
    })?;

    let outer = &rest[outer_pos..];
    if outer.len() < 2 {
        return Err(Error::KeyStore(
            "PKCS#8: outer OCTET STRING too short".to_string(),
        ));
    }

    let outer_len = outer[1] as usize;
    let outer_content = outer
        .get(2..2 + outer_len)
        .ok_or_else(|| Error::KeyStore("PKCS#8: outer OCTET STRING truncated".to_string()))?;

    if outer_content.first() != Some(&0x04) || outer_content.len() < 2 {
        return Err(Error::KeyStore(
            "PKCS#8: expected inner OCTET STRING for Ed25519 seed".to_string(),
        ));
    }

    let inner_len = outer_content[1] as usize;
    if inner_len != Ed25519PrivateKey::BYTE_SIZE {
        return Err(Error::KeyStore(format!(
            "PKCS#8: Ed25519 seed has unexpected length {} (expected {})",
            inner_len,
            Ed25519PrivateKey::BYTE_SIZE
        )));
    }

    let seed_bytes = outer_content
        .get(2..2 + inner_len)
        .ok_or_else(|| Error::KeyStore("PKCS#8: Ed25519 seed data truncated".to_string()))?;

    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(seed_bytes);
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ───── TEST FIXTURES ─────
    // The Ed25519 and RSA private keys below are FOR UNIT TESTS ONLY. They are
    // intentionally checked into the repository and have no value protected by
    // them. Do NOT install them anywhere — anyone with a copy of this repo can
    // sign arbitrary messages with these keys.

    /// Test PKCS#8 Ed25519 PEM lifted from the 1Password DR-014 spec.
    /// FOR TESTS ONLY — see banner above.
    const OP_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMFMCAQEwBQYDK2VwBCIEILfg0K3JM0GwuUuqBcJ79jKqV2owfa4zpRsarl64dDjC\noSMDIQBuIlSrfmaRn6Jj82jh6SDZkTFg0u5TlA9B1wYE2+lIyQ==\n-----END PRIVATE KEY-----\n";

    /// Public counterpart of `OP_PRIVATE_KEY_PEM`. FOR TESTS ONLY.
    const OP_PUBLIC_KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4iVKt+ZpGfomPzaOHpINmRMWDS7lOUD0HXBgTb6UjJ";

    /// Test PKCS#8 RSA-2048 PEM. Generated locally specifically for these tests;
    /// NEVER deploy to production. FOR TESTS ONLY.
    const RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDs/reWpFe7Nfte
seN0L0ZIW5xXtFNLDcNvZ7rIf4Rp7MOeB+GoBvJqw6gCL2S3RZBB1HgFnoeMMW1V
hu/2Jw7S2twOeNCmtDpThG3VBXMJhbwE7oqlWGIa1dIQDqt8x+xndkc0KlRP5BLj
wP8FFfpKrSyHG7Ix9IG24jw4RD39KehnH0SSe0buT2LOVTrFAVihplRICVxIxPTC
ViUcanJC32c3wZDfiRebT8oxSNJvJjhkxBE/zJVXZ045qG1EgPdM0LGozMqeFCGc
xHz3ZVCqItLpu1a7tQyOnbZMyGhMP+PDjbYYvahFqf5iftWKZsWGXFPhCzdqU3lB
stP3v7HnAgMBAAECggEARPk+8itDUzt7PIyWL47ArDdpUYcsRKgtTGOKk2a1YWSk
a/5MOOxIqjTmVTh43fPzb41IHw6L0YvjD6S1etTUNh63M8kKpLHIVd0xX/F1kPxo
g6DvHf8Skk/PkpfKZgcDcPsV7wMwxY2Rx9I4BkFmtkwfLPUtD+fixpiiQRfvWJnF
24Aupf9Yvdx2qPqu12jtaz9JKOfLiyD1vindvDHVwEfEJtGG7NRtPm4OmLIxPihh
9Y2WgLaWJhv6hKAzD/nGitBJUBzItg+wEviCQJ48rTa7OPTn9AblqMbRPeANr9sK
qBUNqj/2l/7MmDjSsz/SvkkL1DE7EbGWiy+aFttMEQKBgQD8qcYReWr5Ap2KyBn3
Bc09ya9e4syE6ycfj4QRMb3otX7y1l8qmYJvaH4MKcTuT4InmazUoqqoRHpyKBRU
wcAioCjL8VKYV4oZiOMNPhbUhCQRNqQbL+l15Vx/hkIUmY6cwAuxpWHYcthbpAJz
EwQ7vbIGLMnhC1ei5LIf562ZEQKBgQDwH/iUvtsoXtnF91QoXziMvQSK6wUKfX5A
zJQxADcHzynPDoQZKST0pprVYTxeCs1J+kSDq9kpbdDR4wkeGTvH1B/1w4ddkcve
xSJOuYjuyoN99Rjl6ocwT6h3o+mpG88FFZdEdi6kmWpaoqguTvOYEeJAKIpjdwiO
2TSuolzbdwKBgQD3AO4uhRmr5/+l/itMD/Luta3pQCWax9zOgNomiQ9UYaKCukn8
9mfKjEe1klwAceAW4KhSk9fsek2OLlp55ZP1Bcf8YKZTYjkS73ywpINjLO+pmFZk
cbl1VU3RKaqOQvRlj2WfPMPj+5pCNJtkbjHUSYWxfbW6eQEqsRLmF/LhUQKBgBVk
09H02zPSl5aCvbXHHhOz94ak/9L6cVg2ofFnsn94nqH7ChvvxYIioeLnAejjD31K
1fXhRrzhMtywXKyY1PGt3ZcY76OPjNlxOOhIsYGM+4AqaSh658aPIlRefz/44U3z
qYGJAgjaPlaK7W8Ky7s9xKmwsvu/rDyF76KrhphrAoGBAOO4bvMQz9ksp8s1fPoB
+H8CJoZgcWKHdD65AUJAbfSGJluqSzKYb6XwRswyV2J+rLJak2lT3IN9kUsOdR/g
/F+QQjFBq+gR1FVb/n4fKNNuazOUQcuTaoFRx4GhSYMhlhW3Nbd5aNXH8zJhqMBW
IGmiN6jIaYLa8S4Be472ERHj
-----END PRIVATE KEY-----
";
    const RSA_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDs/reWpFe7NfteseN0L0ZIW5xXtFNLDcNvZ7rIf4Rp7MOeB+GoBvJqw6gCL2S3RZBB1HgFnoeMMW1Vhu/2Jw7S2twOeNCmtDpThG3VBXMJhbwE7oqlWGIa1dIQDqt8x+xndkc0KlRP5BLjwP8FFfpKrSyHG7Ix9IG24jw4RD39KehnH0SSe0buT2LOVTrFAVihplRICVxIxPTCViUcanJC32c3wZDfiRebT8oxSNJvJjhkxBE/zJVXZ045qG1EgPdM0LGozMqeFCGcxHz3ZVCqItLpu1a7tQyOnbZMyGhMP+PDjbYYvahFqf5iftWKZsWGXFPhCzdqU3lBstP3v7Hn";

    /// Parse an SSH wire signature blob into (algorithm, signature_bytes).
    fn parse_blob(blob: &[u8]) -> (String, Vec<u8>) {
        let mut buf = blob;
        let algo_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        buf = &buf[4..];
        let algo = std::str::from_utf8(&buf[..algo_len]).unwrap().to_string();
        buf = &buf[algo_len..];
        let sig_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        buf = &buf[4..];
        (algo, buf[..sig_len].to_vec())
    }

    fn parse_ssh_signature(blob: &[u8]) -> ssh_key::Signature {
        ssh_key::Signature::try_from(blob).unwrap()
    }

    fn verify(pub_key: &ssh_key::PublicKey, data: &[u8], sig: &ssh_key::Signature) {
        <ssh_key::PublicKey as signature::Verifier<ssh_key::Signature>>::verify(pub_key, data, sig)
            .unwrap();
    }

    /// Verify an ssh-rsa (SHA-1) signature blob directly via the rsa crate.
    fn verify_rsa_sha1(pem: &str, data: &[u8], blob: &[u8]) {
        use pkcs8::DecodePrivateKey;
        let priv_key = rsa::RsaPrivateKey::from_pkcs8_pem(pem).unwrap();
        let pub_key = rsa::RsaPublicKey::from(&priv_key);
        let (algo, sig_bytes) = parse_blob(blob);
        assert_eq!(algo, "ssh-rsa");
        let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        let verifier = rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(pub_key);
        <rsa::pkcs1v15::VerifyingKey<sha1::Sha1> as signature::Verifier<
            rsa::pkcs1v15::Signature,
        >>::verify(&verifier, data, &sig)
        .unwrap();
    }

    #[test]
    fn from_pem_parses_pkcs8_ed25519() {
        let material = KeyMaterial::from_pem(OP_PRIVATE_KEY_PEM).unwrap();
        assert!(matches!(material, KeyMaterial::Ed25519(_)));
    }

    #[test]
    fn from_pem_parses_pkcs8_rsa() {
        let material = KeyMaterial::from_pem(RSA_PRIVATE_KEY_PEM).unwrap();
        assert!(matches!(material, KeyMaterial::Rsa(_)));
    }

    #[test]
    fn rsa_key_has_crt_precomputation() {
        // from_components leaves CRT parameters empty; without precompute() RSA
        // signing falls back to a slow non-CRT exponentiation path. Verify both
        // PKCS#8 and OpenSSH RSA paths populate them.
        use rsa::traits::PrivateKeyParts;
        let material = KeyMaterial::from_pem(RSA_PRIVATE_KEY_PEM).unwrap();
        let key = match &material {
            KeyMaterial::Rsa(k) => k,
            _ => panic!("expected RSA"),
        };
        assert!(key.dp().is_some(), "dp should be precomputed");
        assert!(key.dq().is_some(), "dq should be precomputed");
        assert!(key.qinv().is_some(), "qinv should be precomputed");
    }

    #[test]
    fn rsa_openssh_path_has_crt_precomputation() {
        use pkcs8::DecodePrivateKey;
        use rsa::traits::PrivateKeyParts;
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(RSA_PRIVATE_KEY_PEM).unwrap();
        let kp = ssh_key::private::RsaKeypair::try_from(rsa_key).unwrap();
        let pk = ssh_key::PrivateKey::from(kp);
        let openssh_pem = pk.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();

        let material = KeyMaterial::from_pem(&openssh_pem).unwrap();
        let key = match &material {
            KeyMaterial::Rsa(k) => k,
            _ => panic!("expected RSA"),
        };
        assert!(
            key.dp().is_some(),
            "dp should be precomputed via OpenSSH path"
        );
        assert!(
            key.dq().is_some(),
            "dq should be precomputed via OpenSSH path"
        );
        assert!(
            key.qinv().is_some(),
            "qinv should be precomputed via OpenSSH path"
        );
    }

    #[test]
    fn from_pem_rejects_garbage() {
        assert!(KeyMaterial::from_pem("not a key").is_err());
    }

    #[test]
    fn from_pem_rejects_invalid_pkcs8() {
        let pem = "-----BEGIN PRIVATE KEY-----\nYWJjZA==\n-----END PRIVATE KEY-----\n";
        assert!(KeyMaterial::from_pem(pem).is_err());
    }

    #[test]
    fn extract_ed25519_seed_rejects_non_ed25519_oid() {
        let der = vec![0x30, 0x10, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86];
        let result = extract_ed25519_seed_from_pkcs8(&der);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Ed25519 OID"));
    }

    #[test]
    fn from_pem_rejects_encrypted_pkcs8() {
        let pem =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAA=\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let result = KeyMaterial::from_pem(pem);
        assert!(result.is_err());
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("encrypted PKCS#8 should be rejected"),
        };
        assert!(
            msg.to_lowercase().contains("encrypted"),
            "expected encrypted-rejection message, got: {msg}"
        );
    }

    #[test]
    fn from_pem_distinguishes_pkcs8_header_from_encrypted_substring() {
        // A genuine "BEGIN PRIVATE KEY" must be treated as Pkcs8 (header line
        // wins, body is opaque).
        let result = KeyMaterial::from_pem(OP_PRIVATE_KEY_PEM);
        assert!(result.is_ok(), "valid PKCS#8 PEM must still parse");
    }

    #[test]
    fn from_pem_handles_crlf_line_endings() {
        let crlf_pem = OP_PRIVATE_KEY_PEM.replace('\n', "\r\n");
        let material = KeyMaterial::from_pem(&crlf_pem).unwrap();
        assert!(matches!(material, KeyMaterial::Ed25519(_)));
    }

    #[test]
    fn from_pem_handles_no_trailing_newline() {
        let trimmed = OP_PRIVATE_KEY_PEM.trim_end_matches('\n');
        let material = KeyMaterial::from_pem(trimmed).unwrap();
        assert!(matches!(material, KeyMaterial::Ed25519(_)));
    }

    #[test]
    fn from_pem_rsa_handles_crlf_line_endings() {
        let crlf_pem = RSA_PRIVATE_KEY_PEM.replace('\n', "\r\n");
        let material = KeyMaterial::from_pem(&crlf_pem).unwrap();
        assert!(matches!(material, KeyMaterial::Rsa(_)));
    }

    #[test]
    fn sign_ed25519_produces_verifiable_signature() {
        let pub_key = ssh_key::PublicKey::from_openssh(OP_PUBLIC_KEY).unwrap();
        let data = b"ed25519 challenge";

        let blob = sign(OP_PRIVATE_KEY_PEM, data, 0).unwrap();
        let (algo, _) = parse_blob(&blob);
        assert_eq!(algo, "ssh-ed25519");
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }

    #[test]
    fn sign_rsa_with_default_flags_uses_ssh_rsa_sha1() {
        // flags=0 -> ssh-rsa (SHA-1). Used by legacy OpenSSH. ssh-key 0.6 refuses
        // Algorithm::Rsa { hash: None }, so verify via the rsa crate.
        let data = b"legacy ssh-rsa challenge";
        let blob = sign(RSA_PRIVATE_KEY_PEM, data, 0).unwrap();
        verify_rsa_sha1(RSA_PRIVATE_KEY_PEM, data, &blob);
    }

    #[test]
    fn sign_rsa_with_sha2_256_flag_uses_rsa_sha2_256() {
        let pub_key = ssh_key::PublicKey::from_openssh(RSA_PUBLIC_KEY).unwrap();
        let data = b"rsa-sha2-256 challenge";

        let blob = sign(RSA_PRIVATE_KEY_PEM, data, SSH_AGENT_RSA_SHA2_256).unwrap();
        let (algo, _) = parse_blob(&blob);
        assert_eq!(algo, "rsa-sha2-256");
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }

    #[test]
    fn sign_rsa_with_sha2_512_flag_uses_rsa_sha2_512() {
        // Modern OpenSSH clients request rsa-sha2-512 first.
        let pub_key = ssh_key::PublicKey::from_openssh(RSA_PUBLIC_KEY).unwrap();
        let data = b"rsa-sha2-512 challenge";

        let blob = sign(RSA_PRIVATE_KEY_PEM, data, SSH_AGENT_RSA_SHA2_512).unwrap();
        let (algo, _) = parse_blob(&blob);
        assert_eq!(algo, "rsa-sha2-512");
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }

    #[test]
    fn sign_rsa_openssh_format_works() {
        // Ensure RSA keys parsed from OpenSSH format (not just PKCS#8) sign too.
        use pkcs8::DecodePrivateKey;
        let rsa_key = rsa::RsaPrivateKey::from_pkcs8_pem(RSA_PRIVATE_KEY_PEM).unwrap();
        let kp = ssh_key::private::RsaKeypair::try_from(rsa_key).unwrap();
        let pk = ssh_key::PrivateKey::from(kp);
        let openssh_pem = pk.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string();

        let pub_key = ssh_key::PublicKey::from_openssh(RSA_PUBLIC_KEY).unwrap();
        let data = b"openssh format rsa";
        let blob = sign(&openssh_pem, data, SSH_AGENT_RSA_SHA2_512).unwrap();
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }

    // ───── ECDSA TEST FIXTURES ─────
    // The ECDSA P-256 private keys below are FOR UNIT TESTS ONLY. Generated
    // locally via `ssh-keygen -t ecdsa -b 256`; intentionally checked in and
    // protecting nothing. Do NOT install them anywhere. The P-384 / P-521 round
    // trips are exercised with freshly generated keys instead of hardcoded ones.

    /// P-256 OpenSSH-format private key. FOR TESTS ONLY.
    const ECDSA_P256_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSyKrNRasgsv+4qOOXbTrBD2h8fS0do
S4KFrX0KysZ+nRL8SODhemBItMzL7RRBGwfkdhjyv3Ka1KuVPcjEUuIUAAAAsM7tau/O7W
rvAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLIqs1FqyCy/7io4
5dtOsEPaHx9LR2hLgoWtfQrKxn6dEvxI4OF6YEi0zMvtFEEbB+R2GPK/cprUq5U9yMRS4h
QAAAAgVWlVkNdBySxzgcbhA75tqXuJaEPvvBKPOK1JyIiV5aAAAAARZWNkc2EyNTYgdGVz
dCBrZXkBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
";

    /// P-256 PKCS#8-format private key (same key as `ECDSA_P256_OPENSSH`).
    /// FOR TESTS ONLY.
    const ECDSA_P256_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVWlVkNdBySxzgcbh
A75tqXuJaEPvvBKPOK1JyIiV5aChRANCAASyKrNRasgsv+4qOOXbTrBD2h8fS0do
S4KFrX0KysZ+nRL8SODhemBItMzL7RRBGwfkdhjyv3Ka1KuVPcjEUuIU
-----END PRIVATE KEY-----
";

    /// P-256 SEC1-format private key (`BEGIN EC PRIVATE KEY`, same key).
    /// FOR TESTS ONLY.
    const ECDSA_P256_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFVpVZDXQcksc4HG4QO+bal7iWhD77wSjzitSciIleWgoAoGCCqGSM49
AwEHoUQDQgAEsiqzUWrILL/uKjjl206wQ9ofH0tHaEuCha19CsrGfp0S/Ejg4Xpg
SLTMy+0UQRsH5HYY8r9ymtSrlT3IxFLiFA==
-----END EC PRIVATE KEY-----
";

    /// OpenSSH public counterpart of the P-256 fixtures. FOR TESTS ONLY.
    const ECDSA_P256_PUBLIC: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLIqs1FqyCy/7io45dtOsEPaHx9LR2hLgoWtfQrKxn6dEvxI4OF6YEi0zMvtFEEbB+R2GPK/cprUq5U9yMRS4hQ= ecdsa256 test key";

    #[test]
    fn from_pem_parses_ecdsa_openssh() {
        let material = KeyMaterial::from_pem(ECDSA_P256_OPENSSH).unwrap();
        assert!(matches!(material, KeyMaterial::Ecdsa(_)));
    }

    #[test]
    fn from_pem_parses_ecdsa_pkcs8() {
        let material = KeyMaterial::from_pem(ECDSA_P256_PKCS8).unwrap();
        assert!(matches!(material, KeyMaterial::Ecdsa(_)));
    }

    #[test]
    fn from_pem_parses_ecdsa_sec1() {
        let material = KeyMaterial::from_pem(ECDSA_P256_SEC1).unwrap();
        assert!(matches!(material, KeyMaterial::Ecdsa(_)));
    }

    #[test]
    fn ecdsa_p256_all_formats_yield_same_public_key() {
        // OpenSSH / PKCS#8 / SEC1 are three encodings of the *same* private key;
        // the derived public-key blob must be identical across all three.
        let blob = |pem: &str| {
            let m = KeyMaterial::from_pem(pem).unwrap();
            let kd = m.public_key_data().unwrap();
            let mut b = Vec::new();
            Encode::encode(&kd, &mut b).unwrap();
            b
        };
        let openssh = blob(ECDSA_P256_OPENSSH);
        assert_eq!(openssh, blob(ECDSA_P256_PKCS8));
        assert_eq!(openssh, blob(ECDSA_P256_SEC1));

        // ...and it must match the standalone OpenSSH public key.
        let expected = ssh_key::PublicKey::from_openssh(ECDSA_P256_PUBLIC).unwrap();
        let mut expected_blob = Vec::new();
        expected.key_data().encode(&mut expected_blob).unwrap();
        assert_eq!(openssh, expected_blob);
    }

    #[test]
    fn sign_ecdsa_p256_openssh_produces_verifiable_signature() {
        let pub_key = ssh_key::PublicKey::from_openssh(ECDSA_P256_PUBLIC).unwrap();
        let data = b"ecdsa p256 challenge";
        let blob = sign(ECDSA_P256_OPENSSH, data, 0).unwrap();
        let (algo, _) = parse_blob(&blob);
        assert_eq!(algo, "ecdsa-sha2-nistp256");
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }

    #[test]
    fn sign_ecdsa_p256_pkcs8_produces_verifiable_signature() {
        let pub_key = ssh_key::PublicKey::from_openssh(ECDSA_P256_PUBLIC).unwrap();
        let data = b"ecdsa p256 pkcs8 challenge";
        let blob = sign(ECDSA_P256_PKCS8, data, 0).unwrap();
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }

    #[test]
    fn sign_ecdsa_p256_sec1_produces_verifiable_signature() {
        let pub_key = ssh_key::PublicKey::from_openssh(ECDSA_P256_PUBLIC).unwrap();
        let data = b"ecdsa p256 sec1 challenge";
        let blob = sign(ECDSA_P256_SEC1, data, 0).unwrap();
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }

    /// Round-trip (generate -> OpenSSH PEM -> parse -> sign -> verify) for every
    /// supported curve, using freshly generated keys so we never hardcode P-384 /
    /// P-521 secrets. ECDSA nonces are random, so we only assert verifiability.
    #[test]
    fn sign_ecdsa_round_trip_all_curves_openssh() {
        use ssh_key::private::EcdsaKeypair;
        use ssh_key::{EcdsaCurve, LineEnding};
        for curve in [
            EcdsaCurve::NistP256,
            EcdsaCurve::NistP384,
            EcdsaCurve::NistP521,
        ] {
            let kp = EcdsaKeypair::random(&mut rand_core::OsRng, curve).unwrap();
            let pk = ssh_key::PrivateKey::from(kp);
            let openssh_pem = pk.to_openssh(LineEnding::LF).unwrap().to_string();
            let pub_key = pk.public_key();

            let data = b"per-curve openssh round trip";
            let blob = sign(&openssh_pem, data, 0).unwrap();
            let (algo, _) = parse_blob(&blob);
            let expected_algo = match curve {
                EcdsaCurve::NistP256 => "ecdsa-sha2-nistp256",
                EcdsaCurve::NistP384 => "ecdsa-sha2-nistp384",
                EcdsaCurve::NistP521 => "ecdsa-sha2-nistp521",
            };
            assert_eq!(algo, expected_algo, "curve {curve:?}");
            verify(pub_key, data, &parse_ssh_signature(&blob));
        }
    }

    /// The derived ECDSA public-key blob must round-trip back through
    /// `PublicKey::from_bytes` for every curve (enumeration path soundness).
    #[test]
    fn ecdsa_public_blob_round_trips_all_curves() {
        use ssh_key::private::EcdsaKeypair;
        use ssh_key::{EcdsaCurve, LineEnding};
        for curve in [
            EcdsaCurve::NistP256,
            EcdsaCurve::NistP384,
            EcdsaCurve::NistP521,
        ] {
            let kp = EcdsaKeypair::random(&mut rand_core::OsRng, curve).unwrap();
            let pk = ssh_key::PrivateKey::from(kp);
            let openssh_pem = pk.to_openssh(LineEnding::LF).unwrap().to_string();

            let (blob, _comment) = public_key_blob_from_pem(&openssh_pem).unwrap();
            use ssh_encoding::Decode;
            let parsed = ssh_key::public::KeyData::decode(&mut blob.as_slice()).unwrap();
            assert_eq!(&parsed, pk.public_key().key_data(), "curve {curve:?}");
        }
    }

    // A real ssh-keygen P-521 OpenSSH key whose private scalar mpint is 65 bytes
    // (top byte of the value is zero, ~1/256 chance). ssh-key 0.6 rejects it with
    // `Encoding(Length)`; our hand-rolled OpenSSH ECDSA fallback must recover it.
    // FOR TESTS ONLY — generated locally, protects nothing.
    const ECDSA_P521_SHORT_SCALAR_OPENSSH: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQAln3NyrH79taU0ZWywPKAJaXL+h/n
oQ6kurgRVH3DWM0JgDygA2yUicTQJ4BPUcSnivAUtDGDGiiWLIqPoU7GuTMB5Y8/abgLOr
NMQrZ4KutXYc04E1+4RzswETJgQ3YL/lwqAkI8S/oyssbAN8Ig3nKspAP59vnO6AlP4VAQ
ImsxFGYAAAEABozsCwaM7AsAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAJZ9zcqx+/bWlNGVssDygCWly/of56EOpLq4EVR9w1jNCYA8oANslInE0CeAT1HE
p4rwFLQxgxooliyKj6FOxrkzAeWPP2m4CzqzTEK2eCrrV2HNOBNfuEc7MBEyYEN2C/5cKg
JCPEv6MrLGwDfCIN5yrKQD+fb5zugJT+FQECJrMRRmAAAAQSaNNRsCYO2UBlpjhNSuEx6Q
0Lljg/yS7D/uH+2z8QGtPyVeGCs91uu0Tp6RY2wAerTYQfnFz70bRjXYsYeTysVrAAAAAn
AzAQ==
-----END OPENSSH PRIVATE KEY-----
";

    const ECDSA_P521_SHORT_SCALAR_PUBLIC: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACWfc3Ksfv21pTRlbLA8oAlpcv6H+ehDqS6uBFUfcNYzQmAPKADbJSJxNAngE9RxKeK8BS0MYMaKJYsio+hTsa5MwHljz9puAs6s0xCtngq61dhzTgTX7hHOzARMmBDdgv+XCoCQjxL+jKyxsA3wiDecqykA/n2+c7oCU/hUBAiazEUZg== p3";

    #[test]
    fn ssh_key_rejects_short_scalar_p521_but_we_recover_it() {
        // Document the upstream limitation: ssh-key itself cannot parse this key.
        assert!(
            ssh_key::PrivateKey::from_openssh(ECDSA_P521_SHORT_SCALAR_OPENSSH).is_err(),
            "fixture must be one ssh-key 0.6 rejects (else the fallback is untested)"
        );
        // ...but our fallback parses it as ECDSA.
        let material = KeyMaterial::from_pem(ECDSA_P521_SHORT_SCALAR_OPENSSH).unwrap();
        assert!(matches!(material, KeyMaterial::Ecdsa(_)));
    }

    #[test]
    fn short_scalar_p521_derives_correct_public_key() {
        // The fallback must reconstruct the exact key: its derived public blob
        // has to equal ssh-keygen's published public key (a wrong scalar would
        // yield a different point).
        let (blob, _c) = public_key_blob_from_pem(ECDSA_P521_SHORT_SCALAR_OPENSSH).unwrap();
        let expected = ssh_key::PublicKey::from_openssh(ECDSA_P521_SHORT_SCALAR_PUBLIC).unwrap();
        let mut eb = Vec::new();
        expected.key_data().encode(&mut eb).unwrap();
        assert_eq!(blob, eb);
    }

    #[test]
    fn short_scalar_p521_signs_and_verifies() {
        let pub_key = ssh_key::PublicKey::from_openssh(ECDSA_P521_SHORT_SCALAR_PUBLIC).unwrap();
        let data = b"short scalar p521 challenge";
        let blob = sign(ECDSA_P521_SHORT_SCALAR_OPENSSH, data, 0).unwrap();
        let (algo, _) = parse_blob(&blob);
        assert_eq!(algo, "ecdsa-sha2-nistp521");
        verify(&pub_key, data, &parse_ssh_signature(&blob));
    }
}
