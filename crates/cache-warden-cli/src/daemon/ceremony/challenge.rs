//! Challenge lifecycle for the vault ceremony (DR-0032, applied by DR-0034 §2).
//!
//! A challenge is the thing that makes an assertion *this* ceremony's rather
//! than a recording of an earlier one. Four properties carry that, and each is
//! enforced here rather than left to the caller:
//!
//! - **Unpredictable**: 32 bytes from the system CSPRNG.
//! - **Single use**: taking a challenge removes it. A replayed response finds
//!   nothing to match and is refused, even if it arrives a millisecond later.
//! - **Short lived**: an unclaimed challenge expires. A ceremony a user
//!   abandoned should not stay open for whoever finds the tab tomorrow.
//! - **Purpose bound**: a challenge issued to register a passkey cannot
//!   complete an unlock, and neither can complete an approval from DR-0032's
//!   flow. Returning key material and returning a yes/no are different
//!   operations, and DR-0034 §2 requires that an assertion for one never
//!   satisfies the other.
//!
//! Challenges live in memory only. They are worthless after the process that
//! issued them exits — a successor could not honour one anyway, since the
//! ceremony it belonged to is gone with the page.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand_core::RngCore as _;

/// How long an unclaimed challenge stays valid.
///
/// Long enough to find a security key, wake a phone, or authenticate to a
/// password manager; short enough that an abandoned ceremony closes on its own
/// rather than waiting for a process restart.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(120);

/// The most challenges outstanding at once.
///
/// A bound rather than unbounded growth: issuing a challenge is unauthenticated
/// (the page has to get one before it can prove anything), so without a ceiling
/// a caller that asks in a loop would grow this map until the daemon died.
/// Reaching the ceiling refuses new challenges rather than evicting live ones —
/// evicting would let a flood cancel a ceremony a user is part-way through.
const MAX_OUTSTANDING: usize = 32;

/// What a challenge may be used to complete (DR-0034 §2 domain separation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// Registering a new passkey slot.
    RegisterPasskey,
    /// Opening the vault.
    ///
    /// Carries the generation the vault was at when the challenge was issued,
    /// which is what binds an unlock ceremony to the vault state it was
    /// started against (DR-0034 §2: the purpose string is bound to the
    /// challenge record, deliberately *not* to the key derivation — putting
    /// the generation in the derivation would make every data-key rotation
    /// require a fresh ceremony from every device).
    Unlock {
        /// The vault this unlock is for.
        vault_id: String,
        /// The data-key generation at issue time.
        dek_generation: u64,
    },
}

/// One outstanding challenge.
struct Record {
    purpose: Purpose,
    expires_at: Instant,
}

/// Why a challenge could not be redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    /// No such challenge: never issued, already used, or expired.
    ///
    /// One variant for all three on purpose. A caller learns only that this
    /// challenge is not usable, which is all a legitimate one needs and all a
    /// prober should get.
    Unknown,
    /// The challenge exists but was issued for a different operation.
    WrongPurpose,
    /// Too many challenges are already outstanding.
    TooMany,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ChallengeError::Unknown => "that challenge is not outstanding",
            ChallengeError::WrongPurpose => "that challenge was issued for a different operation",
            ChallengeError::TooMany => {
                "too many ceremonies are already in progress; finish or abandon one and retry"
            }
        };
        f.write_str(s)
    }
}

/// The challenges this process has issued and not yet seen used.
#[derive(Default)]
pub struct ChallengeStore {
    outstanding: HashMap<Vec<u8>, Record>,
}

impl ChallengeStore {
    /// Issue a challenge for `purpose`, returning its bytes.
    pub fn issue(&mut self, purpose: Purpose) -> Result<Vec<u8>, ChallengeError> {
        self.drop_expired(Instant::now());
        if self.outstanding.len() >= MAX_OUTSTANDING {
            return Err(ChallengeError::TooMany);
        }
        let mut bytes = vec![0u8; 32];
        rand_core::OsRng.fill_bytes(&mut bytes);
        self.outstanding.insert(
            bytes.clone(),
            Record {
                purpose,
                expires_at: Instant::now() + CHALLENGE_TTL,
            },
        );
        Ok(bytes)
    }

    /// Redeem a challenge, consuming it.
    ///
    /// Removal happens before the purpose is checked, so a response that names
    /// the right challenge for the wrong operation still burns it. Leaving it
    /// outstanding would let a caller probe purposes with one challenge until
    /// it found the one it was issued for.
    pub fn redeem(&mut self, challenge: &[u8], purpose: &Purpose) -> Result<(), ChallengeError> {
        let now = Instant::now();
        self.drop_expired(now);
        let record = self
            .outstanding
            .remove(challenge)
            .ok_or(ChallengeError::Unknown)?;
        if record.expires_at <= now {
            return Err(ChallengeError::Unknown);
        }
        if &record.purpose != purpose {
            return Err(ChallengeError::WrongPurpose);
        }
        Ok(())
    }

    /// How many challenges are outstanding.
    #[cfg(test)]
    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }

    fn drop_expired(&mut self, now: Instant) {
        self.outstanding.retain(|_, r| r.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlock() -> Purpose {
        Purpose::Unlock {
            vault_id: "abc".into(),
            dek_generation: 1,
        }
    }

    #[test]
    fn a_challenge_is_redeemable_once() {
        let mut store = ChallengeStore::default();
        let c = store.issue(unlock()).expect("issues");
        assert_eq!(store.redeem(&c, &unlock()), Ok(()));
        assert_eq!(
            store.redeem(&c, &unlock()),
            Err(ChallengeError::Unknown),
            "a replayed response must find nothing to match"
        );
    }

    #[test]
    fn challenges_are_unpredictable_and_distinct() {
        let mut store = ChallengeStore::default();
        let a = store.issue(unlock()).unwrap();
        let b = store.issue(unlock()).unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }

    /// DR-0034 §2: an assertion produced for one operation must not complete
    /// another. Registration and unlock are the two here, and the difference
    /// matters — one adds a way into the vault, the other opens it.
    #[test]
    fn a_challenge_for_one_purpose_does_not_complete_another() {
        let mut store = ChallengeStore::default();
        let c = store.issue(Purpose::RegisterPasskey).expect("issues");
        assert_eq!(
            store.redeem(&c, &unlock()),
            Err(ChallengeError::WrongPurpose)
        );
        // And it was consumed even so, rather than left for a second guess.
        assert_eq!(
            store.redeem(&c, &Purpose::RegisterPasskey),
            Err(ChallengeError::Unknown),
            "a wrong-purpose attempt must not leave the challenge usable"
        );
    }

    /// The generation is part of the purpose, so a ceremony begun against one
    /// vault state cannot be completed against another.
    #[test]
    fn an_unlock_challenge_is_bound_to_its_vault_and_generation() {
        let mut store = ChallengeStore::default();
        let c = store.issue(unlock()).expect("issues");
        let rotated = Purpose::Unlock {
            vault_id: "abc".into(),
            dek_generation: 2,
        };
        assert_eq!(
            store.redeem(&c, &rotated),
            Err(ChallengeError::WrongPurpose)
        );

        let c = store.issue(unlock()).expect("issues");
        let other_vault = Purpose::Unlock {
            vault_id: "def".into(),
            dek_generation: 1,
        };
        assert_eq!(
            store.redeem(&c, &other_vault),
            Err(ChallengeError::WrongPurpose)
        );
    }

    #[test]
    fn an_expired_challenge_is_refused_and_forgotten() {
        let mut store = ChallengeStore::default();
        let c = store.issue(unlock()).expect("issues");
        // Reach in and age it, rather than sleeping out the real TTL.
        store.outstanding.get_mut(&c).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        assert_eq!(store.redeem(&c, &unlock()), Err(ChallengeError::Unknown));
        assert_eq!(
            store.outstanding(),
            0,
            "and it is not left occupying a slot"
        );
    }

    /// Issuing is unauthenticated, so it needs a ceiling. Refusing rather than
    /// evicting means a flood cannot cancel a ceremony someone is part-way
    /// through.
    #[test]
    fn a_flood_of_requests_is_refused_without_cancelling_a_live_ceremony() {
        let mut store = ChallengeStore::default();
        let first = store.issue(unlock()).expect("issues");
        for _ in 1..MAX_OUTSTANDING {
            store.issue(unlock()).expect("issues");
        }
        assert_eq!(store.issue(unlock()), Err(ChallengeError::TooMany));
        assert_eq!(
            store.redeem(&first, &unlock()),
            Ok(()),
            "the ceremony already in progress must still be completable"
        );
    }

    /// Expiry frees capacity: a daemon that refused forever after one flood
    /// would be denial-of-serviced by a single burst.
    #[test]
    fn capacity_returns_as_challenges_expire() {
        let mut store = ChallengeStore::default();
        for _ in 0..MAX_OUTSTANDING {
            store.issue(unlock()).expect("issues");
        }
        assert_eq!(store.issue(unlock()), Err(ChallengeError::TooMany));
        for r in store.outstanding.values_mut() {
            r.expires_at = Instant::now() - Duration::from_secs(1);
        }
        store.issue(unlock()).expect("capacity is back");
    }
}
