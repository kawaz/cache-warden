//! OTP adapter (DR-0024 §8).
//!
//! Handler から OTP TOTP math を抜き、cap-gated raw read + meta read + derive の
//! 3-stage borrow に分離した独立 adapter object。
//! DR-0016 schema (= value type metadata は definition、core は OTP を知らない) を維持。

use cache_warden::{Capability, Clock, Store};

use crate::otp_type;

/// OTP adapter: handler から呼ばれ、cap-gated raw read で seed を取り出して TOTP code を導出する。
///
/// adapter は内部で `Arc<Mutex<Store>>` を持たない (deadlock 回避、DR-0024 §8 N6)。
/// caller (handler) が既に store lock を保持してる前提で、`store: &mut Store` を
/// call ごとに引数で受ける。
pub struct OtpAdapter {
    store_cap: Capability,
}

#[derive(Debug)]
pub enum OtpError {
    Cap(#[allow(dead_code)] cache_warden::CapError),
    NoValue,
    Derive(String),
}

impl std::fmt::Display for OtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // 外部応答では token / key を漏らさない
            OtpError::Cap(_) => write!(f, "internal cap mismatch"),
            OtpError::NoValue => write!(f, "no value for otp key"),
            OtpError::Derive(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for OtpError {}

impl OtpAdapter {
    pub fn new(store_cap: Capability) -> Self {
        Self { store_cap }
    }

    /// Derive a TOTP code from the seed cached under `key`.
    ///
    /// Borrow order (DR-0024 §8 / DR-0028):
    /// 1. `definition_of` で meta を読み clone (= 不変借用、cap 不要、この時点で借用解放)
    /// 2. cap-gated raw read → `with_exposed` closure 内で TOTP derive
    ///
    /// seed は `with_exposed` の closure scope に閉じ込められ、owned `Vec<u8>` に
    /// 複写されない (DR-0028)。process memory に残る un-zeroize な seed working
    /// buffer が生まれないので DR-0007 mlock / DR-0016 write-only の意義を保つ。
    /// closure を抜けるのは派生した TOTP code だけ (= seed 自身は出ない)。
    pub fn get_code<C: Clock>(
        &self,
        store: &mut Store,
        key: &str,
        clock: &C,
    ) -> Result<String, OtpError> {
        // step 1: definition meta を先に owned 化 (不変借用を解放してから step 2 の
        // `&mut` 借用に入る)。
        let meta = store
            .definition_of(key)
            .map(|d| d.meta().clone())
            .unwrap_or_default();

        // step 2: cap-gated read → closure 内で derive。seed は closure の外に出ない。
        let secret = store
            .get(key, &self.store_cap, clock)
            .map_err(OtpError::Cap)?
            .ok_or(OtpError::NoValue)?;
        secret
            .with_exposed(|seed| otp_type::derive_code(seed, &meta))
            .map_err(OtpError::Derive)
    }
}
