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
    /// 3-stage borrow (DR-0024 §8):
    /// 1. cap-gated raw read で seed を `Vec<u8>` working buffer にコピー (= `&mut Store` 借用を解放)
    /// 2. `definition_of` で meta を読む (= 不変借用)
    /// 3. TOTP derive (CPU 計算のみ、Store 借用なし)
    pub fn get_code<C: Clock>(
        &self,
        store: &mut Store,
        key: &str,
        clock: &C,
    ) -> Result<String, OtpError> {
        // stage 1: cap-gated raw read → owned bytes
        let seed_bytes: Vec<u8> = {
            let secret = store
                .get(key, &self.store_cap, clock)
                .map_err(OtpError::Cap)?
                .ok_or(OtpError::NoValue)?;
            secret.expose_secret().to_vec()
        };

        // stage 2: definition meta (= 不変借用、cap 不要)
        let meta = store
            .definition_of(key)
            .map(|d| d.meta().clone())
            .unwrap_or_default();

        // stage 3: derive
        otp_type::derive_code(&seed_bytes, &meta).map_err(OtpError::Derive)
    }
}
