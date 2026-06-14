use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone)]
pub struct Capability {
    pub(crate) token: u128,
}

// N1: Debug を手書きし token を出さない。
impl std::fmt::Debug for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capability").finish_non_exhaustive()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    KeyMismatch,
    Unknown,
}

impl std::fmt::Display for CapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapError::KeyMismatch => write!(f, "capability does not match this store"),
            CapError::Unknown => write!(f, "store has no registered capability"),
        }
    }
}

impl std::error::Error for CapError {}

// N8: token = (random offset << 64) | atomic counter。
// process-start に 1 度だけ random offset を `getrandom` で取り、以降は
// atomic counter で増やす。random 部分が process 間予測を困難に、atomic 部分が
// 同一 process 内重複を避ける。`Capability` 構築は process-start に 1 回限り
// (= startup orchestration の cost) なので、`getrandom` の syscall コストは
// 無視できる。
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn process_random_offset() -> u64 {
    use std::sync::OnceLock;
    static OFFSET: OnceLock<u64> = OnceLock::new();
    *OFFSET.get_or_init(|| {
        let mut buf = [0u8; 8];
        // getrandom 0.2 は std + libc に乗る薄い wrapper (= rand crate の依存元、
        // DR-0005 zeroize / DR-0006 libc と同列の意図的最小依存追加)。
        // syscall 失敗時 (= /dev/urandom 不在の極端なコンテナ等) は startup を
        // panic で止める: predictable token で動き続けるよりは fail-fast が筋。
        getrandom::getrandom(&mut buf)
            .expect("cache_warden::capability: OsRng unavailable at startup");
        u64::from_le_bytes(buf)
    })
}

pub(crate) fn fresh_process_local_token() -> u128 {
    let high = process_random_offset() as u128;
    let low = COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    (high << 64) | low
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_unique_across_calls() {
        // counter が都度増えるため、2 回呼ぶと必ず異なる値になる
        let t1 = fresh_process_local_token();
        let t2 = fresh_process_local_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn clone_preserves_token() {
        let cap = Capability {
            token: fresh_process_local_token(),
        };
        let cloned = cap.clone();
        assert_eq!(cap.token, cloned.token);
    }

    #[test]
    fn capability_debug_does_not_leak_token() {
        let cap = Capability {
            token: fresh_process_local_token(),
        };
        let debug_str = format!("{:?}", cap);
        // token の 16 進数表現が Debug 出力に現れないことを確認
        let token_hex = format!("{:x}", cap.token);
        assert!(
            !debug_str.contains(&token_hex),
            "Debug output should not contain token hex: debug={debug_str:?}, token_hex={token_hex:?}"
        );
        // token の 10 進数表現も同様
        let token_dec = format!("{}", cap.token);
        assert!(
            !debug_str.contains(&token_dec),
            "Debug output should not contain token decimal: debug={debug_str:?}, token_dec={token_dec:?}"
        );
    }

    #[test]
    fn cap_error_display_does_not_panic() {
        // Display が文字列を返すことを確認 (panic しないこと)
        let key_mismatch = format!("{}", CapError::KeyMismatch);
        assert!(!key_mismatch.is_empty());
        let unknown = format!("{}", CapError::Unknown);
        assert!(!unknown.is_empty());
    }
}
