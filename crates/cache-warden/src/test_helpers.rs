//! Test helpers for cache-warden core. Available in `#[cfg(test)]` and under
//! the `test-support` feature for external test crates (cli e2e tests).
use crate::capability::Capability;
use crate::store::{Store, StoreBuilder};

pub fn store_with_cap() -> (Store, Capability) {
    let b = StoreBuilder::new().build();
    (b.store, b.control_cap)
}

pub fn store_with_cap_and_backoff(d: std::time::Duration) -> (Store, Capability) {
    let b = StoreBuilder::new().failure_backoff(d).build();
    (b.store, b.control_cap)
}
