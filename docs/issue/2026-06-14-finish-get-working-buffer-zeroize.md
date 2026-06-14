# `finish_get` working buffer (`Vec<u8>`) の zeroize 整合

- status: open / 設計未確定 (= DR-0024 と独立だが併走検討)
- 記録: 2026-06-14 (= DR-0024 cap-access-gate 起草時に Critical adversarial review で析出した「mlock 半減 path」)
- 関連: **DR-0024 (capability-based access gate L1、本 issue の親、Open Q Q12)** / DR-0007 (mlock memory pinning、本 issue の動機) / DR-0016 (OTP value type、seed bytes が `Vec<u8>` に copy される path) / DR-0005 (zeroize crate の依存採用)

## 問題

`crates/cache-warden-cli/src/daemon/handler.rs::finish_get` (L460-L476) は **OTP / opaque 両 path で `secret.expose_secret().to_vec()` を行う**:

```rust
fn finish_get<C: Clock>(store: &mut Store, key: &str, dry_run: bool, ...) -> Response {
    let value = match store.get(key, clock) {
        Some(secret) => secret.expose_secret().to_vec(),  // ← Vec<u8> working buffer
        None => return Response::error(/* ... */),
    };
    // value は Vec<u8>。OTP path では derive_code(&value, ...) に渡す。
    // opaque path では encode_b64(&value) に渡す。
    // value の drop で zeroize は走らない (= Vec<u8>::drop は zero 化しない)。
}
```

DR-0024 で OTP adapter が独立化しても、構造は同じ (= seed を `Vec<u8>` working buffer にコピー → derive → drop)。

**問題の本質**: `Vec<u8>` は drop で zeroize されない。`value: Vec<u8>` が scope を抜けると allocator に返却されるが、bytes は **process memory 上に残る**。次の allocation で上書きされるまで読み出し可能。

これは:

- **DR-0007 mlock の意義を半減させる**: mlock で `SecretBytes` の内側 buffer は swap に出ない / drop で zeroize される、が、`expose_secret().to_vec()` で作った Vec は mlock 対象外 + drop で zero 化されない = swap される可能性あり + 解放後 memory に残る。
- **DR-0016 OTP seed の "write-only" 性質を半減させる**: seed は core から出ないはずだが、handler が `to_vec()` した時点で seed bytes は handler の Vec に複写される。derive 後 drop されても zero 化されないので、process memory dump で seed が読み出せる。
- **DR-0024 cap gate の射程外**: cap gate は「誰が `&SecretBytes` を borrow できるか」を閉じるが、`Vec<u8>` への copy 後の lifecycle は閉じない。

## 動機

DR-0024 が cap gate を入れる同タイミングで、cap gate 通過後の **`Vec<u8>` working buffer**の zeroize を整合させる動機がある。理由:

1. DR-0024 で `handler.rs::finish_get` を書き換える (= OTP 分岐を `OtpAdapter::get_code` に移す)。そのタイミングで `Vec<u8>` 周辺の lifecycle も同時に整理するのが最小コスト。
2. DR-0007 (mlock) と DR-0016 (OTP write-only) の意義を半減させたままで DR-0024 を land すると、cap gate の効果が convention 依存になり、レビュー価値が下がる。
3. 修正は handler / OTP adapter 内部に閉じる (= `Store` API は触らない) ので、本 issue を別 PR で並行 land できる。

## 案

### 案 A: `zeroize::Zeroizing<Vec<u8>>` で working buffer を包む

```rust
use zeroize::Zeroizing;

let value: Zeroizing<Vec<u8>> = Zeroizing::new(secret.expose_secret().to_vec());
// derive_code(&value, ...) や encode_b64(&value) に渡す。
// value の drop で Vec<u8> の内容が zeroize される。
```

利点:

- `zeroize` crate は DR-0005 で既に依存。新規 dep 追加なし。
- 変更箇所が局所的 (= `to_vec()` 呼出を `Zeroizing::new(... .to_vec())` に書き換えるだけ)。

懸念:

- `Vec::push` / `Vec::extend` で reallocation が起きると古い buffer は zeroize されない (= `Zeroizing<Vec<u8>>` の制約)。`finish_get` の path では push しないので問題なしだが、将来 path 追加時に注意点が増える。
- 実装時に「`Vec` reallocation が起きない pattern」をレビュー基準として明示する必要がある。

### 案 B: `SecretBytes::with_exposed<F, R>(&self, f: F) -> R` で scope 限定 borrow

```rust
impl SecretBytes {
    pub fn with_exposed<F, R>(&self, f: F) -> R where F: FnOnce(&[u8]) -> R {
        f(self.expose_secret())
    }
}
```

`finish_get` を closure で書き換える:

```rust
let response = secret.with_exposed(|bytes| {
    if dry_run { Response::get_verified(state) }
    else { Response::get(encode_b64(bytes)) }
});
```

利点:

- そもそも `Vec<u8>` を作らない。`&[u8]` を closure 内で使い、closure を抜けたら何も残らない (= `&SecretBytes` の borrow scope に閉じる)。
- 別 issue `2026-06-14-expose-secret-allowlist.md` の案 C と統合する余地。raw bytes の取り出し allowlist と zeroize 整合が 1 つの API で両立する。

懸念:

- closure 化で borrow checker が厳しくなる (= store borrow と closure 内 borrow の干渉)。OTP adapter (= 2 stage borrow) との整合を確認する必要。
- API 変更が大きい (= `SecretBytes` public API 追加)。

### 案 C: handler 側で手動 `zeroize::Zeroize::zeroize(&mut value)` を drop 直前に呼ぶ

```rust
let mut value: Vec<u8> = secret.expose_secret().to_vec();
let response = /* derive / encode using &value */;
zeroize::Zeroize::zeroize(&mut value);
// drop(value)
return response;
```

利点:

- 既存構造に手を入れる量が最小。
- 失敗 path (= `return Response::error(...)` の early return) では zeroize されないが、early return 時は `value` がそもそも生成されていない (= match arm で分岐) ので問題なし。

懸念:

- `panic!` や `?` による early return で zeroize が漏れる。`Zeroizing` (案 A) の方が drop guard として確実。
- 手動 zeroize は呼び忘れが起きやすい。コードレビューでの検出に頼る。

### 案 D: scope 外、対応しない

- DR-0007 mlock は SecretBytes の内側 buffer に対する保護で、working buffer 経由の copy は本来 hardening 対象外、と整理。
- ただし「cap gate を入れたのに working buffer は zero 化されない」は inconsistency として残る。

## 推奨

**案 A (`Zeroizing<Vec<u8>>`)** を第一候補にする。理由:

- 変更コスト最小 (= `to_vec()` 呼出だけ書き換え)。
- DR-0005 で `zeroize` 既に依存、追加なし。
- `Vec` reallocation 制約は `finish_get` の path では問題にならない。

案 B (`with_exposed`) は別 issue `2026-06-14-expose-secret-allowlist.md` の案 C と統合検討時に再評価する。両 issue を統合的に解決する DR を起こす場合は案 B 路線。

## DR-0024 との関係

本 issue は **DR-0024 の scope 外**。理由:

- DR-0024 は raw read API の cap-gated 化が主、working buffer の zeroize は cap gate の射程外。
- DR-0024 の handler 書き換えと並行 PR で進めると、`finish_get` の merge conflict が起きやすい。順序としては DR-0024 land → 本 issue follow-up PR の順を推奨。
- 修正は `crates/cache-warden-cli/src/daemon/handler.rs` + `crates/cache-warden-cli/src/daemon/otp_adapter.rs` (DR-0024 新規 module) に閉じる。`Store` API は touch しない。

DR-0024 land 後の dogfood で「mlock 半減 path が本当に脅威モデル内か」を改めて評価し、本 issue を実装着手 or `pending-sublimation` で close か判断する。

## 次のアクション

1. DR-0024 が land したらこの issue を re-evaluate。
2. `handler.rs::finish_get` の OTP / opaque 両 path で `to_vec()` を `Zeroizing::new(... .to_vec())` に書き換える PR を起こす。
3. OTP adapter (= DR-0024 §8 で新設) の `get_code` 内部 `seed_bytes` も同様に `Zeroizing` で包む。
4. テスト: `Vec` reallocation が起きない code path であることを実装で担保 (= push / extend を使わない)、CI で lint。
5. process memory dump test は本 issue scope 外 (= release blocker でない)、future hardening の余地として残す。
