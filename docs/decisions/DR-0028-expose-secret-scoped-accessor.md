# DR-0028: 秘密値プレーンテキストの scope 限定アクセサ（`with_exposed`）と `expose_secret` の非公開化

- Status: Accepted
- Date: 2026-07-06

## Context

DR-0024（capability-based access gate）は「誰が `&SecretBytes` を借りる権利を持つか」を
cap で構造的に閉じたが、その射程外に 2 つの穴を残し、Open Questions Q11 / Q12 として
別 issue に切り出していた:

- **Q11 / issue `2026-06-14-expose-secret-allowlist.md`**: cap gate を通過した後、
  `SecretBytes::expose_secret(&self) -> &[u8]` は cap と独立に呼べる。cap gate 通過後の
  adapter 内部で戻り値が誤って log / stderr / owned buffer へ流れる経路は convention
  にしか守られていない。
- **Q12 / issue `2026-06-14-finish-get-working-buffer-zeroize.md`**: `finish_get` /
  `OtpAdapter::get_code` は `secret.expose_secret().to_vec()` で seed / value を
  owned `Vec<u8>` working buffer にコピーする。`Vec<u8>` は drop で zeroize されず、
  解放後も process memory に平文が残る。これは DR-0007（mlock）/ DR-0016（OTP seed
  write-only）の意義を半減させる。

2 つの issue の推奨案（Q11 案 C = `with_exposed` クロージャ API / Q12 案 B = 同）は
**同一の core API に収束する**。issue 本文自身がこの統合を明記していた。本 DR は両者を
1 つの決定として land する。

`expose_secret` / `with_exposed` は core crate `cache-warden` の公開型 `SecretBytes` の
API surface に属するため、変更は library consumer に可視 → DR 化する（pre-1.0 の
breaking minor bump）。

## Decision

### 1. `SecretBytes::with_exposed<F, R>(&self, f: F) -> R` を唯一の平文アクセサにする

```rust
pub fn with_exposed<F, R>(&self, f: F) -> R
where
    F: FnOnce(&[u8]) -> R,
{
    f(&self.data)
}
```

- `&[u8]` は closure の生存期間だけ有効。生の平文を **caller-owned な buffer へ move
  できない**（closure を抜けたら borrow は消える）。
- closure の外に出るのは戻り値 `R` だけ。caller が **派生値**（base64 文字列 / TOTP code /
  署名 blob）を返せば、seed 自身は決して外に残らない。
- `with_exposed` は pinned + zeroize-on-drop な backing buffer を借りるだけで **自前の
  コピーを一切作らない**。よって後始末（zeroize）すべき中間バッファが存在しない。

### 2. `expose_secret` を非公開化（`#[cfg(test)] pub(crate)`）

```rust
#[cfg(test)]
pub(crate) fn expose_secret(&self) -> &[u8] {
    &self.data
}
```

- production / adapter コードからの平文読み出しは **例外なく `with_exposed` 経由**。
  非 test の呼出点はゼロ。
- `#[cfg(test)]` にすることで、core crate 自身の unit test だけが
  `assert_eq!(s.expose_secret(), b"...")` の簡潔なアサーションを書ける（closure で
  全アサーションを包む冗長化を避ける）。public API surface には raw `&[u8]` を得る
  手段が残らない。

### 3. adapter 全呼出点を `with_exposed` へ変換

| 呼出点 | before | after |
|---|---|---|
| `handler.rs::finish_get`（opaque path） | `expose_secret().to_vec()` → base64 | `with_exposed(\|b\| Response::get(encode_b64(b)))` |
| `otp_adapter.rs::get_code` | `expose_secret().to_vec()` → derive | meta を先に clone → `with_exposed(\|seed\| derive_code(seed, &meta))` |
| `authsock.rs::build_registry` | `expose_secret()` → PEM parse | `with_exposed(\|b\| register_from_pem(...))` |
| `authsock.rs`（SIGN_REQUEST 署名） | `expose_secret()` → sign | `with_exposed(\|b\| sign(...))` |

`otp_adapter::get_code` は借用順を入れ替える: `definition_of` の meta を先に clone して
不変借用を解放してから、`store.get`（`&mut self`）→ `with_exposed` 内で derive する。
これで seed working buffer（owned `Vec<u8>`）が消滅する。

### 4. Q12 zeroize は「Zeroizing で包む」でなく「そもそも owned buffer を作らない」で解く

`finish_get` / `get_code` の `Vec<u8>` working buffer は **構造的に消滅**する（closure 内で
base64 化 / derive するため owned コピーが生まれない）。zeroize すべき中間バッファが
存在しないので、`Zeroizing<Vec<u8>>` でラップするより強い保証になる。

## Alternatives（不採用）

- **Q12 案 A: `Zeroizing<Vec<u8>>` で working buffer を包む**。コピー自体は残り、
  `Vec` reallocation 時に旧 buffer が zeroize されない制約を将来 path に負わせる。
  「そもそもコピーを作らない」本 DR の方が保証が強く、制約も残さない。
- **Q11 案 A 単独: `expose_secret` を `pub(crate)` のまま（`with_exposed` なし）**。
  cli crate は別 crate なので `pub(crate)` でも呼べなくなり、結局 helper API が必要。
  `with_exposed` を提供する本 DR がその helper。
- **Q11 案 B: feature flag gating**。monolithic（crate 全体で opt-in）で per-module の
  細かい制御ができない。
- **Q11 案 D: clippy custom lint / rustdoc JSON diff で CI 検出**。API は触らず CI 依存。
  本 DR は `expose_secret` の非公開化で **crate 境界のコンパイル時保証**にした（lint
  pipeline の保守不要）。
- **`with_exposed` の戻り値に `R: !Copy` / zeroize-aware 制約を今かける**。`s.with_exposed(\|b\| b.to_vec())`
  で再コピーする抜け道は塞げるが、現時点の呼出点は全て派生値を返すので過剰。将来
  必要になれば型制約を足せる余地として残す（issue 本文の段階的計画に整合）。

## Consequences

- **breaking minor bump**: `SecretBytes::expose_secret` が public でなくなる。core crate を
  依存する外部 consumer は `with_exposed` に移行する必要がある（pre-1.0 なので minor）。
- **allowlist がコンパイル時保証になる**: crate 外から raw `&[u8]` を得る手段が構造的に
  存在しない。DR-0024 の cap gate（誰が借りるか）+ 本 DR（借りた先の bytes がどこへ行くか）で
  raw secret の流れが閉じる。
- **残る owned コピー（本 DR scope 外）**: authsock の署名 path は closure 内で
  `String::from_utf8_lossy` → PEM parse を行い、PEM 文字列 / parse 済み鍵は依然 owned。
  これは署名処理に内在するコピーで、本 2 issue の射程（`expose_secret` allowlist +
  handler/otp working buffer）外。将来 hardening 余地として残す。
- **将来余地**: `with_exposed` の戻り値 `R` を `b.to_vec()` で再コピーする抜け道は型では
  塞いでいない（§Alternatives 末尾）。必要になれば `R` 制約を追加できる。

## 関連

- DR-0024（cap access gate）— Q11 / Q12 を本 DR / 2 issue に委譲した親決定。§8 の
  `OtpAdapter` 独立化を前提にする。
- DR-0007（mlock memory pinning）/ DR-0016（OTP seed write-only）— working buffer の
  zeroize を整合させる動機。
- DR-0005（zeroize crate 採用）— zeroize 方針の基盤（本 DR は Zeroizing を使わず構造で解く）。
- issue `2026-06-14-expose-secret-allowlist.md` / `2026-06-14-finish-get-working-buffer-zeroize.md`
  — 本 DR が解決する 2 issue。
