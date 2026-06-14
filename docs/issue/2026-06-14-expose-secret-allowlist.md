# `SecretBytes::expose_secret` 呼出点の allowlist 化

- status: open / 設計未確定 (= DR-0024 と独立だが併走検討)
- 記録: 2026-06-14 (= DR-0024 cap-access-gate 起草時に Critical adversarial review で析出した「cap gate の射程外の穴」)
- 関連: **DR-0024 (capability-based access gate L1、本 issue の親、Open Q Q11)** / DR-0007 (mlock memory pinning、本 issue の動機) / DR-0016 (OTP value type、`expose_secret` 経由で seed が handler に出ている path)

## 問題

DR-0024 で `Store::get(key, cap, clock) -> Result<Option<&SecretBytes>, CapError>` を導入し、raw value 読み出しを cap 必須にする。これは「**誰が `&SecretBytes` を借りる権利を持つか**」を構造的に閉じる。

しかし `SecretBytes::expose_secret(&self) -> &[u8]` は cap と独立に呼べる:

```rust
// cap gate を通過した後に、その &SecretBytes に対して
let secret: &SecretBytes = store.get(key, &cap, &clock)?.unwrap();
let raw_bytes: &[u8] = secret.expose_secret();
// ↑ ここから先は cap が関与しない。
// この &[u8] が log / stderr / Vec<u8> へ流れる経路は構造的に制限されてない。
```

= cap gate 通過後の adapter 内部で `expose_secret` の戻り値が誤って外部に流れる経路 (= `eprintln!`、`tracing::info!`、`Vec<u8>::extend_from_slice` 経由の意図せぬ persist) は **convention にしか守られていない**。

具体例:

- `crates/cache-warden-cli/src/daemon/handler.rs::finish_get` の L465 `secret.expose_secret().to_vec()` は cap gate 通過後の path、ただし `Vec<u8>` への copy 後の lifecycle は明示制御されていない (= 別 issue `2026-06-14-finish-get-working-buffer-zeroize.md` で別軸の問題として扱う)。
- 将来 adapter が増えたとき、`expose_secret` を「raw bytes が必要だから」と呼んで結果を加工する path が暗黙に増えていく risk。

## 動機

DR-0024 が cap gate で **「誰が `&SecretBytes` を取れるか」** を閉じても、`expose_secret` で **「`&SecretBytes` から先の bytes が誰に渡るか」** は閉じない。`expose_secret` を呼ぶ正当な場所は handler (= base64 化 / OTP derive 等) と OTP adapter に限定されるはずで、それ以外の場所からの呼出は実装 drift。

cap gate を入れる同タイミングで `expose_secret` allowlist を入れると、「raw bytes が `cache-warden-cli` 内部の限定 module だけから取り出される」が構造的に保証され、DR-0024 の射程が完成する。

## 案

### 案 A: `expose_secret` を `pub(crate)` にして allowlist module からのみ呼ぶ

```rust
// crates/cache-warden/src/secret.rs

impl SecretBytes {
    pub(crate) fn expose_secret(&self) -> &[u8] { /* ... */ }
}
```

- cache-warden core crate 内部からのみ呼べる。
- 既存呼出 (= `handler.rs::finish_get`, OTP adapter, authsock の sign path) は cache-warden-cli crate 配下なので、これらが `expose_secret` を呼ぶには core 経由の helper API (= `with_exposed<F>(&self, f: F)` 等) が必要になる。

懸念: cli crate 全部から呼べてしまうと allowlist の効果が薄い (= 同一 crate 内なら自由に呼べる)。

### 案 B: `expose_secret` を `pub` のまま + `#[cfg(feature = "expose-secret-for-adapter")]` で gating

- 通常 feature では `expose_secret` 不可、明示 feature flag で adapter ごとに opt-in。
- crate dependency 側で feature を有効化する必要があり、unintended exposure を flag で検知できる。

懸念: feature flag が monolithic (= 一度有効化すると crate 全体で呼べる)、per-module の細かい gating はできない。

### 案 C: `SecretBytes::with_exposed<F, R>(&self, f: F) -> R where F: FnOnce(&[u8]) -> R`

```rust
impl SecretBytes {
    pub fn with_exposed<F, R>(&self, f: F) -> R where F: FnOnce(&[u8]) -> R {
        let bytes = /* internal access */;
        let result = f(bytes);
        // optionally zeroize the buffer here
        result
    }
}
```

- caller は closure 内でしか `&[u8]` を持てない (= scope 限定 borrow)。
- 結果 `R` だけ closure の外に出る = `R: !Copy + zeroize-aware` 制約をかけられる将来余地。
- `expose_secret` の戻り値を生で持ち回す path を構造的に作れない。
- 別 issue `2026-06-14-finish-get-working-buffer-zeroize.md` (= `Vec<u8>` working buffer zeroize) と統合する余地が高い (= `with_exposed` 内部で buffer zeroize を一括処理)。

### 案 D: rustdoc JSON / clippy custom lint で外部 caller を検出

- API は touch しない、CI で lint。
- 早く入れられる、ただし build pipeline の保守が増える。

## 推奨

**案 A + 案 C の合成**を推奨:

1. `SecretBytes::expose_secret` は `pub(crate)` 化 (= core crate 外からは呼べない)。
2. core crate が `SecretBytes::with_exposed<F, R>(&self, f: F) -> R` を public 提供。adapter は closure 経由でしか `&[u8]` を取れない。
3. CI で「`expose_secret` の呼出点リスト」を rustdoc JSON 経由で diff、新規呼出は PR review で評価。

これにより cap gate (= DR-0024) + raw bytes 取り出し allowlist (= 本 issue) + working buffer zeroize (= 別 issue) の 3 層で raw secret bytes の流れが構造的に閉じる。

## DR-0024 との関係

本 issue は **DR-0024 の scope 外**。理由:

- DR-0024 は「raw read API を cap-gated にする」が主、`expose_secret` の呼出制限は別軸で型 API surface の変更を伴う。
- DR-0024 を land した後、dogfood で「`expose_secret` 呼出点が実装 drift しがちか」を観察してから方針確定したい。
- 案 A-D のどれを採るかは DR-0007 (mlock) / DR-0016 (OTP) との整合も含めて改めて DR 化が筋良い (= DR-0024 の subsection に詰め込むと scope 肥大)。

DR-0024 land 後の dogfood で「cap gate を入れたら expose_secret 呼出が予期せず log に出ていた」のような事例が観測されたらフォローアップとして DR 起票候補にする。

## 次のアクション

1. DR-0024 が land したらこの issue を re-evaluate。
2. dogfood で `expose_secret` 呼出点の現状 audit (= rustdoc JSON で path リスト出力 + 各 path のレビュー)。
3. 案 A-D の評価を加えて DR-0027 候補として起票するか決定。
4. 不要なら本 issue を `pending-sublimation` で close。
