# DR-0024: capability-based access gate (L1)

- Status: Accepted (2026-06-14)
- Related: DR-0003 (core / adapter 責務分離、本 DR の動機) / DR-0010 (re-auth command、cap 判定との順序) / DR-0011 (TTL 2 分離 + pin、本 DR で pin 系も cap 必須化) / DR-0012 (process access policy、本 DR と直交軸) / DR-0014 (entries / definitions 分離、第 4 マップ追加の前例) / DR-0016 (OTP value type、ValueMeta 維持) / DR-0018 (typed sources、SourceMeta との独立性) / DR-0022 (failure_backoffs 第 3 マップの同型 pattern)

## Context

cache-warden の core (`crates/cache-warden`) は DR-0003 で「秘密値の secure KV cache」と定義され、control socket / authsock / OTP は core の上に乗るアダプタである、と整理された。しかし現行実装ではこの境界が **構造的に強制されていない**。

具体的には `Store::get(&mut self, key, clock) -> Option<&SecretBytes>` が public API として存在する (`crates/cache-warden/src/store.rs:162`)。handler 層には DR-0012 の key-level process gate、DR-0015 の dry-run、DR-0016 の OTP seed → code 変換などの adapter 固有 semantics が積まれているが、同じ process 内の別コードが `Store::get` を直接呼べばすべて bypass できる。これは「raw getter が public のままだと、adapter 境界の意味論はレビュー規約でしか守られない」状態である。

本 DR の起点は `docs/issue/2026-06-14-internal-key-forget-interface.md`。dogfood で `__authsock_op:zl4...` 型の「user 面から見えない / forget できない adapter 内部 key」が観測され、そこから「`StoreKey` newtype で入力面を塞ぐ」案が出た。しかしレビュー過程で「入力面を塞いでも、`Store::get` が public なら **どの adapter がどのキーを触る権利を持つか** は表現できない」と判明し、権限軸への一般化として **capability-based access gate** が浮上した。

DR-0014 で定義と値を分離し、DR-0016 で OTP seed を write-only とし、DR-0018 で authsock 内部鍵を専用 namespace に寄せるほど、秘密値を読む経路は adapter ごとの意味論を帯びる。それにもかかわらず raw getter が public のまま残ると、これらの DR の積み重ねが convention に依存してしまう。capability は convention を API surface に押し上げ、**core 出口判定 + adapter 入口判定** の責務境界を grep 可能にする。

設計の出発点として、独立 draft 2 件 (Opus 案 / Codex 案) と比較レビューを経て、kawaz が以下 4 件を裁定した:

| 裁定 | 結果 | 影響範囲 |
|---|---|---|
| 1. cap の粒度 | **per-Store** (= 1 daemon 1 cap、adapter 名は label のみ) | API surface、Builder 形、handler の lookup cost |
| 2. `define` の cap | **不要** (= value-free metadata) | authsock A-3a の startup orchestration |
| 3. OTP adapter の独立 | **本 DR に含める** (= handler::finish_get の OTP 分岐を adapter object として独立化) | DR-0024 scope の大きさ |
| 4. `Store::new()` の扱い | **`pub(crate)` 即削除** (= `Store::builder()` canonical 化、breaking minor bump) | library consumer 影響、test fixture 数 |

これらは Decision の各 subsection で反映される。

本 DR は L1 として、**同一 process 内** での capability-based access gate を導入する。これは暗号的な分離ではない。Rust の型・module 境界を使った「意図しない bypass を構造的に起こしにくくし、レビューで見つけやすくする」ための設計である。L2 (per-key scoped cap / cap chain) / L3 (IPC 越し remote attestation) は本 DR の射程外で、enum variant 拡張余地のみ確保する。

## Decision

### 1. capability の概念と粒度 (= 裁定 1)

**`Capability` は 1 つの `Store` に対する access token**。daemon は startup 時に **単一の `Capability` を mint**し、それを必要な数だけ `clone` して各 adapter (= control socket handler / authsock listener / OTP adapter) に配る。adapter 名は self-document のためのラベルでしかなく、access 制御の本体は token equality である。

per-Store 採用の根拠:

- L1 の主問題は「public raw getter による意図せぬ bypass」。per-Store cap で十分に塞げる。
- per-key cap (= 1 値 1 cap) は実質 L2 (scoped cap / 最小権限) の早すぎる導入になる。lookup cost (= `BTreeMap<key, Arc<Cap>>` の handler hot path) を払いながら、得られる安全性は「同一 daemon 内の adapter が互いの key を触れない」だけで、本 DR の目的に対して overengineering。
- adapter ごとに最小権限の差を表現する必要が出たら、L1.5 (= scoped cap) を後続 DR として独立に検討できる (= 構造的拡張余地は確保、§Open Questions Q1)。
- per-Store の場合「authsock cap も OTP cap も同じ token の clone」となるが、これは自己整合: cap は core 出口の機械判定であり、「どの adapter がどの key の値を扱ってよいか」は handler dispatch (= adapter wiring) の責務。core と adapter の責務境界 (DR-0003) を最も素直に表現する。

### 2. `Capability` 型 (= 裁定後の最終形、N1 / N8 反映)

`Capability` は process-local equality token (`token: u128`) を 1 つ持つ struct で、`Clone` のみ実装する。要点:

- **token は `getrandom` 由来 random 64bit + `AtomicU64` counter の合成 u128**。process-local equality として十分で、test 環境で `0` などの predictable value にもならない (= 詳細は §Implementation Notes §1)。
- **`Debug` は手書き** (N1): `#[derive(Debug)]` だと `tracing::warn!("{cap:?}")` / `panic!("{cap:?}")` で token が log に流れる。token は秘密ではないが、log 経由で外部に出すべきものでもない (= 手書き impl も §Implementation Notes §1)。
- **`Copy` を採らない**: 「複製が無料、痕跡なし」になり、Rust の所有権モデルが提供する move/borrow trace が無効化される。`Clone` のみで grep 可能な複製点を維持する。
- **`_private: ()` field は採らない** (撤回 2): 将来 enum 化 (= L3 で `enum Capability { L1(...), Remote(...) }`) を妨げる。`pub(crate)` field で外部 construct 防止は十分。
- **`unsafe { std::mem::transmute }` での forge は防がない** (= type system の限界、Trade-off §Limits)。

`CapError` は 2 variant のみ:

- `KeyMismatch`: 別 `Store` の cap を渡したとき / メモリ改竄が起きたとき。production daemon paths では adapter wiring の bug でのみ起きる。
- `Unknown`: `Store` に access token が registered されていない状態 (= 内部 helper 経路でのみ起こる、production では発火しない)。

`Revoked` variant は採らない (= L2 予約、撤回 3、`no-historical-noise.md` 整合)。L3 で revocation が要件化したとき variant 追加で対応する。

### 3. `StoreBuilder` (= startup-only mint の構造的保証)

```rust
// crates/cache-warden/src/store.rs

pub struct StoreBuilder {
    failure_backoff_duration: std::time::Duration,
}

pub struct StoreBundle {
    pub store: Store,
    pub control_cap: Capability,
    pub authsock_cap: Capability,
    pub otp_cap: Capability,
}

impl StoreBuilder {
    pub fn new() -> Self {
        Self { failure_backoff_duration: std::time::Duration::ZERO }
    }

    pub fn failure_backoff(mut self, d: std::time::Duration) -> Self {
        self.failure_backoff_duration = d;
        self
    }

    pub fn build(self) -> StoreBundle {
        let token = fresh_process_local_token();
        let cap = Capability { token };
        StoreBundle {
            store: Store::new_with_token(token, self.failure_backoff_duration),
            control_cap: cap.clone(),
            authsock_cap: cap.clone(),
            otp_cap: cap,
        }
    }
}
```

設計判断:

- **fixed 3-4 method**: per-Store cap なので「daemon の主要 adapter 数だけ clone を返す」で必要十分。Opus 案の動的 `capability_for(key, holder)` loop は per-key 前提の柔軟性で、per-Store では builder loop も pending list も要らない。
- **adapter 数が将来増えたら struct を拡張**: `StoreBundle` への field 追加は minor bump で済む (= pre-1.0 の許容範囲、`design-priority.md` で「後方互換を理由に曲げない」原則と整合)。
- **mint タイミングは `build()` 一発のみ**: builder は consumed (`self`)、build 後の `Store` には cap を発行する method が **存在しない**。これは Rust 型レベルの構造的保証 (= 関数を呼べないものは呼ばれない)。
- **`Store::new()` は public から消す (= 裁定 4)**: §4 で詳述。

### 4. `Store::new()` 廃止 / `Store::builder()` canonical 化 (= 裁定 4 / 撤回 4-5 / N10)

`Store::new()` は **`pub(crate)` 即削除**する。`Store::builder() -> StoreBuilder` が library consumer / daemon 両方の正規経路となる。

- **3 phase deprecation は採らない**: pre-1.0 + 外部 library consumer 未確認 (= ecosystem 検索で `cache_warden::Store` への dep 0 件) なので、deprecation window を置く意味がない。`design-priority.md` の「後方互換を理由に曲げない」原則と整合。
- **「cap なし stub store」は採らない**: `Store::new()` を残して「secret API を呼ぶと `CapError::Unknown` で fail する」状態は半死半生 API。「動くが使えない」は設計として悪い (§4 撤回理由)。
- core 内部の test では `pub(crate)` の helper (`Store::new_with_token` / `Store::for_test()` 等) を使う。`#[cfg(any(test, feature = "test-support"))]` で `cache_warden::test_helpers::store_with_cap() -> (Store, Capability)` を提供する (= §Implementation Notes §7)。

### 5. cap-gated API の signature

`Store` の secret / lifecycle に影響する API は cap を **必須**にする。command source の `key: &str` は wire / config から来る user-facing identifier であり、cap とは独立軸で残す:

```rust
impl Store {
    // ---- secret-handling API: capability-gated ----

    pub fn get(
        &mut self, key: &str, cap: &Capability, clock: &impl Clock,
    ) -> Result<Option<&SecretBytes>, CapError>;

    pub fn set(
        &mut self, key: &str, source: ValueSource, value: SecretBytes,
        ttl: Ttl, cap: &Capability, clock: &impl Clock,
    ) -> Result<(), CapError>;

    pub fn extend_authenticated(/* + cap */) -> Result<(), ExtendAuthOutcome>;
    pub fn regenerate(/* + cap */) -> Result<(), RegenerateOutcome>;
    pub fn get_or_regenerate(/* + cap */) -> Result<(), RegenerateDefOutcome>;
    pub fn pin_authenticated(/* + cap */) -> Result<(), PinAuthOutcome>;
    pub fn unpin(&mut self, key: &str, cap: &Capability) -> Result<bool, CapError>;
    pub fn delete(&mut self, key: &str, cap: &Capability) -> Result<bool, CapError>;
    pub fn delete_with_definition(&mut self, key: &str, cap: &Capability)
        -> Result<bool, CapError>;

    // ---- value-free metadata API: NOT capability-gated ----

    pub fn define(/* no cap */) -> Result<(), DefineError>;            // 裁定 2
    pub fn define_with_meta(/* no cap */) -> Result<(), DefineError>;  // 裁定 2

    pub fn list(&self) -> Vec<&str>;
    pub fn keys(&self) -> Vec<&str>;
    pub fn is_defined(&self, key: &str) -> bool;
    pub fn has_value(&self, key: &str) -> bool;
    pub fn state_of(&mut self, key: &str, clock: &impl Clock) -> Option<EntryState>;
    pub fn source_of(&self, key: &str) -> Option<&ValueSource>;
    pub fn definition_of(&self, key: &str) -> Option<&Definition>;
    pub fn pin_deadline_of(&self, key: &str) -> Option<Monotonic>;
    pub fn failure_backoff_remaining(/* no cap */) -> Option<Duration>;
}
```

設計判断:

- **命名は `authorized_*` prefix を採らない** (= Opus 案撤回、§3 比較レビュー §4.2)。per-Store cap なので handler 側で「cap で gated な動詞 / そうでない動詞」を grep するのは prefix がなくても自明 (= secret-handling 全動詞が cap を取る = signature を見れば判る)。prefix を付けると名前が肥大化し、test 改修コストも増える。
- **`define` / `define_with_meta` は cap 不要 (= 裁定 2)**: definition は value-free metadata (DR-0014 §2)。authsock A-3a の startup orchestration では discover 完了後に op-sourced key の definition を登録するが、ここに cap を要求すると「全 schema setup が raw read 権限を持つ必要がある」= 権限過剰になる。public raw access の主脆弱性は value read であり、define はその穴ではない。
- **`set` は cap 必須**: `set` は secret 値を Store に注入する = 後段の `get` で raw read される値を作る = 上流側の生成権限を持つ adapter のみが行うべき。define (= 値を含まない設定) と set (= 値を含む注入) の責務差をここで分ける。
- **value-free metadata は変更なし**: `list` / `keys` / `state_of` / `source_of` / `definition_of` / `pin_deadline_of` / `failure_backoff_remaining` は secret を露出しないので gating する設計上の動機がない。DR-0012 (process access policy) も同じ判断 (= list は晒す、get は閉じる)、本 DR がそれに揃う。
- **`CapError` は 2 variant** (= 撤回 3): `KeyMismatch` / `Unknown` のみ。`Revoked` は L2 予約として置かない (= `no-historical-noise.md` ルール、futureproof noise)。

### 6. 判定順序 (cap → backoff → lifecycle → runner → auth) (= 比較レビュー §3.1 で「Opus 不可欠」)

`extend_authenticated` / `regenerate` / `get_or_regenerate` 内部の判定順を明文化する:

1. **cap 検証** (= 本 DR の新規 gate)
   - `cap.token == self.access_token` か。
   - 失敗 → `CapError` を返す。**runner も auth も呼ばない**。**backoff も記録しない**。
2. **failure backoff 評価** (DR-0022)
3. **entry / definition の lifecycle 評価** (`evaluate(clock)` で `EntryState::HardExpired` か等)
4. **`runner.run`** (= upstream fetch、命令にコストがかかる)
5. **`auth.authenticate`** (= DR-0010 re-auth prompt、TouchID 等の人間操作)
6. entry の install / state 更新

cap 判定が **最初**である理由:

- 不正な caller (= cap を持たない adapter) を runner / re-auth まで通すと、TouchID prompt や op CLI が走り、user が「身に覚えのない認証要求」を経験する (= attacker が cap を持たない adapter を作って TouchID spam できる、または DR-0022 backoff を消費させて DoS する)。
- cap 拒否は **upstream に何も触らない**: backoff にも記録しない (= cap 違反は user の問題ではなく adapter 実装の bug、DR-0022 の retry policy には乗せない)。

これは DR-0010 の re-auth 順序、DR-0022 の backoff 順序、本 DR の cap 順序が全部矛盾なく直列化される設計。

### 7. handler cap routing (= 信用境界、Codex Critical 反映)

handler は IPC request を受け取る地点で、どの adapter の意味論で処理しているかを **daemon 内部の構造**から知る。

候補 A: daemon が startup 時に `control_cap` / `authsock_cap` を保持し、handler が socket / listener 種別から選ぶ。

候補 B: request payload が `from_adapter: "authsock"` を持ち、handler がそれを見て選ぶ。

本 DR は **候補 A** を採用する。候補 B は unsafe: Unix socket 上の JSON request は peer が作る data であり、現在の threat model では adapter identity attestation がない。control socket に送られた `from_adapter: "authsock"` は authsock から来た証明にならない。これを信じると raw getter bypass と同種の「境界を data の自己申告に移す」失敗になる。

具体的には:

- control socket の `run_request` は CLI / control adapter 用 cap を持つ `HandlerCtx` を構築。
- authsock の `local_sign` は authsock adapter 用 cap を持つ `LocalSignCtx` を構築。
- OTP adapter は control handler の中で呼ばれる派生 view ではなく、cap を持つ **adapter object** として呼ばれる (= 次節)。

### 8. OTP adapter の独立化 (= 裁定 3 / N6 / Codex review v1 反映)

DR-0016 の現行実装では `handler.rs::finish_get` (`crates/cache-warden-cli/src/daemon/handler.rs:453`) が OTP seed を読んで TOTP code を導出する。本 DR で raw read が cap-gated になる以上、この path も cap 経由になる。さらに「OTP adapter が seed を読むには control socket 経由で `kv.get` する」と実装すると循環する (= handler が OTP key を見て OTP adapter を呼び、その adapter が control socket 経由でまた handler を呼ぶ)。

循環を切るため、OTP adapter を **in-process adapter object** として独立させる。borrow 設計は現行 `handler.rs::finish_get` (L460-L476) と同型の **2 stage borrow** (= stage 1 で seed を owned `Vec<u8>` にコピーして `&mut Store` 借用を解放、stage 2 で `definition_of` で meta を読む)。`&SecretBytes` を保持したまま `definition_of` を呼ぶ設計は Rust borrow checker で compile error になるため採らない:

```rust
// crates/cache-warden-cli/src/daemon/otp_adapter.rs (新規)

pub struct OtpAdapter {
    store_cap: Capability,
}

impl OtpAdapter {
    pub fn new(store_cap: Capability) -> Self { Self { store_cap } }

    /// Derive a TOTP code from the seed cached under `key`.
    ///
    /// Borrow plan (= 現行 `handler.rs::finish_get` と同型の 3 stage):
    /// stage 1 で `&mut Store` を借りて cap-gated raw read → seed を
    /// owned `Vec<u8>` working buffer にコピーし、block を抜けて borrow を
    /// 解放する。stage 2 で `definition_of` (= 不変借用) を呼んで meta を読む。
    /// stage 3 で TOTP derive を行う。seed の owned copy は scope を抜けた
    /// 時点で drop される (= `Vec` の zeroize は本 DR scope 外、Q12 で追跡)。
    pub fn get_code<C: Clock>(
        &self,
        store: &mut Store,
        key: &str,
        clock: &C,
    ) -> Result<String, OtpError> {
        // stage 1: cap-gated raw read → owned bytes。block scope で
        // `&SecretBytes` borrow を即解放するのが重要。
        let seed_bytes: Vec<u8> = {
            let secret = store
                .get(key, &self.store_cap, clock)
                .map_err(OtpError::Cap)?
                .ok_or(OtpError::NoValue)?;
            secret.expose_secret().to_vec()
        };

        // stage 2: borrow が解けたので definition_of (= 不変借用) を呼べる。
        let meta = store
            .definition_of(key)
            .map(|d| d.meta().clone())
            .unwrap_or_default();

        // stage 3: TOTP derive。seed_bytes は本式呼出後に drop される。
        otp_type::derive_code(&seed_bytes, &meta).map_err(OtpError::Derive)
    }
}
```

handler の `finish_get` は OTP 分岐を adapter call に差し替える。opaque path も同じ 2 stage borrow を使う:

```rust
// handler.rs finish_get の置き換え後 sketch。
// handler 側はもう TOTP math を知らない (= DR-0016 schema 維持、§Why core)。
fn finish_get<C: Clock>(
    store: &mut Store,
    ctx: &HandlerCtx<'_, /* ... */>,
    key: &str,
    dry_run: bool,
    state: &str,
) -> Response {
    // meta を先に読む (= 不変借用、cap 不要、value-free)。
    // OTP 判定で path を分岐するためだけの読み出しなので、seed には触らない。
    let meta = store
        .definition_of(key)
        .map(|d| d.meta().clone())
        .unwrap_or_default();

    if otp_type::meta_is_otp(&meta) {
        // OTP path: adapter に丸投げ。adapter 内で 2 stage borrow が走り、
        // seed working buffer は adapter scope を抜けた瞬間に drop される。
        return match ctx.otp_adapter.get_code(store, key, ctx.clock) {
            Ok(_) if dry_run => Response::get_verified(state),
            Ok(code) => Response::get(encode_b64(code.as_bytes())),
            Err(e) => Response::error(ErrorKind::BadRequest, e.to_string()),
        };
    }

    // Opaque path: 従来同様の 2 stage borrow で raw read → owned copy。
    let value_bytes: Vec<u8> = {
        let secret = match store.get(key, ctx.store_cap, ctx.clock) {
            Ok(Some(s)) => s,
            Ok(None) => return Response::error(ErrorKind::Internal, "value gone before finish_get"),
            Err(_) => return Response::error(ErrorKind::Internal, "internal cap mismatch"),
        };
        secret.expose_secret().to_vec()
    };
    if dry_run { Response::get_verified(state) } else { Response::get(encode_b64(&value_bytes)) }
}
```

設計判断 (= borrow / lock 順序の明文化):

- **2 stage borrow**: `&SecretBytes` を保持したまま `&Store` を再借用する設計 (= 比較レビュー Critical A 指摘) は Rust の borrow checker で弾かれる。seed を一度 owned `Vec<u8>` にコピーして borrow を解放してから meta を読む。これは現行 `handler.rs::finish_get` (L460-L476) と同型の構造で、移行時のリスクが小さい。
- **`OtpAdapter::get_code` は `store: &mut Store` を引数で受ける** (= N6 deadlock 対策): caller (= handler) が既に Mutex を保持している前提。OTP adapter は内部で `Arc<Mutex<Store>>` を持たない。これにより「handler が Mutex を握ったまま OTP adapter を呼ぶ」一方向の lock 関係になり、deadlock の余地がない (= lock を取り直す経路がない)。
- **lock を握る範囲は stage 1 + stage 2 の極短 window に閉じる**: stage 3 (= TOTP derive) は CPU 計算のみで Store 借用は不要。実装上は server.rs 側で `let mut store = shared.store.lock().await; ctx.otp_adapter.get_code(&mut store, ...)` の形で MutexGuard を `&mut Store` の寿命と一致させる。derive を lock 外に出したい場合は handler 側で stage 2 直後に MutexGuard を `drop` する pattern も取れる (= dogfood で lock contention を観察して実装着手時に判断)。
- **Codex 案の「OTP adapter が `Arc<Mutex<Store>>` を直接持つ」は不採用**: deadlock の余地を生むため。adapter object は cap だけ持ち、`store: &mut Store` を call ごとに引数で受ける構造に統一する。
- **seed working buffer の zeroize**: `Vec<u8>` は drop で zeroize されないので、本 DR の sketch でも seed bytes は process memory に残る (= DR-0007 mlock の意義が半減する)。これは本 DR の scope 外として Open Q Q12 / 別 issue `docs/issue/2026-06-14-finish-get-working-buffer-zeroize.md` で扱う。

これにより:

- DR-0016 の schema は維持 (metadata は definition、seed は raw value、TOTP math は OTP adapter)。
- handler は OTP math を持たず、`finish_get` の責務は「OTP / opaque の dispatch + dry-run / base64 整形」のみ。
- OTP adapter は新規 module `crates/cache-warden-cli/src/daemon/otp_adapter.rs` として独立 (= Open Questions Q2 で crate / module 配置の余地を残す)。

### 9. registry / Store の内部レイアウト (= DR-0022 第 3 マップ pattern との整合)

```rust
pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
    definitions: BTreeMap<String, Definition>,
    failure_backoffs: BTreeMap<String, FailureRecord>,
    failure_backoff_duration: Duration,
    // NEW: per-Store access token. immutable after `builder.build()`.
    access_token: u128,
}
```

DR-0014 (definitions 分離) → DR-0022 (failure_backoffs 第 3 マップ) → 本 DR (access_token) の流れ。lifecycle が独立した state を独立フィールドに置く pattern と整合する。

per-Store cap なので「`BTreeMap<CapId, ...>` の registry」は要らない。`access_token: u128` 1 個で十分 (= cap check は token equality のみ)。Opus 案の `BTreeMap<CapabilityId, RegisteredCapability>` は per-key 前提の構造で、per-Store では overengineering。

### 10. `cap` の Drop semantics と registry lifetime (= N2)

- `Capability` の Drop は **何もしない**。`access_token` 自体は `Store` 側に持つので、`Capability` の drop が「権限を返納する」semantics は持たない。
- `Store` の `access_token` は `build()` 時に決定し、`Store` の lifetime 中 **immutable**。再 mint しない、revoke しない。
- adapter が `Capability` を panic / shutdown で drop しても、`Store::access_token` には影響しない。adapter は cap を持っていないので raw read できなくなるが、process としては continue する (= 当該 adapter のみ機能停止)。
- 「Drop で registry から自動削除」のような cleanup 経路は L1 では設計しない (= 比較レビュー A2)。L2 で per-adapter scoped cap を入れる際にはこの semantics が再評価される (Open Questions Q1)。

これは「`Store` の access_token は startup 後 immutable」の明文化であり、cap 表に「holder が居ない zombie cap」のような状態を作らない構造的選択。

## Alternatives Considered

### A: L1.5 / cap chain (= delegated capabilities)

cap が上位 cap から派生する chain。例: `control_cap` から `OtpCap` を derive、`authsock_cap` が `OpSpecificCap` を derive。

不採用:

- L1 で「同一 process trust domain」と決めた以上、chain の検証は core 内に閉じる = chain policy を core が知るしかなくなる。Codex Info で固定した責務境界 (「core は出口判定まで、adapter は『どの値にどの cap が必要か』まで」) を逆侵犯する。
- L1 単一 cap で全 use case が cover できる。adapter は自分が必要な cap の clone を持てば「グループ cap」相当を表現可能。
- chain 導入は L2 (mTLS / 署名で外部主体を identify する段階) で初めて意味を持つ。in-process だけの段階で chain は overengineering。
- 本 DR の構造は L1.5 への移行を阻まない (= `Capability` を opaque token に閉じた)。chain が要件化したタイミングで別 DR として独立に検討できる。

### B: raw `Store::get` を public に維持

DR-0014 / DR-0016 の library consumer (= 想定: 将来 cache-warden を Rust library として組み込む 3rd party) のために素の getter を残す案。

不採用:

- cap gate と並走する素の getter は **全 cap 判定を無効化する近道**。bypass 経路が構造的に残ると本 DR の意味がない。
- library consumer 用途は現実には存在しない (= 現状の cache-warden は daemon binary としてのみ流通、`crates/cache-warden` を直接 depend する外部リポは ecosystem に未確認)。pre-1.0 なので breaking removal 可能。
- 「3rd party が cap 不要で使える」インターフェースを提供したいなら、`Store::builder().build().control_cap` を取り出して使えばよい = builder が canonical entry point として既に存在する。

### C: DR-0016 OTP value type schema の廃止 / 統合

OTP derivation を `Capability` 種別の discriminator に押し込む案 (= `Capability::Opaque(...)` / `Capability::OtpDerivation(...)` のタグ付き enum で、core が cap 経由で「opaque を返す or derivation を返す」を分岐)。

不採用:

- DR-0016 が「value type は **definition の永続メタ**として持つ、core は解釈しない」と確定済。これを覆すと handler 層と core 層の責務分離が破壊される (= core が TOTP 計算を知ることになる) / 既存の `ValueMeta` / `SourceMeta` の置き場が宙に浮く / DR-0014 §1 exact-match の枠が壊れる。
- cap は「誰が触れるか」の権限、value type は「どう解釈するか」の semantics で独立した軸。重ねるべきでない。

### D: cap を全 API (= value-free metadata 含む) に必須化

`Store::list` / `Store::keys` / `Store::is_defined` / `Store::status` 系にも cap を要求し、「unrestricted operator」を消す案。

不採用:

- handler 層の `kv list` / `status` を実装すると「全 key の cap を集める」loop が必要になり、cap registry を逆 lookup する API が要る (= 結局「無制限 cap」を作るのと同じ)。
- value-free metadata は secret を露出しない = bypass 価値ゼロ。gating する設計上の動機がない。
- DR-0012 (process access policy) も同じ判断 (= list は晒す、get は閉じる) を採用しており、本 DR がそれに揃うのは整合的。
- 裁定 2 (`define` も cap-free) と同じ判断軸。

### E: cap を `Arc<dyn Capability>` の trait object に

将来の L2/L3 拡張 (= mTLS / 署名付き cap) を見越して trait に抽象化する案。

不採用:

- L1 で trait object 化すると `Capability` の比較・lookup が dynamic dispatch を経由し、dual-impl の equality 判定が `Any::downcast` 頼みになる (= core の内部実装が「knows about all impls」をやり始める)。
- L1 が `Capability` 構造体 1 種で十分。L2 で別種が出てきた時点で `enum Capability { L1(...), L2(...) }` の variant 追加で対応できる (= newtype / enum の拡張余地は構造的に存在、trait object 化は今は不要)。
- 比較レビュー §3.7 の「拡張性 = Opus 優位」相当の余地は enum variant 拡張で確保。

### F: Lost-cap 永続化 (再起動跨ぎ復旧用)

cap token を state dir に書き出し、再起動後も同じ token が adapter に渡される案。

不採用:

- 永続化すると `token` が「daemon process 跨ぎで stable な識別子」になり、log / status / handoff で露出した瞬間に forge 可能な値として扱う必要が出る (= 永続 token 経由で偽 cap を作れるリスク)。
- daemon の SIGHUP-graceful-restart / DR-0021 watchdog `_exit(0)` 系経路で「cap registry も state handoff」と一緒に persist する設計余地は本 DR で封じる (= 再起動 = 新 trust session、過去 cap を信用しない)。
- L1 では「再起動 → access_token reset → adapter は新 cap で再開」で何も壊れない (= cap token は adapter 内部にしか流れない、再 mint しても外向き API は不変)。

### G: in-process token と remote attestation を 1 つの抽象に

将来の L3 (= IPC 越し adapter / リモート caller) を見越して、本 DR で cap の wire format を仮定する案。

不採用:

- L3 の「remote attestation」は構造的に別物 = 鍵交換 / 署名検証 / replay 対策が要る。in-process token (= Rust 参照渡し) と同じ抽象に乗せるのは semantic を腐らせる。
- 本 DR は in-process token に限定。L3 が要件化した時点で「opaque な authorization context」を `enum Capability { L1(L1Cap), Remote(RemoteAttestation) }` の形で別 variant 追加 = 構造的拡張余地は確保 (Open Questions Q3)。

### H: `register_adapter(&mut Store)` pattern

`Store` を作った後で mutable registration する方式。

不採用:

- 未登録期間、二重登録、テスト fixture の登録漏れを作る。
- `Store::new()` が public のまま残りやすく、capability なし Store を作る逃げ道になる。
- builder が `Store` と caps を同時に返す方が、初期化完了状態を型で表しやすい (= 起動後 mint 不能の構造的保証、§3)。

### I: String-based cap ID

`"authsock"` / `"cli"` / UUID 文字列を request や API に渡す方式。

不採用:

- 同一 process 内の型境界を捨てて、比較対象を data に落とす。
- 文字列はログ、config、テスト fixture、IPC payload へ容易に漏れ、spoof も容易である。L1 では private-field newtype を使い、外部 crate が forge できない値にする。

## Why this works

### 防ぐもの

- **adapter 実装者がうっかり `Store::get` を直接呼んで、handler の process gate / OTP write-only / authsock namespace 制約を飛ばす事故**。`Store::get` が cap 必須になることで「素の getter による近道」が物理的に消える。
- **code review で raw access の正当性を追えない状態**。cap-gated API に寄せると、秘密値 raw read は `get(key, cap, clock)` 相当の呼び出しに集中する = grep で全 raw read 箇所を列挙できる。
- **lint / grep / deny ルールの対象不明瞭さ**。public raw `get` が消えれば、「raw read は cap API だけ」という機械チェックを置ける (Open Questions Q4 で具体形)。
- **request payload の自己申告による adapter spoof**。handler は request が名乗る adapter を信じず、自分が処理している socket / listener 種別に基づき cap を選ぶ (§7)。
- **不正な caller への TouchID spam / DR-0022 backoff DoS**。cap 判定が runner / auth / backoff より先 (§6) なので、cap を持たない adapter は upstream に届かない。
- **OTP seed の write-only 性質の構造的維持**。OTP adapter が独立 object になり、handler は code response を受けるだけになる (§8)。

### 防がないもの

- **同一 process 内で任意 Rust code を実行できる攻撃者**。cap は暗号鍵ではなく、メモリ上の Rust value である。
- **`unsafe`、FFI、debugger、process memory read による秘密値抽出**。DR-0007 系の hardening は別層であり、本 DR の cap では防げない。
- **`cache_warden` crate 内部の悪意ある変更**。`pub(crate)` は crate 内部の協力的境界であって、同じ crate に悪意あるコードを入れれば迂回できる。
- **capability を保持する adapter 自身のバグ**。cap は「誰が raw read 可能か」を狭めるだけで、読んだ後の扱いを自動で安全にしない (= adapter が secret を平文 log に出す bug は防げない)。
- **define 経路の DoS**。`define` は cap-free なので、malicious local client が大量に definition を登録する DoS は本 DR では塞がない (Open Questions Q5 で別 DR に切り出す候補)。

それでも導入する理由は、現在の主リスクが「決意ある攻撃者」より「アダプタ境界の実装 drift」にあるためである。DR-0014 / DR-0016 / DR-0018 の積み重ねで、value read は単なる map lookup ではなくなった。raw getter を public に置いたままでは、設計上の write-only / adapter-owned translation / namespace policy がすべて convention になる。capability は convention を API surface に押し上げる。

## Trade-off

| 観点 | 良い面 | 悪い面 |
|---|---|---|
| 責務分離 | adapter が core API を呼ぶには cap が必須、bypass 経路が型レベルで消える。secret-handling API は signature を見れば cap 必要が判る | API surface 変化 (= `get(key, cap, clock)` の引数増)、慣れるまで認知負荷あり |
| 安全性 | accidental bypass (= 今の `op_kv_key` 状況) が構造的に発生し得ない | malicious adapter (= 同 binary に組み込まれた敵対 code) は防げない (= type system の限界、§Limits) |
| 拡張性 | enum 化 (`L1(...) / L2(...) / L3(...)`) で将来余地が構造的に確保 | L1 単一 cap は将来 chain / 委譲が要件化したとき API 拡張が必要 (= 本 DR で chain は不採用、別 DR 余地) |
| Lost-cap | 永続化しない設計で `cap.token` が secret な操作 ID にならない (= forge できない、過去 token を log しても害がない) | 再起動後の adapter は cap を作り直す必要 (= startup orchestration の責務が増える、Builder で startup 一発処理する設計で吸収) |
| 実装規模 | 中規模 (= `capability.rs` 新規 200 SLOC + `Store` API 改修 200 SLOC + adapter / handler 配線 200 SLOC + OTP adapter 独立化 100 SLOC + test 改修 600 SLOC ≈ 1300 SLOC) | pre-1.0 を活かす breaking change、CHANGELOG での semver minor bump 必須、127 件の `Store::new()` 呼出点を書き換え |
| dogfood への効果 | `__authsock_op:zl4...` 型の「user 面から見えない / forget できない adapter 内部 key」を構造的に user 操作面に出さない判断が legitimize される (cap 経由でしか触れないから user 面に晒す必要がない) | 即時の forget UX 改善は本 DR 単体では完了しない (= 別 issue の NS 正規化 / reserved NS bouncer と組み合わせて完成) |
| OTP scope | handler から OTP math が抜け、adapter object として独立化 (= DR-0016 schema 維持、test も独立) | scope が肥大化 (handler.rs::finish_get の OTP 分岐引き剥がし + adapter 新規 module + test 移行)、本 DR の作業量を増やす |

### Limits (= 明文化必須)

- **同一 process 内 trust domain**: `unsafe { std::mem::transmute }` 等で `Capability` を直接構築する code path は型では止められない。本 DR は **honest adapter** (= bug や mistake) からの偶発的 bypass を防ぐもので、malicious adapter (= 故意の forge) は防御対象外。
- **`Capability::clone()` の trace 不能**: clone は Rust の所有権モデルで自由にできるため、「この cap が何回 clone されたか / どの module が握ってるか」は実行時には追えない。Opus 案の「`#[derive(Clone)]` を捨てて `tracing::trace!` hook を埋める」は撤回 (= production でも log 経由 side effect が走る / debug build 限定の formal な保証がない、撤回 1)。production trace としては保証しない。
- **`cap.token` の predictability**: process-start 時の random offset (= `OsRng` 由来) を採るので、同一 process 内では predictable だが process 間では予測困難。`unsafe` による forge を許す Rust の型システムを前提にすれば、token の random 性は「process 間で偶然衝突しない」性質のみ意味を持つ。

## Consequences

### 公開 API 変更 (semver minor bump 宣言)

- `Store::get(&mut self, key, clock)` → **削除**。`Store::get(&mut self, key, cap, clock) -> Result<Option<&SecretBytes>, CapError>` に置き換え。
- `Store::set(&mut self, key, source, value, ttl, clock)` → **削除**。`Store::set(&mut self, key, source, value, ttl, cap, clock) -> Result<(), CapError>` に置き換え。
- `Store::extend_authenticated` / `Store::regenerate` / `Store::get_or_regenerate` / `Store::pin_authenticated` / `Store::unpin` / `Store::delete` / `Store::delete_with_definition` → 全部 cap 引数を追加。
- `Store::new()` → **削除** (= 裁定 4)。`Store::builder() -> StoreBuilder` が新しい canonical 経路。
- `Store::set_failure_backoff(Duration)` setter → **削除**。`StoreBuilder::failure_backoff(Duration)` に統合 (= 再 mint 不能な startup 一発設定として整合)。
- 新 API: `Capability` + `CapError` + `StoreBuilder` + `StoreBundle`。
- `Store::define / define_with_meta` → 変更なし (= 裁定 2、cap 不要を維持)。
- value-free metadata API (`list / keys / is_defined / has_value / pin_deadline_of / source_of / definition_of / state_of / failure_backoff_remaining`) → 変更なし (= cap 不要、既存 signature 維持)。
- `cache_warden` crate の semver: **0.x.y → 0.(x+1).0 minor bump**。pre-1.0 なので minor で breaking 可、ただし CHANGELOG 明示 + journal に migration note を残す。

### Library consumer 影響

現状 library として cache-warden を depend している外部リポは確認できる範囲では存在しない (= daemon binary としてのみ流通)。万一存在した場合:

- secret API を直接呼んでいる場合 → `Store::builder().build()` で取得した cap を持ち回す形に移行。
- value-free API しか使っていない場合 → 影響なし。
- `Store::new()` のみ使っている test 等 → `Store::builder().build()` に書き換え、cap が要らない用途なら `StoreBundle` から bundle 全体を捨ててよい (= 値を読まないなら cap は要らない)。

### 依存追加 (= `getrandom` 1 件)

- `crates/cache-warden/Cargo.toml` に **`getrandom = "0.2"`** を追加 (= §Implementation Notes §1 / §9)。token 生成 (= startup 1 回) で使う。
- DR-0005 (zeroize) / DR-0006 (libc) と同列の **意図的な最小依存例外**として CHANGELOG / commit message に明示する。
- `Capability` / `StoreBuilder` のロジック自体は `std` のみ。
- `tracing` (= cap reject log) は既存依存。

### handler / adapter の書き換え範囲

- **`crates/cache-warden-cli/src/daemon/server.rs`** の `Shared` に `control_cap` / `authsock_cap` / `otp_adapter: OtpAdapter` を追加。startup orchestration を `StoreBuilder::new().build() -> StoreBundle` の形に変える。
- **`crates/cache-warden-cli/src/daemon/handler.rs`** の `HandlerCtx` に `store_cap: &Capability` と `otp_adapter: &OtpAdapter` を追加。`handle_get` / `handle_set` / `handle_define` / `handle_pin` の各 path で cap を `Store` API に渡す。`finish_get` の OTP 分岐を `otp_adapter.get_code` に差し替える (= §8)。
- **`crates/cache-warden-cli/src/daemon/authsock.rs`** の `register_op_keys` / `spawn_listeners` で startup 時の cap routing を変更。authsock listener の `SocketState` に `Capability` を持たせる。op key の register は cap-free な `Store::define` で行う (= 裁定 2)。
- **`crates/cache-warden-cli/src/daemon/otp_adapter.rs`** (= 新規) で `OtpAdapter` を定義 (§8)。

### test fixture migration (= N3)

`Store::new()` の呼出点は **127 件** (`grep -n 'Store::new' crates/ | wc -l`)。これらは大部分が test fixture (= `crates/cache-warden/src/store.rs::tests` / `crates/cache-warden-cli/tests/*` / `crates/cache-warden/src/{entry,definition}.rs::tests`)。書き換え方針:

- core 内部の test (`#[cfg(test)]`) には `cache_warden::test_helpers::store_with_cap() -> (Store, Capability)` を提供。一行で `let (mut store, cap) = test_helpers::store_with_cap();` で済む形にする。
- 公開 test (= `cache-warden-cli/tests/*` の e2e) には feature gate された `pub fn store_with_cap()` を `cache_warden::test_helpers` から `#[cfg(any(test, feature = "test-support"))]` で expose。
- 各 secret API 呼出は `store.get(key, &cap, &clock)` の形に統一書き換え。`Result` を返すようになるので `unwrap()` 追加、または直接 `?` で伝播。
- migration は機械的に grep + sed で大部分が処理できる予測 (= 「`store.get(key, clock)` → `store.get(key, &cap, clock).unwrap()`」の pattern マッチ書き換え)。具体的な migration コマンドは実装着手前に決定。

### 既存 DR との関係

- **DR-0003**: 本 DR は DR-0003 の責務分離を **実装で強制**するレイヤ。「分離してるはずなのに侵犯してる」状態を構造的に解消。
- **DR-0014**: definitions 分離 + entries 分離の延長として cap も第 4 軸として分離 (= access_token は startup-immutable な scalar、3 マップとは別軸)。
- **DR-0016 / DR-0018**: ValueMeta / SourceMeta は完全に維持。本 DR が追加するのは「誰が触れるか」の軸、これらは「何をどう解釈するか」の軸で独立。OTP adapter の独立化 (§8) は DR-0016 schema に手を加えない。
- **DR-0010**: re-auth は cap 判定の **後**。cap 拒否は upstream / re-auth を一切呼ばない (§6)。
- **DR-0022**: failure_backoffs を第 3 map にした pattern と同型で、本 DR は access_token を scalar として追加。backoff も cap 判定の後に評価する (§6)。
- **DR-0012**: key-level process access policy と本 DR の cap は **直交軸**。両方とも handler が evaluate する; cap は「この caller が core API を呼べるか」、policy は「この requester が key の secret を取得できるか」。順序は cap 先 → policy 後 (= cap 不在は registered key ですらないので NotFound、policy 違反は AuthFailed で分離)。

### issue `2026-06-14-internal-key-forget-interface.md` との関係

本 DR は issue で確定した「`StoreKey` newtype + 公開 API validation 強制」の **権限軸への一般化**。issue の `StoreKey` 案は「入力面 (= 不正キーを作れない)」を塞ぐ、本 DR は「出力面 (= 不正キーを既存 store に push できない、許可された主体しか操作できない)」を塞ぐ。両者は補完関係。

実装順序の推奨:

1. 本 DR (= capability framework) を先に land。
2. 続いて `StoreKey` newtype + NS 正規化 + reserved NS bouncer を別 DR (= DR-0026 候補) で扱う (= 入力面)。
3. authsock 内部 key の rename (`__authsock_op:` → `authsock/op_`) は別 PR (= 上記 2 とまとめてもよい)。

## Implementation Notes

### 1. `crates/cache-warden/src/capability.rs` (新規)

```rust
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
```

依存:

- `crates/cache-warden/Cargo.toml` に `getrandom = "0.2"` を追加 (= DR-0005 / DR-0006 と同列の「意図的な最小依存例外」として CHANGELOG / commit message に明示)。
- `getrandom` 0.2 は `rand` crate の依存元として ecosystem 全体で広く使われており、std + libc 上の薄い wrapper。本 DR 以降に `rand` や `ring` 等のより重い crypto crate に切り替える余地は L3 で別 DR とする。
- 別案: `std::time::SystemTime + std::process::id()` の自前 PRNG で済ます (= 依存追加なし) は採らない。test 環境で predictable な値が出る + audit でレビューしづらい。
- 別案 2: libc 経由で `getentropy(3)` (macOS) / `getrandom(2)` (Linux) を直叩き (= DR-0006 libc 経由) も技術的には可能だが、`getrandom` crate 経由のほうが platform 抽象が clean で本 DR の射程内では over-cost。

### 2. `crates/cache-warden/src/store.rs` 改修

```rust
pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
    definitions: BTreeMap<String, Definition>,
    failure_backoffs: BTreeMap<String, FailureRecord>,
    failure_backoff_duration: Duration,
    access_token: u128,
}

impl Store {
    pub fn builder() -> StoreBuilder { StoreBuilder::new() }

    pub(crate) fn new_with_token(token: u128, backoff: Duration) -> Self {
        Self {
            entries: BTreeMap::new(),
            definitions: BTreeMap::new(),
            failure_backoffs: BTreeMap::new(),
            failure_backoff_duration: backoff,
            access_token: token,
        }
    }

    fn check_cap(&self, cap: &Capability) -> Result<(), CapError> {
        if cap.token == self.access_token { Ok(()) } else { Err(CapError::KeyMismatch) }
    }

    pub fn get(
        &mut self, key: &str, cap: &Capability, clock: &impl Clock,
    ) -> Result<Option<&SecretBytes>, CapError> {
        self.check_cap(cap)?;
        Ok(self.entries.get_mut(key).and_then(|e| e.get(clock)))
    }

    // ...他の secret API も同様に check_cap → 既存ロジック
}
```

### 3. `Store::new()` 削除と test_helpers (= N3)

- `Store::new()` / `Store::default()` の public 露出は廃止。`#[derive(Default)]` の Store も除去 (= access_token が 0 で「Unknown 経路に必ず落ちる」状態を作らない)。
- `crates/cache-warden/src/test_helpers.rs` (= 新規) を `#[cfg(any(test, feature = "test-support"))]` で提供:

```rust
pub fn store_with_cap() -> (Store, Capability) {
    let bundle = StoreBuilder::new().build();
    (bundle.store, bundle.control_cap)
}

pub fn store_with_cap_and_backoff(d: Duration) -> (Store, Capability) {
    let bundle = StoreBuilder::new().failure_backoff(d).build();
    (bundle.store, bundle.control_cap)
}
```

- 既存の `Store::new()` 呼出 127 件は機械的に書き換え:

```bash
# 例: Store::new() → test_helpers::store_with_cap() 形式へ
rg -l 'Store::new\(\)' crates/ | while read f; do
  # 実装着手時に sed pattern を確定する; pattern は文脈依存なので手動レビュー併用
done
```

### 4. `CapError` の戻り方 (= Open Q Q6 対応)

handler が `CapError` を見たら、外部応答としては何を返すか:

- control socket: `CapError` は **caller 起因の認可違反**だが、protocol 上 user に見せる情報差を作らない方が安全 (= adapter spoof 試行に対して「key そのものが存在しない」と区別がつかない応答)。`CapError::KeyMismatch` も `CapError::Unknown` も外部応答としては `Response::error(ErrorKind::NotFound, "no such key")` に統一する。
- 内部 log には `tracing::warn!("cap rejected: kind={:?}", err)` で差を残す (= operator が daemon log で「adapter 設定の bug か攻撃か」を切り分け可能、§Implementation Notes §6)。

### 5. handler 書き換え + OTP adapter 独立化 (§7-§8)

- `crates/cache-warden-cli/src/daemon/server.rs` の `Shared`:

```rust
pub struct Shared {
    pub store: Mutex<Store>,
    pub runner: CommandRunner,
    pub auth: Auth,
    pub clock: SystemClock,
    pub control_cap: Capability,
    pub authsock_cap: Capability,
    pub otp_adapter: OtpAdapter,
}
```

- `crates/cache-warden-cli/src/daemon/handler.rs::HandlerCtx`:

```rust
pub struct HandlerCtx<'a, A: ?Sized, R, C> {
    pub auth: &'a A,
    pub runner: &'a R,
    pub clock: &'a C,
    pub store_cap: &'a Capability,        // NEW
    pub otp_adapter: &'a OtpAdapter,      // NEW
    pub requester: Option<&'a [ProcessInfo]>,
    pub kv_process_policies: &'a BTreeMap<String, Vec<PathBuf>>,
}
```

- `handle_get` の cap 経路:

```rust
match store.get(&key, ctx.store_cap, ctx.clock) {
    Ok(Some(_)) => finish_get(store, ctx, &key, dry_run, "active"),
    Ok(None) => /* lazy_generate or NotFound */,
    Err(_) => Response::error(ErrorKind::Internal, "internal cap mismatch"),
}
```

- `finish_get` の OTP 分岐は `ctx.otp_adapter.get_code(store, key, ctx.clock)` 1 行に縮約。`handler.rs:489` の `otp_type::derive_code` 直接呼び出しは消える (= handler から OTP math が抜ける、§8)。

### 6. authsock 改修

- `register_op_keys` (= `authsock.rs:193`) は cap-free な `Store::define` を呼ぶ (= 裁定 2)。signature は変更不要。
- `spawn_listeners` (= `authsock.rs:242`) で `SocketState` に `authsock_cap: Capability` を保持。`local_sign` 経路で seed を読むときに cap を使う (= `store.get(kv_key, &state.authsock_cap, clock)`)。
- `__authsock_op:<id>` の `:` 違反 (DR-0017 文字種規定) は本 DR の射程外 (= 別 PR で `authsock/op_<id>` に rename、上記 §Consequences の issue follow-up)。

### 7. `cache_warden::test_helpers` の射程 (= N3)

- `#[cfg(any(test, feature = "test-support"))]` で gated。production binary には含まれない。
- 提供:
  - `store_with_cap()` (cap 1 個と Store)
  - `store_with_cap_and_backoff(Duration)` (DR-0022 fixture)
  - `bundle_of(store: Store, token: u128) -> Capability` (test 内で手動 cap を発行したい用)

### 8. tracing policy (= N7)

production log で何を出して何を出さないか:

- **出す**:
  - cap mint: `tracing::debug!("cap minted at startup")` (= 1 度のみ、token は出さない)
  - cap reject: `tracing::warn!("cap rejected: kind={:?}", err)` (= error variant のみ、token / key 名は出さない)
- **出さない**:
  - `cap.token` の値 (= log 経由で別 process に流れると forge 補助材料になる)
  - cap clone 回数 (= production trace としては保証しない、§Limits)
  - adapter ↔ key 対応の log (= 「authsock-op が `__authsock_op:itemABC` を借りた」のような log は adapter 関係性を晒す)

これは比較レビュー §3.8 「adapter 関係性漏洩」への対策。operator が daemon log を Datadog / sentry へ送るケースでも、cap 経路の log は機械的に「token / key / holder を含まない」を保証する。

### 9. dependencies (= 確定)

- **`getrandom = "0.2"` を `crates/cache-warden/Cargo.toml` に追加** (= §Impl §1 で確定): DR-0005 (zeroize) / DR-0006 (libc) と同列の「意図的な最小依存例外」。本 DR の token 生成 (= startup 1 回) でのみ使う。
- `tracing` は既存依存 (= DR-0022 で使用済み)。
- 本 DR 追加分は `getrandom` 1 件のみ。DR-0002 の依存最小原則は維持。

## Open Questions

### Q1: L1.5 scoped cap への移行余地

per-Store cap (= L1) で adapter 間最小権限を表現しきれない。authsock cap も OTP cap も control cap も同じ token clone なので、authsock adapter が malicious になった場合、`authsock/op_<id>` だけでなく user-facing key (= `kv.*`) の secret も読めてしまう。scoped cap は L1.5 として後続 DR で扱うべきか?

- 本 DR の構造は scoped cap への移行を阻まない (= `Capability` を opaque token に閉じた)。L2 で `enum Capability { L1(L1Token), Scoped(ScopedToken { keys: ... }) }` の variant 拡張余地は確保。
- 移行判断は dogfood で「adapter 間の権限差が運用上必要か」が見えてから (Codex 案 Q2 採用)。

### Q2: OTP adapter の crate / module 配置

`crates/cache-warden-cli/src/daemon/otp_adapter.rs` (= cli crate 内) か、cache-warden core crate の adapter module か。OTP derivation 自体は CLI crate に置く (= DR-0016、core は OTP を知らない) ので CLI crate 配置が自然だが、将来 typed derived view が増えたとき (= JWT / PASETO 等) `adapter trait` を切る余地を残すか。

- 暫定設計: CLI crate 配置。trait 化は実装後に再評価。
- Codex 案 Q6 採用。

### Q3: IPC 拡張時の attestation 設計 (L3 接続)

将来 L3 で IPC 越し adapter (= 別 process の adapter binary) が同 store に接続するケース。in-process cap (= 本 DR) は Rust 参照渡し前提なので IPC では使えない。`enum Capability` の variant 拡張で対応できる構造は維持。

- 暫定設計: `enum Capability { L1(L1Cap), Remote(RemoteAttestation) }` の variant 化。L3 variant は内部に attestation context (= 検証済の peer identity + 認可 scope) を持つ。検証 (= `check_cap` の内部) で L3 variant は signature / cert / nonce の validity を再 evaluate (= replay 対策)。L1 / L3 共に「token 検証」の最終段は共通。
- Opus 案 Q6 採用。本 DR では variant 拡張余地のみ確保、L3 設計は別 DR (= 候補 DR-0027+)。

### Q4: lint hook の CI 統合手段 (= N9)

`Store::get` public symbol の不在、`SecretBytes::expose_secret` 呼び出し箇所の allowlist、OTP seed raw read の module allowlist を CI でどう表現するか:

- 候補 A: clippy custom lint plugin (= 学習コスト + maintenance)
- 候補 B: rustdoc JSON 出力を grep する自前 script (= 軽量、CI 統合容易、ただし public surface 変更検出のみ)
- 候補 C: `cargo deny` + workspace-level grep の組み合わせ (= 既存 toolchain で完結)

着地点は実装着手後に dogfood で確定。Codex 案 Q10 採用。

### Q5: `define` cap-free と DoS の境界

`define` を cap-free にすると malicious local client が大量に definition を登録する DoS には効かない (= 裁定 2 で許容)。これは protocol auth / quota の別 DR に分離してよいか?

- 暫定設計: 本 DR は raw value capability の軸に限定、DoS は protocol 層 (DR-0009 control socket、DR-0012 process access policy) で扱う。明示的な quota / rate limit は別 DR (= 候補 DR-0028) で起こす。
- Codex 案 Q7 採用。

### Q6: wrong cap と missing key の error 区別

`Store::get(key, cap, clock)` の `Result<Option<&SecretBytes>, CapError>` で、wrong cap と missing key の区別は audit には有用だが adapter response へ漏らすと情報差になる。

- 暫定設計: 内部 log には差を残す、外部応答は統一 (= `NotFound`)。§Implementation Notes §4。
- Codex 案 Q4 採用。

### Q7: discover 遅延と cap mint タイミング

DR-0023 Phase 1 で authsock op discover は blocking pool 上で同期実行。discover が長引くと `StoreBuilder::build()` が遅れ、control socket の bind も遅れる。

- per-Store cap 採用により本 DR では問題が縮小: cap mint は build 時 1 発 (= per-key loop は不要)、`define` は cap-free なので discover 完了後でも定義登録可能。実質「control socket は即 bind、authsock listener は discover 完了後に spawn」の構造で問題ない。
- DR-0023 follow-up として残す。Opus 案 Q3 採用。

### Q8: cap-gated API の async 化

future の async refactor (= DR-0023 Phase N+) で `Store::*` が async 化する可能性。`&Capability` を borrow したまま .await すると lifetime が複雑化する。

- 暫定設計: `Capability` は `Clone` 可能で安いので、handler / adapter 側で `cap.clone()` してから `.await` を超える pattern を採る。
- Opus 案 Q8 採用。

### Q9: `Store::new()` 廃止後の library user 体験

裁定 4 で `Store::new()` は即削除されるが、value-free metadata だけ使う library user (= 仮の future consumer) には不要なコストになる。

- 暫定設計: `StoreBuilder::new().build().store` で取り出せばよい (= cap は dropping して捨てれば metadata only 用途として動作)。実用上の摩擦は少ない予測。
- 実装後に library user 出現タイミングで再評価。

### Q10: test fixture migration cost (= 実数 127 件、land 後の機械的書き換えで対処)

`Store::new()` 呼出は `grep 'Store::new()' --include='*.rs' -r crates/ | wc -l` で **127 件** (= 2026-06-14 計測値、core/store.rs::tests + cli unit test + cli e2e test 合算)。本 DR land 後の実装 PR で書き換える方針:

1. **先に `cache_warden::test_helpers::store_with_cap()` を land** (= §Implementation Notes §3、§7)。これを base に置くと多くの fixture が `let (mut store, cap) = test_helpers::store_with_cap();` 1 行に縮む。
2. **機械的 sed pattern の確立** (= 1-2 件先行書き換え → recipe 固定 → 残りに展開):
   - `Store::new()` → `test_helpers::store_with_cap()` への置換 (= cap 受け取り + helper import)
   - `store.get(key, &clock)` → `store.get(key, &cap, &clock).unwrap()` への置換 (= cap 引数 + Result unwrap)
   - `store.set(key, ..., &clock)` → `store.set(key, ..., &cap, &clock).unwrap()` への置換
3. **手動対応想定箇所**: e2e test で `Mutex<Store>` 越しに操作する path、複数 cap を test 内で発行したい path、`Store::with_failure_backoff` を使う path (= setter 廃止に伴う API 変化)。これらは context 依存で sed が効かない。
4. **見積もり粒度**: 127 件のうち 80% (= ~100 件) は機械的 sed、20% (= ~25 件) は手動レビュー必要、と現時点で推定。実装着手時に precise な分類は `git grep -l 'Store::new'` の path 集合と各 file の adapter pattern を見て確定。
5. land 着手前に dry-run 統計を `journal` か別 issue に記録 (= 比較レビュー B1 / N3 採用)。

### Q11: `SecretBytes::expose_secret` allowlist の射程 (本 DR scope 外)

`SecretBytes::expose_secret` を `pub(crate)` にして allowlist module からのみ呼べる構造にする案は本 DR とは別軸。本 DR は raw read API の cap-gated 化が主、`expose_secret` の呼出制限は別 issue として切り出す。

- 比較レビュー B2 / N4 採用。本 DR scope 外、別 issue `docs/issue/2026-06-14-expose-secret-allowlist.md` (= 本 DR land と併設) で扱う。

### Q12: `finish_get` working buffer の zeroize 整合 (本 DR scope 外)

`handler.rs::finish_get` の `secret.expose_secret().to_vec()` で `Vec<u8>` への copy 後、その Vec は zeroize されない (= DR-0007 mlock の意義を半減させる)。本 DR の OTP adapter 独立化 (§8) で path は変わるが、Vec への copy 自体は残る。

- 比較レビュー B3 / N5 採用。本 DR scope 外、別 issue `docs/issue/2026-06-14-finish-get-working-buffer-zeroize.md` (= 本 DR land と併設) で扱う。DR-0007 / DR-0016 と整合を取る別 PR で進める。

## Related

### code

- `crates/cache-warden/src/store.rs` (= 全 secret API を cap 必須に改修対象、特に L96-L654 の `impl Store`)
- `crates/cache-warden/src/capability.rs` (= 新規、§Implementation Notes §1)
- `crates/cache-warden/src/test_helpers.rs` (= 新規、§Implementation Notes §3 / N3)
- `crates/cache-warden/src/entry.rs` (= 変更なし、`CacheEntry` は core 内部 primitive)
- `crates/cache-warden/src/auth.rs` (= 変更なし、`Authenticator` は cap 判定後に評価される)
- `crates/cache-warden-cli/src/daemon/server.rs` (= `Shared` 構造体に cap / OTP adapter 追加、startup orchestration の builder phase 化)
- `crates/cache-warden-cli/src/daemon/handler.rs:1-580` (= `HandlerCtx` に cap / `otp_adapter` 追加、全 `handle_*` で `Store::get(key, cap, clock)` 呼出、`finish_get` の OTP 分岐を `otp_adapter.get_code` に差し替え)
- `crates/cache-warden-cli/src/daemon/handler.rs:453-501` (= `finish_get` の OTP 分岐削除、§8)
- `crates/cache-warden-cli/src/daemon/authsock.rs:188-300` (= `register_op_keys` は cap-free なまま、`spawn_listeners` で `SocketState` に cap 保持)
- `crates/cache-warden-cli/src/daemon/authsock.rs:75-110` (= `build_registry` も cap 経由の `store.get` に書き換え)
- `crates/cache-warden-cli/src/daemon/otp_adapter.rs` (= 新規、§8)

### docs

- DR-0003 (= core / adapter 責務分離、本 DR の根本動機)
- DR-0010 (= re-auth command、cap 拒否との順序、§6)
- DR-0011 (= TTL 2 分離 + pin、本 DR で `pin_authenticated` も cap 必須化)
- DR-0012 (= process access policy、本 DR とは直交軸)
- DR-0014 (= entries / definitions 分離、本 DR の access_token 追加と同型 pattern)
- DR-0016 (= OTP value type、ValueMeta 維持、OTP adapter 独立化の前提)
- DR-0018 (= typed sources、SourceMeta との独立性)
- DR-0022 (= failure_backoffs 第 3 マップ、本 DR の同型 pattern + 判定順序)
- DR-0023 (= startup blocking pool、Open Q Q7 follow-up)

### issue / journal

- `docs/issue/2026-06-14-internal-key-forget-interface.md` (= 本 DR の起点、`StoreKey` newtype 案と相補)
- `docs/issue/2026-06-14-op-refetch-loop.md` (= dogfood で発見、本 DR とは直接対応しないが「内部 key の forget 不能」関連)
- `docs/issue/2026-06-14-expose-secret-allowlist.md` (= 本 DR land と併設、Q11 scope 外)
- `docs/issue/2026-06-14-finish-get-working-buffer-zeroize.md` (= 本 DR land と併設、Q12 scope 外)
- `docs/decisions/draft-DR-0024-cap-access-gate-OPUS.md` (= 比較レビュー source、land 後 archive 候補)
- `docs/decisions/draft-DR-0024-cap-access-gate-CODEX.md` (= 比較レビュー source、land 後 archive 候補)
- `docs/decisions/draft-DR-0024-comparison-review.md` (= 統合判断 source、land 後 archive 候補)
