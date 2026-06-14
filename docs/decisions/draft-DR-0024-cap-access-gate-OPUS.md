# DR-0024 (draft / Opus 視点): capability-based access gate (L1 単一 cap)

- Status: Draft (= Opus 独立起草、Codex 案と比較レビュー予定)
- Date: 2026-06-14
- Related: **DR-0003 (コア / アダプタ責務分離、本 DR の動機の根本)** / DR-0004 (NotLoaded を core に持ち込まない判断、本 DR の置き場判断と同型) / DR-0010 (re-auth command、cap 拒否との順序関係) / DR-0014 (entries / definitions 分離、本 DR の registry 配置の前提) / DR-0016 (OTP value type、ValueMeta 維持判断の関係先) / DR-0018 (typed sources、SourceMeta との独立性) / DR-0022 (failure_backoffs を第 3 マップとして並置した先例、本 DR の第 4 マップ追加と同型) / `docs/issue/2026-06-14-internal-key-forget-interface.md` (本 DR の起点)

## Context

### 問題: コア API が「中からの不正キー push」を物理的に止められない

DR-0003 は「コア (`cache-warden` lib) は秘密値の KV キャッシュ、アダプタは
プロトコル変換」と責務を分けた。DR-0017 は KEY / NS の文字種を
`[A-Za-z0-9_]+` の `NS/KEY` 形式に縛った。`handler.rs::validate_protocol_key`
(`crates/cache-warden-cli/src/daemon/handler.rs:207`) は control socket 経由の
`kv.set` / `kv.define` を保護している。

しかし `Store::set / get / define / regenerate / get_or_regenerate / pin /
unpin / delete` は **すべて `&str` / `impl Into<String>` を素通しで受ける**。
adapter は control socket を介さず `Store` を直接呼べるため、handler 側の
validation を構造的に bypass できる。実例:

- `crates/cache-warden-cli/src/daemon/authsock.rs:223 op_kv_key` は
  `format!("__authsock_op:{item_id}")` で `:` 含むキーを生成し、`Store::define`
  にそのまま渡す。`:` は DR-0017 が禁じた文字。これは adapter 都合の「内部
  ネームスペース」を `:` という違反文字で実現している = **アダプタが core
  契約を勝手に破っている**。
- `handler.rs` の `kv_process_policies` (DR-0012 key layer) も「key 名でしか
  policy を引けない」前提で動くが、`__authsock_op:<id>` のような内部 key は
  そもそも `kv.list` から見えない / `kv del` で消せないため、user の操作面
  からは「存在しないのに残り続ける鍵」になる。dogfood で `zl4...` regression
  として観測された (issue `2026-06-14-internal-key-forget-interface.md`)。

責務分離は「アダプタを介さない近道」を消さない限り **絵に描いた餅** で、
将来別 adapter が同じ pattern (`__myauth_op:`, `__totp:`, ...) を再生産する。
NS 正規化だけでは構造的に止まらない (= 必要条件であって十分条件でない)。

### なぜ「型レベル newtype」だけでは不足か

issue は当初「`StoreKey` newtype 案」を提示した: `StoreKey::parse(s)` か
`StoreKey::compose(ns, key)` 経由でしかキーが作れないようにし、`Store` の
公開 API を `StoreKey` 受け取りに変更する。これは bypass の **入力面** を
塞ぐ良い案だが、別の側面で不足する:

1. **どの adapter がどのキーを使う権利を持つか** が表現できない。「authsock
   adapter は `authsock/op_<id>` を作って良い」「`kv.*` 由来の user key は
   adapter 内部から触らない」という adapter 間の境界が、型では分離できない
   (同じ `StoreKey` を全 adapter が共有してしまう)。
2. **内部キーを user 面から forget するインターフェース** が定義されない。
   今は `kv del` から見えず、再生成も `lazy_load_op_key` が独自経路で行う
   ため、`__authsock_op:<id>` は invariant に依存して生きている。
3. core が「これは内部キーだから user 操作を通すな」を判断する手段がない。
   名前 prefix (`__`) で hack するのは DR-0017 文字種規定との二重否定で、
   contract が文字列規約に分散する。

→ 「キーを物理的に作れない」だけでは責務境界として弱い。「**この cap を
持っている主体だけがこのキー集合を触れる**」という **権限の認可** モデルが
要る。

### 設計の出発点 (合意済み確定事項)

| 項目 | 確定 (issue + 事前合意) |
|---|---|
| 単一 vs chain | **L1 単一 cap** (= 1 値 = 1 cap、chain は将来余地のみ確保) |
| raw `Store::get` | **crate-private 化** (= public API から消す、bypass を構造的に不可) |
| DR-0016 OTP type schema | **維持** (= ValueMeta は永続メタの正規置き場、廃止しない) |
| Lost-cap 復旧 | **永続化しない (= in-memory only)、再起動で cap ID リセット** |
| IPC adapter 身分証明 | **Phase 3 範囲外** (= L3 mTLS / 署名は将来 generic opaque 設計の余地) |
| register 配線 | **Builder pattern** (= Store 構築時に全 adapter cap 登録、起動時の `&mut Store` 競合回避) |
| trust domain | 同一 process = 同一 trust domain (= cap は **daemon 内部の規約**、attacker model 外) |

Codex review v1 で確定した追加制約:

- raw getter の廃止 or crate-private 化が必須 (= bypass 経路を構造的に消す)
- Capability は同一 process では型で完全防御不能 = 設計の限界として明文化
- Lost-cap の永続ロックを作らない (= in-memory)
- `Vec<Capability>` より専用型 (L1 単一 cap なら `Option<Capability>` で済む)
- DR-0010 (re-auth) との順序: **cap 拒否を先**に評価 (= 不正 caller に
  upstream fetch / re-auth prompt を誘発しない)
- IPC 越し cap は in-process token と remote attestation を最初から分けて、
  本 DR は **in-process token に限定**
- 「core は出口条件の機械判定まで、adapter は『どの値にどの cap が必要か』
  の決定まで」で境界固定

## Decision

### 1. capability の概念 (= 何を表すか)

**Capability = 「core が register した、ある key (または key の集合) に対して
core API を呼ぶ権利を持つ unforgeable token」**。L1 では:

- 1 つの capability は **1 つの key (exact match)** に対応する。
- capability は `Copy` ではなく `Clone` で borrow される (= 型レベルで偽装を
  難しくし、複製履歴が trace 可能になる)。
- capability の発行は **`Store` 構築時の Builder pattern** に閉じる
  (= 起動後に新規発行できない / cap ID 表が固定される)。
- core は cap の中身を opaque な ID (`u64` の monotonic counter) と、
  cap が許可する key の `String` (内部正規化済み) で保持する。
- adapter 越しで cap を渡す経路は **同一 process 内 Rust 参照のみ**
  (= IPC 越しの cap は L3 で別途設計)。

**capability は 1 key 単位**: 「authsock_op の cap」のような adapter
グループ単位ではなく、`authsock/op_<id>` 1 つに 1 cap。理由:

- adapter グループ単位にすると、新規 key 登録時に「グループ cap が cover
  する key 集合」が動的に拡張される = cap の意味が時間変動して reasoning が
  難しい (= chain 化が逆流入する)。
- L1 の単純さ (= 1 cap = 1 key、ID 固定、永続なし) を保つには 1 key 単位が
  下限。adapter 側で「自分の cap のリスト」を保持すればグループは表現できる
  (= cap は core 側の primitive、grouping は adapter 側の責務 = 責務境界が
  きれいに分かれる)。

### 2. Capability 型 (= `Capability` newtype)

```rust
// crates/cache-warden/src/capability.rs (新規)

/// An unforgeable token granting core API access to one specific key.
///
/// Issued only at `StoreBuilder` time and handed to one specific adapter (or
/// the handler) at startup. Cloning a capability is allowed (an adapter often
/// borrows the same cap to several internal call sites) but a capability cannot
/// be **constructed** outside core: its sole inner field is `pub(crate)`.
///
/// L1 grants exactly one key (exact match). A future revision may extend the
/// grant to a key set or to a chained delegation, but the current core matches
/// `cap.key == requested_key` literally.
///
/// # trust domain (= the limit of what a type can defend against)
///
/// Inside the same Rust process, the type system cannot prevent code that
/// already runs in that process from forging a capability via `unsafe` or from
/// borrowing one it has no business borrowing. Capability is therefore best
/// understood as **a daemon-internal contract**: it makes the boundary
/// explicit, gives every misuse a single grep target, and makes accidental
/// bypass (the present-day `op_kv_key` situation) structurally impossible.
/// It does **not** defend against a malicious adapter compiled into the same
/// binary; that threat is out of scope (see "Limits" in Trade-off).
#[derive(Debug, Clone)]
pub struct Capability {
    /// Unique within a single `Store`. Monotonic, opaque, never reused.
    pub(crate) id: CapabilityId,
    /// The single key this capability grants (L1, exact match).
    pub(crate) key: String,
    /// Cheap discriminator for diagnostics / `Display` (e.g. "authsock-op").
    /// Never used in authorization decisions; purely human-readable.
    pub(crate) holder: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapabilityId(u64);
```

#### Clone / Copy の判断

- `Copy` は採用しない。`Copy` を許すと「複製が無料、痕跡なし」になり、
  Rust の所有権モデルが提供する「move / borrow の trace」が無効化される。
- `Clone` は採用する。adapter 内部で 1 cap を複数 call site が借りる用途は
  正当 (= authsock の register / lazy refresh / cleanup 全部が同じ cap を
  使う)。
- ただし `Capability::clone()` は `tracing::trace!("capability cloned: {id}
  for {holder}")` の hook を埋める余地を残す (= debug build でのみ有効化)。

#### holder field の用途

`holder: &'static str` は **diagnostic only**。authorization 判定に使わない
(= 「holder 名で許可判定」をやり始めると adapter 識別の責務が core に
逆流入する)。`status` 出力や log で「この cap は誰が握ってる」を表示し、
人間が責務境界をデバッグするためだけに存在する。

### 3. StoreBuilder pattern

```rust
// crates/cache-warden/src/store.rs (改修)

/// Build a `Store` together with all capabilities its adapters will need.
///
/// Capabilities are issued **only** here: once `build()` is called the store
/// is frozen against new capability minting (re-mint requires reconstructing
/// the daemon, which matches the "in-memory only / restart resets caps"
/// decision and removes a whole class of mid-flight authorization races).
pub struct StoreBuilder {
    /// Capabilities to be installed before the store ships. Indexed by
    /// (capability_id) so issuance order is deterministic.
    pending_caps: Vec<(CapabilityId, String, &'static str)>,
    failure_backoff: std::time::Duration,
    next_cap_id: u64,
}

impl StoreBuilder {
    pub fn new() -> Self { /* ... */ }

    /// Issue a fresh capability granting access to `key` (exact match).
    /// The capability is returned by value; the caller is responsible for
    /// handing it to exactly one holder (Rust's ownership ensures it isn't
    /// silently shared until `clone` is explicitly called).
    pub fn capability_for(
        &mut self,
        key: impl Into<String>,
        holder: &'static str,
    ) -> Capability { /* ... */ }

    pub fn set_failure_backoff(&mut self, d: std::time::Duration) -> &mut Self {
        self.failure_backoff = d;
        self
    }

    /// Finalize. After this, no new capability can ever be minted for this
    /// store (the only way to add one is to rebuild the daemon).
    pub fn build(self) -> Store { /* ... */ }
}

impl Store {
    pub fn builder() -> StoreBuilder { StoreBuilder::new() }
    // `Store::new()` is **retained** for library consumers (= the public
    // `cache_warden` crate users) who don't care about caps. It builds a
    // store with **no capabilities registered**; any attempt to call the
    // capability-gated API will fail with `CapMissing`. This preserves the
    // existing single-line idiom for library tests while making the daemon
    // path opt into the stricter shape via `Store::builder()`.
    pub fn new() -> Self { Self::builder().build() }
}
```

#### なぜ起動時に固定するか

- 起動後 mint 可能だと「誰でも cap を作れる API が常時存在」= bypass surface
  が消えない (= 全 cap-gated API 呼び出しの前段に「cap mint 不能の証明」が
  必要になる)。
- daemon の `&mut Store` は startup 後 `Mutex` の中。起動後 mint には mutex
  lock + builder 取り直しが必要で、競合 + lock 保持時間が増える (= DR-0023
  Phase 1 / DR-0007 mlock 観点とも噛み合わない)。
- 「再起動で cap ID リセット」が L1 の Lost-cap 復旧戦略と一致する
  (= startup 一発で全 cap が再 mint される、永続化なし)。

### 4. 公開 API の改修 (= cap を受け取る形に)

`Store` の **secret / lifecycle に影響する** API は cap を必須にする:

```rust
impl Store {
    // ---- secret-handling API: capability-gated ----

    /// Borrow the secret under `cap.key` iff currently Active.
    /// Internal getter: callable only by holders of the matching capability.
    pub(crate) fn get(&mut self, cap: &Capability, clock: &impl Clock)
        -> Result<Option<&SecretBytes>, CapError> { /* ... */ }

    /// Public alias that takes a capability. The name `get` remains for
    /// `pub(crate)` use; the public surface is renamed `authorized_get` to
    /// make the gate self-evident at call sites.
    pub fn authorized_get(&mut self, cap: &Capability, clock: &impl Clock)
        -> Result<Option<&SecretBytes>, CapError>;

    pub fn authorized_set(
        &mut self,
        cap: &Capability,
        source: ValueSource,
        value: SecretBytes,
        ttl: Ttl,
        clock: &impl Clock,
    ) -> Result<(), CapError>;

    pub fn authorized_define(
        &mut self,
        cap: &Capability,
        source: ValueSource,
        ttl: Ttl,
    ) -> Result<(), CapDefineError>;

    pub fn authorized_define_with_meta(
        &mut self,
        cap: &Capability,
        source: ValueSource,
        ttl: Ttl,
        meta: ValueMeta,
        source_meta: SourceMeta,
    ) -> Result<(), CapDefineError>;

    pub fn authorized_extend_authenticated(/* cap + 既存引数 */) -> ...;
    pub fn authorized_regenerate(/* cap + 既存引数 */) -> ...;
    pub fn authorized_get_or_regenerate(/* cap + 既存引数 */) -> ...;
    pub fn authorized_pin_authenticated(/* cap + 既存引数 */) -> ...;
    pub fn authorized_unpin(&mut self, cap: &Capability) -> bool;
    pub fn authorized_delete(&mut self, cap: &Capability) -> bool;
    pub fn authorized_delete_with_definition(&mut self, cap: &Capability) -> bool;

    // ---- value-free metadata API: NOT capability-gated ----
    //
    // `list` / `keys` / `is_defined` / `has_value` / `pin_deadline_of` /
    // `source_of` / `definition_of` / `state_of` / `failure_backoff_remaining`
    // 等は cap なしで呼べる。理由:
    //
    // - これらは **secret を露出しない** (= 名前 / metadata / TTL のみ)
    // - `kv list` / `status` の手で list したい unrestricted operator
    //   (= handler 層の status path) が cap を全 key 分集める必要が出ると
    //   実装が崩壊する
    // - 「key の存在 / 状態」は `kv.list` で常に見えてよい (DR-0012 で
    //   policy gate も「list は晒す、get は閉じる」設計、本 DR もそれに
    //   揃える)
}
```

#### 命名: `authorized_*` prefix を全 secret API に付ける

- `get` → `authorized_get` / `set` → `authorized_set` / ...
- prefix 統一の理由 = `grep -n 'fn authorized_' src/store.rs` で「cap が要る
  API の全集合」が 1 コマンドで列挙できる。`grep -n 'fn get\|fn set'` だと
  ノイズが多すぎる。
- 短い名前 (`get`) を **`pub(crate)` 用に温存**: core 内部のテスト / 内側の
  helper は短い名前を使い、公開境界は長い名前で「ここに gate がある」を
  signal する。「core は出口判定まで、adapter は entry 判定まで」(Codex
  Info 指摘 #9) と一致する line がこの prefix で目視できる。

#### CapError

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    /// The capability does not match the requested key (L1 exact-match).
    KeyMismatch {
        cap_key: String,
        requested: String,
    },
    /// The capability id is unknown to this store (e.g. a capability from
    /// another `Store` instance, or the store was rebuilt and the cap is
    /// stale).
    Unknown { id: CapabilityId },
    /// The capability was issued for this store but is no longer registered
    /// (= someone called `revoke`, currently unused but reserved for L2).
    Revoked { id: CapabilityId },
}
```

`CapError::Unknown` は **多 store 防御**: テスト等で `Store` を複数立てる
ケースで「他 store の cap を渡してしまった」を catch する。production では
1 daemon = 1 store なので発火しない。

### 5. raw `Store::get` の crate-private 化 (= bypass 経路の物理削除)

Codex Critical #1 の指摘どおり、cap 経由の getter とは別に
**「key 文字列を渡せば中身が返る素の getter」を public に残してはならない**
(= 全 cap gate を無効化する近道として残る)。

L1 では:

- `pub fn get(&mut self, key: &str, clock: &impl Clock) -> Option<&SecretBytes>`
  を **削除**し、`pub(crate) fn get_by_key(...)` に rename して core 内部の
  test だけが使う。
- 公開境界の getter は `authorized_get(&Capability, ...)` のみ。
- 既存の `state_of` / `source_of` 等の value-free metadata は keep (= secret
  を返さないため bypass にならない)。
- `extend_authenticated` / `regenerate` / `get_or_regenerate` / `pin_*` も
  `authorized_*` 版に置き換え、cap なしの旧版は **public から消す**
  (`pub(crate)` で core 内部テストから残す)。

= breaking change だが pre-1.0、`cache-warden` を lib として依存している
外部 crate は現時点で存在しない (= kawaz の他リポへの利用が確認できる範囲
では daemon 経由のみ)。

### 6. registry の実体 (= Store の第 4 マップ)

```rust
pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
    definitions: BTreeMap<String, Definition>,
    failure_backoffs: BTreeMap<String, FailureRecord>,
    // NEW: cap ID → (granted_key, holder)。issuance 順は CapabilityId が
    // monotonic なので別途保持しない。
    capabilities: BTreeMap<CapabilityId, RegisteredCapability>,
    failure_backoff_duration: Duration,
}

struct RegisteredCapability {
    key: String,
    holder: &'static str,
}
```

`failure_backoffs` を第 3 マップとして並置した DR-0022 と同じ pattern
(= 「lifecycle が独立した state は独立した map に持つ」)。`Store::capabilities`
の lifetime は **builder→build 時に固定**、`drop(Store)` 時にまとめて捨てる
(= cap ID 表は in-memory only)。

cap lookup は `BTreeMap::get(&cap.id)` の O(log n)、n は L1 では 1-10
オーダー (= 1 daemon が抱える cap 数 ≈ 鍵数)、実測 negligible。

### 7. authorization 判定の順序 (= DR-0010 re-auth との関係)

`authorized_extend_authenticated` / `authorized_regenerate` /
`authorized_get_or_regenerate` 内部の判定順:

1. **cap 検証** (= 本 DR の新規 gate)
   - `cap.id` が `self.capabilities` に存在し `key` が一致するか
   - 失敗 → `CapError` を返す。**runner も auth も呼ばない**
2. failure backoff 評価 (DR-0022)
3. entry / definition の lifecycle 評価
4. `runner.run` (= upstream fetch)
5. `auth.authenticate` (= re-auth prompt)
6. entry の install / state 更新

cap 判定が **最初** なのは Codex Warning #7 指摘の通り:

- 不正な caller (= 期待された cap を持たない) を runner / re-auth まで
  通すと、TouchID prompt や op CLI が走り、user が「身に覚えのない認証
  要求」を経験する (= attacker が cap を持たない adapter を作って TouchID
  spam できる、または DR-0022 backoff を消費させて DoS する)。
- cap 拒否は **upstream に何も触らない**: backoff にも記録しない (= cap
  違反は user の問題ではなく adapter 実装の bug、backoff trigger に値しない)。

### 8. adapter / handler の book-keeping

adapter 側 (`authsock.rs` / `handler.rs`) は cap を **Arc に包んで握り回す**:

```rust
// crates/cache-warden-cli/src/daemon/server.rs (改修イメージ)

pub struct Shared {
    pub store: Mutex<Store>,
    pub clock: SystemClock,
    /// Capabilities held by the control-socket handler for every
    /// user-facing key (= keys in `kv_process_policies` 集合 ∪ config
    /// `[kv.*]`)。startup 時に builder から 1 key 1 cap で受け取り
    /// `Arc<Capability>` で保持。
    pub handler_caps: Arc<BTreeMap<String, Arc<Capability>>>,
    /// Per-socket: authsock adapter が握る op_<id> 系の cap。
    pub authsock_caps: Arc<BTreeMap<String, Arc<Capability>>>,
}
```

#### handler.rs の改修

`handle_get` / `handle_set` / `handle_define` / `handle_pin` /
`handle_status` で wire request の `key` を `ctx.handler_caps.get(&key)` に
lookup し、`Arc<Capability>` を `Store` API に渡す。

```rust
fn handle_get<A, R, C>(store: &mut Store, ctx: &HandlerCtx<'_, A, R, C>, key: String, dry_run: bool)
    -> Response
{
    // validate_protocol_key は維持 (= 多層防御の前段 + error message 改善)
    if let Err(resp) = validate_protocol_key(&key) {
        return resp;
    }

    // cap lookup: handler は user-facing key の cap だけを握る
    let cap = match ctx.handler_caps.get(&key) {
        Some(c) => c,
        None => {
            // user-facing key として登録されていない (= adapter 内部 key
            // を user が触りに来た or config 由来でない random key)
            return Response::error(ErrorKind::NotFound, "no such key");
        }
    };

    // 既存の kv_process_policies 評価は cap lookup の **後** に置く
    // (= cap 不在の caller には policy 文言を返さない)
    if let Some(allowed) = ctx.kv_process_policies.get(&key)
        && !cache_warden_authsock::chain_gate_passes(ctx.requester, allowed)
    {
        return Response::error(ErrorKind::AuthFailed,
            "process not permitted to access this key");
    }

    // 以降の Store 呼び出しは authorized_* に書き換え
    if let Ok(Some(_)) = store.authorized_get(cap, ctx.clock) {
        return finish_get_with_cap(store, cap, &key, dry_run, "active", ctx.clock);
    }
    // ...
}
```

handler 側に注意点が 1 つ: `finish_get` 内部の OTP derive 経路 (DR-0016)
も `store.authorized_get(cap, ...)` 経由になる。OTP の seed は cap 持ちで
ないと読めない = `meta_is_otp` 判定 (= value-free) は cap なしで OK、
seed bytes 取得時に cap 必須。

#### authsock.rs の改修

`register_op_keys` で `Store::define` を呼ぶ箇所が cap 必須に。startup 時
builder で全 op_<id> key 分の cap を mint し、各 socket task の
`SocketState` に `Arc<Capability>` を持たせる:

```rust
// authsock.rs register_op_keys (旧)
match registry.register_op_key(&kv_key, &key.public_key, &key.title, src) {
    Ok(()) => n += 1,
    Err(e) => eprintln!(/* ... */),
}

// (新)
let cap = builder.capability_for(&kv_key, "authsock-op");
match registry.register_op_key(&kv_key, &key.public_key, &key.title, src, cap.clone()) {
    Ok(()) => { authsock_caps.insert(kv_key, Arc::new(cap)); n += 1; }
    Err(e) => eprintln!(/* ... */),
}
```

sign path (= upstream の SIGN_REQUEST 受信時) は `Arc<Capability>` を
握っているので、`store.authorized_get(&cap, &clock)` で PEM を借りられる。

`__authsock_op:<item_id>` の `:` 違反は本 DR の射程外 (= 別問題)、でも本 DR
で `authsock/op_<item_id>` 形式に rename する余地ができる (= cap 経由で
register するので、内部 key 名は core 規約に従わせる強い動機が生まれる)。
ただし rename 自体は本 DR の scope に **含めない** (= 別 PR で扱う、本 DR
は capability framework 単体に絞る)。

## Alternatives Considered

### 案 A: L1.5 chain (= cap がより上位 cap を派生できる)

```rust
impl Capability {
    pub fn derive(&self, key: &str) -> Result<Capability, CapError> { /* ... */ }
}
```

`authsock-warden` cap が `authsock/op_<id>` cap を派生し、その派生 cap が
さらに… のような委譲 chain。

**不採用理由**:

- L1 で「同一 process trust domain」と決めた以上、chain の検証は core 内に
  閉じる = chain policy を core が知るしかなくなる。Codex Info #9 が固定
  した責務境界 (「core は出口条件まで、adapter は『どの値にどの cap が
  必要か』まで」) を **逆侵犯**する。
- L1 単一 cap で全 use case が cover できる (= adapter は自分が必要な
  cap の集合を `Vec<Arc<Capability>>` で保持すれば「グループ cap」相当)。
- chain 導入は **L2 mTLS / 署名で外部主体を identify** したくなったタイミング
  で初めて意味を持つ (= 外部の認証された主体に対して権限委譲する)。in-process
  だけの段階で chain は overengineering。

### 案 B: raw `Store::get` を public に維持

DR-0014 / DR-0016 の library consumer (= 想定: 将来 `cache-warden` を Rust
library として組み込む 3rd party) のために素の getter を残す案。

**不採用理由**:

- Codex Critical #1: cap gate と並走する素の getter は **全 cap 判定を
  無効化する近道**。bypass 経路が構造的に残ると本 DR の意味がない。
- library consumer 用途は現実には存在しない (= 現状の cache-warden は
  daemon binary としてしか出荷していない、`crates/cache-warden` を直接
  depend する外部リポは ecosystem に未確認)。pre-1.0 なので breaking
  removal 可能。
- 「3rd party が cap 不要で使える」インターフェースを提供したいなら、cap
  を unit-struct で発行する `Store::trivial_capability()` のような escape
  hatch を別途用意するのが筋 (= 既定で gate あり、明示的に escape する
  形)。これは L1 では作らない (= 必要になったら別 DR で追加)。

### 案 C: DR-0016 OTP value type schema の廃止 / 統合

OTP derivation を `Capability` 種別の discriminator に押し込む案
(= `Capability::Opaque(key)` / `Capability::OtpDerivation(key)` のような
タグ付き enum で、core が cap 経由で「opaque を返す or derivation を
返す」を分岐)。

**不採用理由**:

- DR-0016 が「value type は **definition の永続メタ**として持つ、core は
  解釈しない」と確定した。これを覆すと:
  - handler 層 (= OTP derivation の正規実装場所) と core 層の責務分離が
    破壊される (= core が TOTP 計算を知ることになる)。
  - 既存の `ValueMeta` / `SourceMeta` (DR-0018 §2) の置き場が宙に浮く。
  - status / persistence / idempotency (DR-0014 §1 exact-match) の枠が
    壊れる。
- Codex Warning #6 でも明示的に「ValueMeta は維持」が確定済。
- cap は **「誰が触れるか」** の権限、value type は **「どう解釈するか」**
  の semantics で独立した軸。重ねるべきでない。

### 案 D: cap を全 API (= value-free metadata 含む) に必須化

`Store::list` / `Store::keys` / `Store::is_defined` / `Store::status` 系
にも cap を要求し、「unrestricted operator」を消す案。

**不採用理由**:

- handler 層の `kv list` / `status` を実装すると「全 key の cap を集める」
  loop が必要になり、cap registry を逆 lookup する API が要る (=
  `Store::capabilities_for_listing()` のような super-cap が要る = 結局
  「無制限 cap」を作るのと同じ)。
- value-free metadata は **secret を露出しない** = bypass 価値ゼロ。
  gating する設計上の動機が無い。
- DR-0012 (process access policy) も同じ判断 (= list は晒す、get は閉じる)
  を採用しており、本 DR がそれに揃うのは整合的。

### 案 E: cap を `Arc<dyn Capability>` の trait object に

将来の L2/L3 拡張 (= mTLS / 署名付き cap) を見越して trait に抽象化する案。

**不採用理由**:

- L1 で trait object 化すると `Capability` の比較・lookup が dynamic
  dispatch を経由し、dual-impl の equality 判定が `Any::downcast` 頼みに
  なる (= core の内部実装が「knows about all impls」をやり始める)。
- L1 が `Capability` 構造体 1 種で十分。L2 で別種が出てきた時点で
  `enum Capability { L1(L1Cap), L2(L2Cap) }` の variant 追加で対応できる
  (= newtype / enum の **拡張余地は構造的に存在**、trait object 化は今は不要)。

### 案 F: 永続化 (Lost-cap 復旧用)

cap ID + key の対応を state dir に書き出し、再起動後も同じ cap が adapter
に渡される案。

**不採用理由**:

- 合意済の「Lost-cap は永続化しない、再起動で reset」と直接矛盾。
- 永続化すると `cap.id` が「daemon process 跨ぎで stable な識別子」になり、
  この ID が他経路 (log / status / handoff) で露出した瞬間に **forge 可能な
  値**として扱う必要が出る (= 永続 ID 経由で偽 cap を作れるリスク)。
- daemon の SIGHUP-graceful-restart / DR-0021 watchdog `_exit(0)` 系経路で
  「cap registry も state handoff」と一緒に persist する設計余地は本 DR で
  封じる (= 再起動 = 新 trust session、過去 cap を信用しない)。
- L1 では「再起動 → 全 cap reset → adapter は再 mint された cap で再開」
  で何も壊れない (= cap ID は adapter 内部にしか流れない、再 mint しても
  外向き API は不変)。

### 案 G: in-process token と remote attestation を 1 つの抽象に

将来の L3 (= IPC 越し adapter / リモート caller) を見越して、本 DR で cap
の wire format を仮定する案。

**不採用理由** (Codex Warning #8):

- L3 の「remote attestation」は構造的に別物 = 鍵交換 / 署名検証 / replay
  対策が要る。in-process token (= Rust 参照渡し) と同じ抽象に乗せるのは
  semantic を腐らせる。
- 本 DR は **in-process token に限定**。L3 が要件化した時点で「opaque な
  authorization context」を `Capability::Remote(RemoteAttestation)` の形で
  別 variant 追加 = 構造的拡張余地は確保 (= enum 化で済む)。

## Why core

### 1. core にしか置けない判定

- cap registry は `Store` と同じ lifetime (= startup → daemon shutdown) を
  持ち、`Store::entries / definitions / failure_backoffs` と並列の第 4 map。
  adapter 側に置くと cap が「複数 adapter で 1 個の store を共有する場合」
  に矛盾する (= どの adapter が cap の registry を持つか曖昧)。
- secret 取得 (= `entries.get` / `expose_secret`) の gate は **secret に
  最も近い場所** で評価するのが最小権限原則。core より外で判定すると core
  との間に「cap なしで secret を吐く API」が必要になり、本 DR の目的と矛盾。

### 2. 責務分離との整合

DR-0003 の責務分離:

- core: 秘密値の KV キャッシュ + lifecycle
- adapter: プロトコル変換

cap は「**core が adapter に対して発行する access token**」= core 側に
issuance / verification を置くのが定義どおり。adapter 側に置くと:

- adapter が自分用の cap を自由に発行できる = bypass surface が再生する
- adapter 間の cap 検証が adapter cross-talk になり、cross-cutting concern
  として複雑化

### 3. Codex Info #9 との一致

「core は出口条件の機械判定まで、adapter は『どの値にどの cap が必要か』
の決定まで」境界の固定。本 DR の API design:

- core (`authorized_*`) = cap と key の exact-match 判定 + secret 取得
  (= 機械判定)
- adapter (`handler.rs` / `authsock.rs`) = 起動時 builder で「自分が必要な
  cap」を列挙 + 各 request にどの cap を渡すか決定 (= 政策判定)

両者が grep 1 発で分離されている。

## Trade-off

| 観点 | 良い面 | 悪い面 |
|---|---|---|
| 責務分離 | adapter が core API を呼ぶには cap が必須、bypass 経路が型レベルで消える。`grep -n 'fn authorized_'` で gate の全集合が列挙できる | API surface が複雑化 (= `authorized_get` の長い名前を adapter / handler 全箇所で書く)。慣れるまで認知負荷あり |
| 安全性 | accidental bypass (= 今の `op_kv_key` 状況) が構造的に発生し得ない (= cap なしでは secret API を呼べない) | malicious adapter (= 同 binary に組み込まれた敵対 code) は防げない (= type system の限界、明文化済) |
| 拡張性 | enum 化 (`L1Cap` → `L1(...) / L2(...) / L3(...)`) で将来余地が構造的に確保される | L1 単一 cap は将来 chain / 委譲が要件化したとき API 拡張が必要 (= 本 DR で chain は不採用) |
| Lost-cap | 永続化しない設計で `cap.id` が secret な操作 ID にならない (= 過去 ID を log しても害がない、forge できない) | 再起動後の adapter は cap を作り直す必要がある (= startup orchestration の責務が増える、Builder で startup 一発処理する設計で吸収) |
| 実装規模 | 中規模 (= `capability.rs` 新規 300 SLOC + `Store` API 全 secret 動詞改修 200 SLOC + adapter / handler 配線 200 SLOC + テスト 400 SLOC ≈ 1100 SLOC) | pre-1.0 を活かす breaking change (= `Store::get` 等の素の API が消える)、CHANGELOG での semver minor bump 必須 |
| dogfood への効果 | `__authsock_op:zl4...` 型の「user 面から見えない / forget できない adapter 内部 key」を **構造的に user 操作面に出さない判断** が legitimize される (cap 経由でしか触れないから user 面に晒す必要がない) | 即時の forget UX 改善は本 DR 単体では完了しない (= 別 issue `2026-06-14-internal-key-forget-interface.md` の NS 正規化 / reserved NS bouncer と組み合わせて完成) |

### Limits (= 明文化必須)

- **同一 process 内 trust domain**: `unsafe { std::mem::transmute }` 等で
  cap struct を直接構築する code path は型では止められない。本 DR は
  **honest adapter** (= bug や mistake) からの偶発的 bypass を防ぐもので、
  malicious adapter (= 故意の forge) は防御対象外。
- **`Capability::clone()` の trace 不能**: clone は Rust の所有権モデルで
  自由にできるため、「この cap が何回 clone されたか / どの module が
  握ってるか」は実行時には追えない。debug build で `tracing::trace!` の
  hook を埋める案は提示済だが、production trace としては保証しない。
- **cap ID の monotonic counter**: `CapabilityId(u64)` は overflow しない
  前提 (= u64 ≈ 1.8e19、daemon 1 process で消費しうる cap 数を絶対に
  超えない)。万が一 overflow が現実化したら別 DR で wrap around 処理。

## Consequences

### 公開 API 変更 (semver minor bump 宣言)

- `Store::get(&mut self, key, clock)` → **削除** (`pub` から `pub(crate)`、
  rename `get_by_key`)
- `Store::set(&mut self, key, source, value, ttl, clock)` → **削除** (同上)
- `Store::define / define_with_meta` → **削除** (同上)
- `Store::extend / extend_authenticated / regenerate / get_or_regenerate /
  pin_authenticated / unpin / delete / delete_with_definition` → **削除**
  (同上)
- 新 API: `Store::authorized_*` 系全部 + `StoreBuilder` + `Capability` +
  `CapabilityId` + `CapError` + `CapDefineError`
- `Store::new()` は維持 (= cap なしの「stub store」: secret API 呼出は
  `CapError::Unknown` で fail)、`Store::builder()` が daemon の正規経路。
- value-free metadata (`list / keys / is_defined / has_value /
  pin_deadline_of / source_of / definition_of / state_of /
  failure_backoff_remaining`) は **変更なし** (= cap 不要、既存 signature
  維持)。
- `cache_warden` crate の semver: **0.x.y → 0.(x+1).0 minor bump**。pre-1.0
  なので minor で breaking 可、ただし CHANGELOG 明示 + journal に
  migration note を残す。

### Library consumer 影響

現状 library として cache-warden を depend している外部リポは確認できる
範囲では存在しない (= daemon binary としてのみ流通)。万一存在した場合:

- secret API を直接呼んでいる場合 → `authorized_*` への移行 + `Capability`
  発行を必須化
- value-free API しか使っていない場合 → 影響なし
- `Store::new()` のみ使っている test 等 → 動作するが secret API を呼ぶと
  `CapError` (= test 用に `StoreBuilder` 経由を推奨)

### 依存追加なし

- `Capability` / `StoreBuilder` 共に `std` のみで実装可。
- `tracing` (= debug build の cap clone trace) は既存依存。
- DR-0002 (= cache-warden lib は依存最小) 不変。

### handler / adapter の配線

- `crates/cache-warden-cli/src/daemon/server.rs` の `Shared` に
  `handler_caps: Arc<BTreeMap<String, Arc<Capability>>>` 追加
- `crates/cache-warden-cli/src/daemon/handler.rs` の `HandlerCtx` に
  `handler_caps` の参照を追加、各 `handle_*` で lookup
- `crates/cache-warden-cli/src/daemon/authsock.rs` の `register_op_keys` /
  `spawn_listeners` で startup 時に cap を mint し `SocketState` に保持
- `register_op_keys` の signature 変更 (cap を受け取って registry に渡す)

### 既存 DR との関係

- **DR-0003**: 本 DR は DR-0003 の責務分離を **実装で強制**するレイヤ。
  「分離してるはずなのに侵犯してる」状態を構造的に解消。
- **DR-0014**: definitions 分離 + entries 分離の延長として cap も第 4 map
  に分離。lifecycle (= startup → shutdown) は他 3 map と一致。
- **DR-0016 / DR-0018**: ValueMeta / SourceMeta は **完全に維持**。本 DR が
  追加するのは「誰が触れるか」の軸、これらは「何をどう解釈するか」の軸で
  独立。
- **DR-0010**: re-auth は cap 判定の **後**。cap 拒否は upstream / re-auth
  を一切呼ばない (= unprivileged caller が TouchID prompt を spam できない)。
- **DR-0022**: failure_backoffs を第 3 map にした pattern と同型で第 4 map
  を追加。
- **DR-0012**: key-level process access policy (= chain_gate_passes) と本
  DR の cap は **直交軸**。両方とも handler が evaluate する; cap は「この
  caller が core API を呼べるか」、policy は「この requester が key の
  secret を取得できるか」。順序は cap 先 → policy 後 (= cap 不在は
  registered key ですらないので NotFound、policy 違反は AuthFailed と
  分離)。

### issue `2026-06-14-internal-key-forget-interface.md` との関係

本 DR は issue で確定した「`StoreKey` newtype + 公開 API validation 強制」
の **権限軸への一般化**。issue の `StoreKey` 案は「入力面 (= 不正キーを
作れない)」を塞ぐ、本 DR は「出力面 (= 不正キーを既存 store に push
できない、許可された主体しか操作できない)」を塞ぐ。両者は補完関係。

実装順序の推奨:

1. 本 DR (= capability framework) を先に land
2. 続いて `StoreKey` newtype + NS 正規化 + reserved NS bouncer を別 DR で
   (= 入力面)
3. authsock 内部 key の rename (`__authsock_op:` → `authsock/op_`) は別 PR

## Implementation Notes

### 1. `capability.rs` 新規

```rust
// crates/cache-warden/src/capability.rs

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId(u64);

impl CapabilityId {
    pub(crate) fn next(counter: &AtomicU64) -> Self {
        Self(counter.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug, Clone)]
pub struct Capability {
    pub(crate) id: CapabilityId,
    pub(crate) key: String,
    pub(crate) holder: &'static str,
}

impl Capability {
    pub fn id(&self) -> CapabilityId { self.id }
    pub fn key(&self) -> &str { &self.key }
    pub fn holder(&self) -> &'static str { self.holder }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    KeyMismatch { cap_key: String, requested: String },
    Unknown { id: CapabilityId },
    Revoked { id: CapabilityId },
}

impl std::fmt::Display for CapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapError::KeyMismatch { cap_key, requested } => write!(
                f, "capability grants {cap_key:?}, not {requested:?}"
            ),
            CapError::Unknown { id } => write!(
                f, "capability {id:?} not registered in this store"
            ),
            CapError::Revoked { id } => write!(
                f, "capability {id:?} has been revoked"
            ),
        }
    }
}

impl std::error::Error for CapError {}
```

### 2. `StoreBuilder` + `Store::capabilities` 改修

```rust
// crates/cache-warden/src/store.rs

pub struct StoreBuilder {
    pending: Vec<(CapabilityId, String, &'static str)>,
    failure_backoff: std::time::Duration,
    counter: std::sync::atomic::AtomicU64,
}

impl StoreBuilder {
    pub fn new() -> Self {
        Self {
            pending: Vec::new(),
            failure_backoff: std::time::Duration::ZERO,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn capability_for(
        &mut self, key: impl Into<String>, holder: &'static str,
    ) -> Capability {
        let id = CapabilityId::next(&self.counter);
        let key = key.into();
        self.pending.push((id, key.clone(), holder));
        Capability { id, key, holder }
    }

    pub fn set_failure_backoff(&mut self, d: std::time::Duration) -> &mut Self {
        self.failure_backoff = d;
        self
    }

    pub fn build(self) -> Store {
        let mut caps = BTreeMap::new();
        for (id, key, holder) in self.pending {
            caps.insert(id, RegisteredCapability { key, holder });
        }
        Store {
            entries: BTreeMap::new(),
            definitions: BTreeMap::new(),
            failure_backoffs: BTreeMap::new(),
            capabilities: caps,
            failure_backoff_duration: self.failure_backoff,
        }
    }
}
```

### 3. `Store` の secret API を `authorized_*` に置き換え

各 `authorized_*` の共通前段:

```rust
fn check_cap(&self, cap: &Capability, requested: &str) -> Result<(), CapError> {
    match self.capabilities.get(&cap.id) {
        Some(reg) if reg.key == cap.key && reg.key == requested => Ok(()),
        Some(reg) => Err(CapError::KeyMismatch {
            cap_key: reg.key.clone(), requested: requested.to_string()
        }),
        None => Err(CapError::Unknown { id: cap.id }),
    }
}
```

注意: `cap.key` と `requested` の double check は **`cap` 構造体内 vs
registry 内** の整合 (= attacker が cap 構造体の key field を mutate
できる場合の最後の砦)。`cap.key` は `pub(crate)` なので外部 mutate は型で
止まるが、registry 側を「真実の source」として常に参照する。

### 4. handler / adapter 配線

`spawn_listeners` / `bind_control_socket` 前段に **builder 段階**を作る:

```rust
// crates/cache-warden-cli/src/daemon/server.rs (改修)

pub async fn run(cfg: Config, ...) -> Result<(), DaemonError> {
    let mut builder = Store::builder();
    builder.set_failure_backoff(cfg.daemon.fetch_failure_backoff);

    // 1. config `[kv.*]` 由来の user key 全部に cap を mint
    let mut handler_caps = BTreeMap::new();
    for (key, _spec) in &cfg.kv {
        let cap = builder.capability_for(key.clone(), "handler-kv");
        handler_caps.insert(key.clone(), Arc::new(cap));
    }

    // 2. authsock 由来の op_<id> key 全部に cap を mint (discover 後)
    let discovered = blocking_spawn(discover_all_sources(&cfg.authsock.sources)).await?;
    let mut authsock_caps = BTreeMap::new();
    for keys in discovered.values() {
        for key in keys {
            let kv_key = op_kv_key(&key.item_id); // 旧形式は別 DR で rename
            let cap = builder.capability_for(kv_key.clone(), "authsock-op");
            authsock_caps.insert(kv_key, Arc::new(cap));
        }
    }

    // 3. store を frozen で取り出す
    let store = builder.build();
    let shared = Arc::new(Shared {
        store: Mutex::new(store),
        clock: SystemClock,
        handler_caps: Arc::new(handler_caps),
        authsock_caps: Arc::new(authsock_caps),
    });

    // 4. listener spawn
    bind_control_socket(&shared, ...).await?;
    spawn_listeners(&cfg.authsock.sockets, ..., shared.clone(), ...);
    // ...
}
```

cap mint と store build が同期 (= 全 cap が build 前に集まる) なので、
discover が長引く (= DR-0023 Phase 1 は blocking pool で実行) と全 listener
起動が遅れる。dogfood で許容範囲か観察、駄目なら DR-0023 と同 pattern の
2 stage (= 起動時 cap = config 由来のみ、authsock cap は discover 完了後に
**新規 builder** で別 store を作って swap = 既存 cap ID は同じ store
死亡で全部無効化される) を検討。Open Question Q3 で扱う。

### 5. テスト戦略

`crates/cache-warden/src/capability.rs` および `store.rs` の test module で:

#### Red first (= 失敗するテストを先に書く)

1. **cap なしで secret API を呼ぶと CapError**: `Store::new()` (= cap なし
   builder) で `authorized_get(&some_cap, &clock)` → `CapError::Unknown`
2. **他 key の cap で呼ぶと KeyMismatch**: builder で `cap_a` (key "A") /
   `cap_b` (key "B") 発行、`authorized_get(&cap_a, ...)` で key "B" の
   secret を取ろうとする path がそもそも書けないことを compile-time で
   確認 (= cap struct が key を持っているので「cap_a で B を取る」呼び
   方ができない)、加えて `check_cap` の内部で `cap.key != registry.key` の
   ケース (= cap 構造体の改竄を想定) を unit test
3. **cap を別 store から渡すと Unknown**: `store_a.builder()` の cap を
   `store_b` に渡すと `CapError::Unknown`
4. **value-free API は cap なしで動く**: `Store::new()` で `list()` /
   `keys()` / `is_defined()` 等は cap 関係なく動く
5. **cap 拒否時 runner / auth は呼ばれない**: `RecordingRunner` /
   `RecordingAuthenticator` を使い、`authorized_regenerate` を不正 cap で
   呼んで両 recorder の call_count が 0 を確認
6. **cap 経由なら従来動作**: cap 経由で `authorized_set` → `authorized_get`
   → `authorized_extend` → `authorized_regenerate` の full lifecycle が
   既存テスト (= DR-0011 / DR-0014 系) と等価
7. **`StoreBuilder` 後 mint 不能**: `build()` 後の `Store` には cap 発行
   メソッドが **存在しない** (compile-time 保証、test は `Store` の
   `impl` に `capability_for` がないことを doctest 風に確認)
8. **`handler.rs` 側の integration test**: cap を持たない key を wire
   request で叩くと `NotFound` (cap 不在は user に「key 自体がない」と
   見せる、policy 違反は AuthFailed = 区別を test)

#### 既存テスト改修

`crates/cache-warden/src/store.rs::tests` の全 cmd_entry / 既存 fixture を
`StoreBuilder` 経由に書き換え。`Store::new()` のままだと secret 呼出が
全部 CapError で落ちる。

`crates/cache-warden-cli/src/daemon/handler.rs::tests` の `ctx` fixture
(= `HandlerCtx`) は `handler_caps` 引数を追加。`empty_policies()` と同じく
`empty_caps()` 静的 BTreeMap を用意。

### 6. tracing

- cap mint: `tracing::debug!("cap minted: id={id} key={key} holder={holder}")`
- cap reject: `tracing::warn!("cap rejected: holder={holder} requested={key} reason={err}")`
- (debug build) cap clone: `tracing::trace!("cap cloned: id={id} holder={holder}")`

production log は `debug` 以上で抑制 (= cap minting は startup 1 発のみ)。

## Open Questions

### Q1: cap ID の安定性 vs 揺らぎ

L1 では `cap.id` は **同一 process 内のみ stable**。再起動で全部 reset、
adapter は新 cap を mint してもらう。

- **問**: handoff / SIGHUP-graceful-restart で「同じ cap ID を新 process
  に引き継ぐ」要件が出たらどうするか?
- **暫定設計**: 引き継がない (= 新 process は新 cap を builder で mint)。
  cap ID は外部 wire に出ない (= adapter 内部で `Arc<Capability>` を借りる
  のみ) ので、引き継ぎ要件は理屈上発生しない。発生したら別 DR。

### Q2: 名前 (= key 文字列) の再導出

cap 経由の `authorized_delete(&cap)` は key 文字列を引数に取らない
(= cap が key を握っている)。一方 `handle_set` で wire request の `key`
と cap の key が一致しているか runtime check するべきか?

- **暫定設計**: handler 側で「wire request の key で cap を lookup」する
  段階で一致が保証される (= `handler_caps.get(&wire_key) → Some(cap)` で
  cap.key == wire_key)。core 側で二重 check するのは冗長。
- ただし `authorized_set / authorized_define` のように cap の他に `source`
  を別途渡す API は、cap の key と source の指す key が一致するかを test
  で確認する仕様にしておく (= source.cwd 等は cap と独立、key は cap が
  正本)。

### Q3: discover 遅延と cap mint タイミング

DR-0023 Phase 1 で authsock op discover は blocking pool 上で同期実行。
discover が長引くと `StoreBuilder` の `build()` が遅れ、control socket の
bind も遅れる。

- **問**: control socket は discover 結果を待たずに早期 bind したい
  (= user の `kv set` を即座に受けたい)、しかし authsock cap も同 store の
  builder で mint したい (= cap 表は 1 process 1 表) — 矛盾する
- **暫定案 A**: 2 stage build。phase 1 で config `[kv.*]` の cap を mint
  → `Store` build → control socket 起動。phase 2 で discover 完了後に
  **新 Store** を別 builder で構築し、handler 側を `swap_store` で差し替え
  → 旧 store は drop。**問題**: in-flight request が旧 store を握って
  いる場合の race。
- **暫定案 B**: builder を mutex に包み、discover 完了まで mint 受付可能に
  し、build を遅延。control socket は別 path で「discover 完了待ち」
  応答を返す。
- **解は本 DR の射程外**、別 DR で扱う (= DR-0023 follow-up)。

### Q4: Lost-cap の warning 手段

cap を渡した adapter が panic / drop した場合、cap 表に「registered だが
holder が居ない」エントリが残る。in-memory only なので process 終了で
消えるが、稼働中の status / log で表示すべきか?

- **暫定設計**: warning しない (= cap 自体は registered なら有効、holder
  の生存は core の責務ではない)。cap が「使われない」のは adapter の
  bug = adapter 側の `tracing` で検出すべき。
- 加えて `Capability` を `Arc<Capability>` で持つので、`Arc::strong_count`
  で「いま誰が握ってるか」は外部から見れる (= 必要なら status に出せる)。

### Q5: DR-0016 派生処理の置き場 (OTP)

`finish_get` で OTP derivation は cap で gate された seed 取得後に行う。
seed bytes は `expose_secret` で借り、derive_code に渡して捨てる。

- **問**: derivation のために生 seed を一度メモリに取り出すのは「最小権限
  原則」に反するか? cap が「seed を読む権限」と「code を生成する権限」を
  別軸で持つべきか?
- **暫定設計**: 別軸にしない (= 1 cap = 1 key、derivation は handler 層の
  「value type 解釈」responsibility、cap は core 層の「access 認可」
  responsibility で分離済み)。derivation の責務を cap 軸に折り込むと
  DR-0016 を覆すことになる (= 案 C で却下済)。

### Q6: IPC 拡張時の attestation 設計

将来 L3 で IPC 越しの adapter (= 別 process の adapter binary) が同 store
に接続するケース。

- **問**: in-process cap (= 本 DR) は Rust 参照渡し前提なので IPC では
  使えない。L3 で「remote attestation」(= mTLS 証明書 / 署名付き token /
  challenge-response) を導入するとして、`Capability` enum に variant 追加
  で対応できるか?
- **暫定設計**:
  - `enum Capability { L1(L1Cap), L3(L3RemoteCap) }` のように variant 化
  - L3 variant は内部に attestation context (= 検証済の peer identity +
    認可 scope) を持つ
  - 検証 (= `check_cap` の内部) で L3 variant は signature / cert / nonce
    の validity を再 evaluate (= replay 対策)
  - L1 / L3 共に「`cap.granted_key == requested` を判定」の最終段は共通
- 本 DR では variant 拡張余地のみ確保、L3 設計は別 DR (= 候補 DR-0025+)。

### Q7: `Capability::Display` の漏洩

`tracing::warn!("cap rejected: holder={holder} requested={key}")` で
`holder` と `requested` (= key 名) が log に出る。key 名は秘密ではない
(= DR-0017 / DR-0018 で「key 名は status / list で公開」と確定済) ので
漏洩リスク無し。

ただし `cap.id` を log に出す場合は per-process 限定値であることを comment
で明示しておく (= 「他 process の cap.id と一致しても同 cap ではない」)。

### Q8: cap-gated API の async 化

future の async refactor (= DR-0023 Phase N+) で `Store::authorized_*` が
async 化する可能性。

- **問**: cap を borrow したまま .await すると lifetime が複雑化する
  (= `&Capability` を hold したまま await できるか)
- **暫定設計**: `Arc<Capability>` を渡す pattern を最初から推奨する
  (= handler / adapter 側で `Arc::clone` してから `.await` を超える)。
  Rust の borrow checker が future 化で苦しめば pattern 変えるが、L1 は
  同期 API のみ。

## Related

### code

- `crates/cache-warden/src/store.rs` (= 全 secret API を `authorized_*` に
  改修対象、特に L144-L654 の `impl Store`)
- `crates/cache-warden/src/capability.rs` (= 新規)
- `crates/cache-warden/src/entry.rs` (= 変更なし、`CacheEntry` は core
  内部 primitive)
- `crates/cache-warden/src/definition.rs` (= 変更なし、`Definition` は
  cap と独立)
- `crates/cache-warden/src/meta.rs` (= 変更なし、`ValueMeta` /
  `SourceMeta` は DR-0016 / DR-0018 で確定済、本 DR は触らない)
- `crates/cache-warden/src/auth.rs` (= 変更なし、Authenticator は cap
  判定後に評価される)
- `crates/cache-warden-cli/src/daemon/server.rs` (= `Shared` 構造体 +
  `handler_caps` / `authsock_caps` の Arc 追加、startup orchestration の
  builder phase)
- `crates/cache-warden-cli/src/daemon/handler.rs:1-580` (= `HandlerCtx` に
  `handler_caps` 追加、全 `handle_*` で cap lookup → `authorized_*` 呼出)
- `crates/cache-warden-cli/src/daemon/authsock.rs:188-300` (=
  `register_op_keys` で startup 時 cap mint、`SocketState` に
  `Arc<Capability>` 保持)
- `crates/cache-warden-cli/src/daemon/authsock.rs:75-110` (= `build_registry`
  も cap 経由の `store.authorized_get` に書き換え)

### docs

- DR-0003 (= core / adapter 責務分離、本 DR の根本動機)
- DR-0004 (= NotLoaded を core に持ち込まない判断、本 DR の cap 配置と同型)
- DR-0010 (= re-auth command、cap 拒否との順序)
- DR-0011 (= TTL 2 分離 + pin、本 DR で `pin_authenticated` も cap 必須化)
- DR-0012 (= process access policy、本 DR とは直交軸)
- DR-0014 (= entries / definitions 分離、第 4 map 追加の前例)
- DR-0016 (= OTP value type、ValueMeta 維持)
- DR-0018 (= typed sources、SourceMeta との独立性)
- DR-0022 (= failure_backoffs 第 3 map、本 DR の同型 pattern)
- DR-0023 (= startup blocking pool、本 DR の Q3 follow-up)

### issue / journal

- `docs/issue/2026-06-14-internal-key-forget-interface.md` (= 本 DR の起点、
  `StoreKey` newtype 案と相補)
- `docs/issue/2026-06-14-op-refetch-loop.md` (= dogfood で発見、本 DR とは
  直接対応しないが「内部 key の forget 不能」関連)
