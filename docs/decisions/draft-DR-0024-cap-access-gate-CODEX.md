# draft-DR-0024: capability-based access gate (L1)

- Status: Draft
- Date: 2026-06-14
- Related DRs: DR-0003 / DR-0014 / DR-0016 / DR-0018 / DR-0022

## Context

cache-warden の core は DR-0003 で「秘密値の secure KV cache」として定義され、control socket / authsock / OTP などはその上のアダプタである、と整理された。しかし現行実装ではこの境界が十分に強制されていない。

具体的には `Store::get(&mut self, key, clock) -> Option<&SecretBytes>` が public API として存在し、アダプタやライブラリ利用者が TTL 評価後の秘密値を直接借りられる。handler 層には key-level process gate、dry-run、OTP seed の write-only 変換などの制御があるが、同じ process 内の別コードが `Store::get` を直接呼べば、それらを迂回できる。

この問題は、単なる「関数の visibility が広い」だけではない。DR-0014 で定義と値を分離し、DR-0016 で OTP seed を write-only とし、DR-0018 で authsock 内部鍵を専用 namespace に寄せるほど、秘密値を読む経路はますますアダプタごとの意味論を持つ。ところが raw getter が public のままだと、その意味論はレビュー規約でしか守られない。

本 DR は L1 として、同一 process 内での capability-based access gate を導入し、秘密値 raw access を明示的に capability 保持コードへ限定する。これは暗号的な分離ではない。Rust の型・module 境界を使った「意図しない bypass を起こしにくくし、レビューで見つけやすくする」ための設計である。

## Decision

L1 では、`Store` インスタンスごとに単一 capability を発行し、raw value access はその capability を要求する API に限定する。multi-cap chain や delegating chain は採用しない。

決定事項:

- `Store::get` は public API から外す。crate-private helper にするか、cap-gated API へ置き換えて public raw getter を消す。
- `Store` は `StoreBuilder` 経由で構築する。builder が adapter capability を発行し、daemon の `Shared` に必要な cap を保持させる。
- 1 つの `Store` が持つ capability root は単一。L1.5 の cap chain は扱わない。
- control socket / authsock / OTP adapter は、startup 時に daemon が配った cap を保持して raw read する。request payload に cap ID や `from_adapter` を載せない。
- `Store::define` は L1 では cap を要求しない。定義は値を含まない設定データであり、DR-0014 の lazy define / authsock A-3a を壊さないためである。
- DR-0016 の schema は維持する。OTP の値型 metadata は definition に残し、TOTP 変換は OTP adapter が担う。`handler.rs` は OTP math を持たない方向へ移す。
- capability の紛失時 recovery は in-memory only。永続化しない。cap を失った adapter は raw value にアクセスできず、再起動または reauth / rebuild による再配布まで利用不能とする。
- IPC adapter identity attestation は Phase 3+ に defer する。本 DR は同一 daemon process 内の API boundary を対象にする。

## Alternatives Considered

### L1.5: capability chain / delegated caps

不採用。chain は「control cap から OTP cap を派生」「authsock cap は PEM だけ」などの表現力を持てるが、L1 の主問題は public raw getter である。chain を入れると、revocation、debug 表示、cap comparison、serde 誤用、clone policy まで設計範囲が膨らむ。最初に塞ぐべき穴に対して過剰で、実装レビューも難しくなる。

### raw getter retention

不採用。`Store::get` が public に残る限り、capability は任意機能になる。adapter が「正しい経路」を使うことを期待しても、ライブラリ利用者や将来の adapter が raw getter を呼べば bypass は再発する。特に OTP seed の write-only 性質は raw getter 1 つで崩れる。

### String-based cap ID

不採用。`"authsock"` / `"cli"` / UUID 文字列を request や API に渡す方式は、同一 process 内の型境界を捨てて、比較対象を data に落とす。文字列はログ、config、テスト fixture、IPC payload へ容易に漏れ、spoof も容易である。L1 では private-field newtype を使い、外部 crate が forge できない値にする。

### `register_adapter(&mut self)` pattern

不採用。`Store` を作った後で mutable registration する方式は、未登録期間、二重登録、テスト fixture の登録漏れを作る。さらに `Store::new()` が public のまま残りやすく、capability なし Store を作る逃げ道になる。builder が Store と caps を同時に返す方が、初期化完了状態を型で表しやすい。

### DR-0016 abolition

不採用。OTP を通常 opaque value に戻したり、handler で seed をそのまま返せる escape hatch を作る案は、本 DR の目的と逆方向である。DR-0016 の「seed は cached secret、code は derived view」という分離は維持し、capability は seed raw read を OTP adapter に限定する補助線として使う。

### IPC request payload carries `from_adapter`

不採用。Unix socket の request body に `{ "from_adapter": "authsock" }` を載せても、現在の threat model ではただの自己申告である。control socket に接続できる peer はその文字列を自由に書ける。peer pid / ancestry gate はあるが、それは process policy であり adapter identity attestation ではない。よって cap routing は daemon 内部の dispatch table で決める。

## Why This Works / Design Correctness

この設計が防ぐものは限定的である。

防ぐもの:

- adapter 実装者がうっかり `Store::get` を直接呼び、handler の process gate / OTP write-only / authsock namespace 制約を飛ばす事故。
- code review で raw access の正当性を追えない状態。cap-gated API に寄せると、秘密値 raw read は `get_with_cap` 相当の呼び出しに集中する。
- lint / grep / deny ルールの対象不明瞭さ。public `get` が消えれば、「raw read は cap API だけ」という機械チェックを置ける。
- request payload の自己申告による adapter spoof。handler は request が名乗る adapter を信じず、自分が処理している socket / path / request kind に基づき cap を選ぶ。

防がないもの:

- 同一 process 内で任意 Rust code を実行できる攻撃者。cap は暗号鍵ではなく、メモリ上の Rust value である。
- `unsafe`、FFI、debugger、process memory read による秘密値抽出。DR-0007 系の hardening は別層であり、本 DR の cap では防げない。
- `cache_warden` crate 内部の悪意ある変更。private field や `pub(crate)` は crate 内部の協力的境界であって、同じ crate に悪意あるコードを入れれば迂回できる。
- capability を保持する adapter 自身のバグ。cap は「誰が raw read 可能か」を狭めるだけで、読んだ後の扱いを自動で安全にしない。

それでも導入する理由は、現在の主リスクが「決意ある攻撃者」より「アダプタ境界の実装 drift」にあるためである。DR-0014 / DR-0016 / DR-0018 の積み重ねで、value read は単なる map lookup ではなくなった。raw getter を public に置いたままでは、設計上の write-only / adapter-owned translation / namespace policy がすべて convention になる。capability は convention を API surface に押し上げる。

## Handler Cap Routing

handler は各 IPC request を受け取る地点で、どの adapter の意味論で処理しているかを daemon 内部の構造から知っている必要がある。

候補 A: daemon が startup 時に `cli_adapter_cap` と `authsock_adapter_cap` を保持し、handler が request kind / listener kind に基づいて選ぶ。

候補 B: request payload が `from_adapter: "authsock"` を持ち、handler がそれを見て cap を選ぶ。

候補 B は unsafe である。Unix socket 上の JSON request は peer が作る data であり、現在の設計では adapter identity attestation がない。control socket に送られた `from_adapter: "authsock"` は、authsock から来た証明にならない。これを信じると、まさに raw getter bypass と同じ種類の「境界を data の自己申告に移す」失敗になる。

本 DR は候補 A を採用する。control socket の `run_request` は CLI / control adapter 用 cap を持つ `HandlerCtx` を構築する。authsock の `local_sign` は authsock adapter 用 cap を持つ `LocalSignCtx` を構築する。OTP adapter は control handler の中で呼ばれる派生 view ではなく、cap を持つ adapter object として呼ばれる。

## OTP Adapter Circularity

DR-0016 の現行実装では `handler.rs` が `finish_get` で OTP seed を読み、TOTP code を導出している。しかし L1 では raw read が cap-gated になるため、「OTP adapter が seed を読むには control socket 経由で `kv.get` する」という実装にすると循環する。

循環例:

1. client が control socket へ `kv.get OTP` を送る。
2. handler が definition meta を見て OTP と判断する。
3. OTP adapter が seed を得るため control socket へ `kv.get OTP` を送る。
4. handler が再び OTP adapter を呼ぶ。

この循環は採用しない。OTP adapter は daemon startup 時に発行された cap と `Arc<Shared>` または `Arc<Mutex<Store>>` への直接参照を持つ in-process adapter とする。handler は OTP key を見つけたら、socket 経由ではなく `otp_adapter.get_code(key, ctx)` を呼ぶ。OTP adapter は `Store` の lazy generate / extend / regenerate chain を通したうえで、cap-gated raw seed read を行い、code だけを返す。

この形なら DR-0016 の schema は維持される。metadata は definition に残り、seed は raw value として Store に残り、TOTP math は handler ではなく OTP adapter に移る。

## Define Policy

`Store::define` / `define_with_meta` は L1 では cap を要求しない。

理由:

- definition は値を含まない。DR-0014 では定義を値ストアから分離し、status / persistence 対象の value-free metadata として扱っている。
- authsock A-3a は startup 時に op-sourced key の definition を登録する。ここへ cap requirement を入れると、すべての schema setup が raw read 権限を持つ必要があり、権限が過剰になる。
- public raw access の主脆弱性は value read であり、define はその穴ではない。

ただし define が無害という意味ではない。definition は将来の source command 実行を予約するため、未信頼入力から define すると data-to-code 境界の問題になる。これは DR-0014 の `--defs` 明示性、DR-0018 の typed source validation、CLI / protocol key validation で扱うべき問題であり、本 DR の raw value capability とは別軸である。

## Trade-offs

| # | Trade-off | 採用判断 |
|---|---|---|
| 1 | 同一 process cap は暗号的 enforcement ではない | それでも accidental bypass と review drift を減らす価値がある |
| 2 | `Store::new()` を public のまま残すと逃げ道になる | public constructor は deprecated → private constructor へ移行する |
| 3 | builder 導入でテスト fixture が重くなる | test helper builder を用意し、cap 明示の負荷を受け入れる |
| 4 | define を cap-free にすると誰でも定義できる | value-free metadata として許容。ただし protocol / config validation は別途必須 |
| 5 | single cap は adapter 別最小権限を表現しきれない | L1 では public raw getter 排除を優先し、chain / scoped cap は後続へ送る |
| 6 | cap 紛失で値が読めなくなる | persistence しない方が安全。再起動 / reauth rebuild を recovery とする |
| 7 | OTP adapter が Store を直接持つと handler より強い権限を持つ | handler に OTP math を置くより境界が明確。adapter の raw read 箇所をレビュー対象に集中できる |
| 8 | public API 破壊が起きる | pre-1.0 として minor bump で扱う。ただし migration path は明示する |

## Consequences

### Public API changes

- `Store::get` は public API から削除または `pub(crate)` 化する。
- 新 API は概ね `Store::get_with_cap(&mut self, key, &StoreAccessCap, clock)` の形になる。ただし名前は実装時に `borrow_secret` 等へ調整してよい。
- `StoreBuilder` を追加し、`Store` と adapter caps を同時に生成する。
- `Store::new()` は即時には削除せず、段階的に扱う:
  - Phase 1: `#[deprecated]` を付け、builder を推奨する。既存 tests / library users に移行猶予を与える。
  - Phase 2: crate 内 private constructor (`Store::new_unchecked` などの `pub(crate)`) に下げる。
  - Phase 3: public `Store::new()` を削除する。
- semver は pre-1.0 の breaking minor として扱う。CHANGELOG に「raw getter removal」「builder migration」「cap-gated raw read」を明記する。

### Migration path

既存 library consumer:

1. `Store::new()` を `StoreBuilder::new().build()` に置き換える。
2. raw value が必要な consumer は builder から返る cap を保持する。
3. raw value が不要な consumer は `state_of` / `definition_of` / `keys` / `failure_backoff_remaining` など value-free API のみ使う。
4. `Store::get` を使っていた箇所は、意図が adapter-level reveal なのか metadata check なのかを分ける。後者は raw read しない API へ移す。

daemon:

- `Shared` に control / authsock / otp adapter の cap または cap holder を保持する。
- `HandlerCtx` / `LocalSignCtx` / `OtpAdapter` へ必要な cap を参照で渡す。
- request payload には cap を載せない。

## Implementation Notes

### Core sketch

```rust
pub struct Store {
    entries: BTreeMap<String, CacheEntry>,
    definitions: BTreeMap<String, Definition>,
    failure_backoffs: BTreeMap<String, FailureRecord>,
    failure_backoff_duration: Duration,
    access_gate: AccessGate,
}

#[derive(Debug)]
struct AccessGate {
    token: u128,
}

#[derive(Debug, Clone)]
pub struct StoreAccessCap {
    token: u128,
    // private field prevents external construction
    _private: (),
}

#[derive(Debug)]
pub enum AccessError {
    MissingCapability,
    WrongCapability,
}

impl Store {
    pub(crate) fn new_with_gate(access_gate: AccessGate) -> Self {
        Self { access_gate, ..Self::default_without_gate() }
    }

    pub fn get_with_cap(
        &mut self,
        key: &str,
        cap: &StoreAccessCap,
        clock: &impl Clock,
    ) -> Result<Option<&SecretBytes>, AccessError> {
        self.check_cap(cap)?;
        Ok(self.entries.get_mut(key).and_then(|e| e.get(clock)))
    }

    fn check_cap(&self, cap: &StoreAccessCap) -> Result<(), AccessError> {
        if cap.token == self.access_gate.token {
            Ok(())
        } else {
            Err(AccessError::WrongCapability)
        }
    }
}
```

`u128` は暗号鍵ではない。process-local equality token である。`StoreAccessCap` の field を private にし、外部 crate が通常 Rust で forge できないようにする。`unsafe` による forge は防がない。

### Builder sketch

```rust
pub struct StoreBuilder {
    failure_backoff_duration: Duration,
}

pub struct BuiltStore {
    pub store: Store,
    pub control_cap: StoreAccessCap,
    pub authsock_cap: StoreAccessCap,
    pub otp_cap: StoreAccessCap,
}

impl StoreBuilder {
    pub fn new() -> Self { ... }
    pub fn failure_backoff(mut self, d: Duration) -> Self { ... }

    pub fn build(self) -> BuiltStore {
        let token = fresh_process_local_token();
        let gate = AccessGate { token };
        let cap = StoreAccessCap { token, _private: () };
        BuiltStore {
            store: Store::new_with_gate(gate),
            control_cap: cap.clone(),
            authsock_cap: cap.clone(),
            otp_cap: cap,
        }
    }
}
```

L1 は single capability per Store なので、`control_cap` / `authsock_cap` / `otp_cap` は同じ token の clone でよい。名前を分けて返すのは daemon wiring を self-documenting にするためであり、権限差を表すものではない。

### Daemon wiring sketch

```rust
pub(crate) struct Shared {
    store: Mutex<Store>,
    runner: CommandRunner,
    auth: Auth,
    clock: SystemClock,
    control_cap: StoreAccessCap,
    authsock_cap: StoreAccessCap,
    otp_adapter: OtpAdapter,
}

pub(crate) struct OtpAdapter {
    store_cap: StoreAccessCap,
}
```

`server::run` は `StoreBuilder` で `BuiltStore` を作り、`Shared` に caps を入れる。`run_request` は `HandlerCtx { store_cap: &shared.control_cap, otp_adapter: &shared.otp_adapter, ... }` を作る。authsock の `local_sign` は `LocalSignCtx { store_cap: &state.shared.authsock_cap, ... }` を作る。

### Invariants

- public raw value read API は `StoreAccessCap` を必ず要求する。
- `StoreAccessCap` は external crate から構築できない。
- `Store::new()` は public escape hatch として残さない。残す期間は deprecated migration window のみ。
- request payload 由来の adapter name / cap ID は信用しない。
- `define` / `definition_of` / `keys` / `status` 系は value-free API として cap-free のままにする。
- OTP seed raw read は OTP adapter 内に閉じる。handler は code response を受けるだけにする。

## Test Strategy

最低限、以下を実装する。

1. unit test: missing / wrong cap rejects raw get
   - `StoreBuilder` で `store_a` と `cap_a`、別 builder で `cap_b` を作る。
   - `store_a.get_with_cap(key, &cap_a, clock)` は成功。
   - `store_a.get_with_cap(key, &cap_b, clock)` は `Err(AccessError::WrongCapability)`。
   - cap を渡さない public raw get API が存在しないことを compile-fail test か grep/lint で確認する。

2. table-driven test: adapters × cap types
   - rows: `control`, `authsock`, `otp`
   - cols: own cap, other Store cap, no cap
   - own cap は accept、other Store cap / no cap は reject。
   - L1 では adapter 間 cap は同じ Store cap clone なので、adapter 種別の accept/reject 差は作らない。差が必要になったら L1.5 の scoped cap として別 DR にする。

3. handler routing test
   - control socket request body に `from_adapter = "authsock"` 相当の未知 field / spoof field を入れても、handler が control cap routing から外れないことを確認する。
   - serde が unknown field を拒否する場合は bad request、許容する場合でも cap selection に使わない。

4. OTP circularity regression
   - OTP key の `kv.get` が control socket へ再入しないことを、fake `OtpAdapter` の direct-call counter で確認する。
   - handler の OTP math 関数呼び出しを削除し、OTP adapter が code を返す経路だけを通す。

5. define remains cap-free
   - authsock A-3a 相当の startup lazy definition registration が cap なしで成功する。
   - define 後も raw get は cap なしでは失敗する。

## Open Questions

1. `Store::new()` の削除タイミングをどの release に置くか。pre-1.0 とはいえ、tests / downstream examples の移行量が大きい場合、deprecation window を 1 minor 置くべきか。
2. L1 の single cap で十分か。authsock PEM、OTP seed、opaque KV value を同じ cap で読めるため、adapter compromise 時の blast radius は広い。scoped cap は L1.5 として分けるべきか。
3. `StoreAccessCap` の token 生成は何で行うか。`rand` dependency を core に入れるか、atomic counter + process salt で足りるか。暗号境界ではないが、predictable token は test 以外で気持ち悪い。
4. cap-gated API の戻り値は `Result<Option<&SecretBytes>, AccessError>` でよいか。wrong cap と missing key の区別は audit には有用だが、adapter response へ漏らすと情報差になる。
5. compile-fail test をどこまで入れるか。`trybuild` 依存を増やすか、public API grep / rustdoc JSON check で済ませるか。
6. OTP adapter の crate / module 配置をどうするか。CLI crate 内 module のままか、将来の typed derived views を見越して adapter trait を切るか。
7. `define` を cap-free にする方針は L1 では妥当だが、malicious local client が大量 definition を登録する DoS には効かない。これは protocol auth / quota の別 DR に分離してよいか。
8. `StoreKey` newtype / namespace validation issue と本 DR の実装順序。key validation を先に入れると cap API signature も同時に変わるため、破壊変更を 1 回にまとめるべきか。
9. lost-cap recovery の user experience。daemon 内部 bug で cap holder を落とした場合、再起動以外の recovery command を用意すべきか、それ自体が cap persistence の穴になるため拒否すべきか。
10. lint hook の具体形。`Store::get` public symbol の不在、`SecretBytes::expose_secret` 呼び出し箇所の allowlist、OTP seed raw read の module allowlist を CI でどう表現するか。

## Related

- [DR-0003](./DR-0003-secure-kv-core-and-adapters.md) — core と adapter の責務分離。本 DR はその API 境界を強める。
- [DR-0014](./DR-0014-kv-definition-model.md) — definition は value-free metadata。本 DR で define を cap-free にする前提。
- [DR-0016](./DR-0016-otp-value-type.md) — OTP seed write-only / derived code。OTP adapter の権限境界に関係する。
- [DR-0018](./DR-0018-typed-sources-auth-and-prefetch.md) — typed source / authsock namespace / prefetch。adapter wiring と cap routing の前提。
- [DR-0022](./DR-0022-fetch-failure-backoff.md) — Store builder migration と failure_backoff 設定の前例。
- [docs/issue/2026-06-14-internal-key-forget-interface.md](../issue/2026-06-14-internal-key-forget-interface.md) — core API validation 欠落の隣接問題。
