# draft-DR-0024: Opus 案 vs Codex 案 比較レビュー

- Status: Review (= 最終 DR-0024 起草の判断材料)
- Date: 2026-06-14
- Reviewer: nitpick-reviewer (Opus メインへ返却)
- 比較対象:
  - `draft-DR-0024-cap-access-gate-OPUS.md` (1162 行、Open Q 8 件、Alternatives 7 件)
  - `draft-DR-0024-cap-access-gate-CODEX.md` (327 行、Open Q 10 件、Trade-off 表 8 件、Alternatives 6 件)
- 比較軸: 設計判断の整合性 / API surface / 完全性 / 簡潔性 / Open Q の質 /
  実装容易性 / 拡張性 / adversarial バイアス / 見落としの 9 観点

---

## 1. エグゼクティブサマリー (= 結論先出し)

**base 案推奨: Codex (= 短い方)**。ただし **Opus 案からの抜粋大量併合が必須**で、最終形は Codex 構造 + Opus 詳細注入で **600 行前後** が妥当な着地点。

理由 (要点):

- Codex 案は **責務分離の判断が一段深い**: handler が `from_adapter` を信じない、OTP adapter は handler に math を残さず adapter object として独立、define は cap 不要 — の 3 点が **Opus 案で明示されていない or 暗黙**。これらは「設計判断の根拠」として DR-0024 の core を成す。
- Opus 案は **実装で躓きにくい詳細が圧倒的に厚い**: Builder の Rust 型、`Capability` の Clone/Copy 判断、registry の data shape、判定順序、Codex review v1 の Critical/Warning 反映の追跡、テスト戦略 8 項目。これらが Codex 案では **言及のみで実装可能性に届かない**。
- ただし **両案とも致命的な見落とし**: (a) `&mut Store` lock 中の cap clone コスト = `BTreeMap` lookup 競合、(b) `Capability` を Drop しても registry が残る semantics の未定義、(c) `Capability` の `Debug` derive が cap.key を log に漏らす risk、(d) `Store::new()` を残す/廃止の判断が両案で一貫していない、(e) test 環境での cap 配布が「全テストが builder 経由」になる migration コストの見積もりが両案とも甘い。
- **両案とも撤回すべき判断**: Opus の `Capability::clone()` の `tracing::trace!` hook 案 (=「debug build 限定」と但し書きするが、`Clone` impl を手書きすると Rust の `#[derive(Clone)]` を捨てることになり、cap clone のたびに log 経由の side effect が生じる = 仕様として悪い)。Codex の `_private: ()` field は L1.5 chain 化したとき variant 化で詰む (= struct を enum に rewrite せざるを得ない)。
- **次のステップ**: Codex 案を base に Opus 案から (a) `StoreBuilder` 詳細 / (b) `CapError` enum 3 variant / (c) registry を `BTreeMap<CapId, RegisteredCapability>` で持つ shape / (d) 判定順序 (= cap 先 → backoff → lifecycle → runner → auth) / (e) Alternatives 案 A/E/F/G / (f) テスト戦略 1-8 を section 単位で取り込み、新規追加で (g) Drop semantics / (h) `Debug` 漏洩対策 / (i) test fixture 用 helper / (j) lock contention 評価 を入れる。

判断シート (短縮):

| 観点 | 推奨 | 一言 |
|---|---|---|
| 設計判断の正しさ | Codex | OTP 循環・define cap-free・handler 信用境界の **判断軸が明示** |
| 実装可能性 | Opus | Builder / registry shape / 判定順序が具体的 |
| 簡潔性 | Codex | DR-0022 v2 の質目標 (272 行) に近い |
| 完全性 | Opus | Codex review v1 の Critical/Warning を行内で追跡 |
| Open Q の質 | Codex | 「lint hook 具体形」「OTP adapter の crate 配置」「定義 DoS の境界」など本質的 |
| 拡張性 (L3) | Opus | enum variant 拡張余地を明文化 |

---

## 2. 判断比較マトリクス

凡例: ✓ = 明示、△ = 部分的 / 暗黙、× = 触れていない、!= = 両者で判断が異なる

| # | 観点 | Opus 案 | Codex 案 | 推奨 | コメント |
|---|---|---|---|---|---|
| 1 | L1 単一 cap | ✓ 1 key 単位 | ✓ 1 Store 1 cap (= 全 adapter が同 cap clone) | **Codex** | Opus は「1 cap = 1 key (exact match)」、Codex は「1 Store 全体に 1 cap、adapter 名で分割するのは self-doc のためだけ」。これは **根本的に意味が違う**。Opus 案だと N 鍵 = N cap で `Arc<BTreeMap<key, Arc<Cap>>>` を持ち回る必要がある。Codex 案だと `Arc<Cap>` 1 個で済む。L1 単純性の目標を満たすのは Codex 案。Opus 案は実質 L2 (= per-key 細粒度) を L1 と呼んでいる。**ここは要 kawaz 判断**: 「1 値 1 cap」と「1 Store 1 cap」のどちらが「L1 単一 cap」か。Codex 案を採るなら API surface が大幅に減る (= adapter は `&StoreAccessCap` 1 個だけ持ち回せばよい) |
| 2 | raw `Store::get` 廃止 | ✓ 削除 → `pub(crate) get_by_key` rename | ✓ 削除 or `pub(crate)` | **両者一致** | Codex は段階移行 (deprecated → pub(crate) → 削除) も提案、Opus は一発削除。Opus が pre-1.0 を理由に一発削除を推すのは `design-priority.md` 原則 (= 後方互換で曲げない) と一致 |
| 3 | DR-0016 OTP schema 維持 | ✓ 維持、cap は値型と直交 | ✓ 維持、OTP adapter object 化を提案 | **Codex** | Opus は schema 維持と書くだけ。Codex は **OTP adapter circularity 問題を明示し**、`otp_adapter.get_code(key, ctx)` 形式で handler から TOTP math を adapter に移すことを提案。これは Open Q ではなく Decision として書かれている。本 DR で扱うか別 DR に切るかは要判断だが、**判断の質は Codex が一段上** |
| 4 | Lost-cap 永続化 | ✓ しない、`cap.id` 公開で害がない理由を明示 | ✓ しない | **両者一致** | Opus は「cap.id が forge 可能な値になる」リスクを明文化、Codex は短く済ます。Opus が詳しい |
| 5 | IPC adapter 身分証明 | ✓ Phase 3 範囲外、L3 enum variant 拡張余地 | ✓ Phase 3 defer、本 DR は in-process 限定 | **両者一致** | Opus は将来 `Capability::Remote(...)` variant を提案、Codex は触れない。**拡張性で Opus が勝つ** |
| 6 | register 配線 = Builder | ✓ `StoreBuilder` 詳細実装あり | ✓ `StoreBuilder` 概念のみ | **Opus** | Codex の Builder は `BuiltStore { store, control_cap, authsock_cap, otp_cap }` を返すだけで、cap mint の order / lifetime / 後 mint 不能を Rust 型で表現する詳細が無い。Opus は `pending_caps: Vec<(CapId, key, holder)>` で startup-only mint を構造的に保証 |
| 7 | trust domain 定義 | ✓ 同 process、type 限界を明文化 | ✓ 暗号境界でない、unsafe / FFI で抜けると明文化 | **Codex (僅差)** | Codex の「Why This Works / Design Correctness」section は **防ぐもの / 防がないもの** を独立 list 化、これは Opus 案には対応 section が無い (= Trade-off 表内に分散)。**DR-0022 文体に近いのは Codex** |
| 8 | define cap-free | × 言及なし (= 案 D で cap 全 API 必須化を不採用とは書くが、define 単体の判断は曖昧) | ✓ Decision に明示、理由 3 つ | **Codex** | これは **重大な差**。Opus 案は `authorized_define / authorized_define_with_meta` を cap 必須にしている (L262-L277)。しかし authsock の A-3a (= startup 時 definition 登録) は **discover 完了前に cap 表が固定できない** ため、Opus 案の path だと chicken-and-egg が出る。Codex 案は define を cap-free にすることで A-3a を素直に通せる。Opus 案は実質「define cap を別途用意」or「discover 後の 2 stage build」を Q3 で先送りしているが、**Codex の判断 (= define は value-free metadata なので cap-free) のほうが筋良い** |
| 9 | handler routing の信用境界 | × 言及なし | ✓ 「候補 A vs B」で `from_adapter` を信じない判断を明示 | **Codex** | Opus 案は handler が「wire request の key で handler_caps を lookup する」と書くだけで、なぜ `from_adapter` field を request に載せないかの判断が無い。Codex は **adapter spoof リスクを明示し**、handler が socket / listener 種別から cap を選ぶことを Decision としている。**security review としてはこちらが厳しい** |
| 10 | OTP adapter の責務移動 | × 言及なし (handler 内 `finish_get` で OTP derive のまま) | ✓ OTP adapter object 化、handler は code 受け取りのみ | **Codex (大差)** | これは本 DR の射程に入れるべきか kawaz 判断。Codex 案は OTP adapter circularity を Decision で扱うが、これにより本 DR の scope が肥大化する (= `handler.rs::finish_get` 内 OTP 分岐の引き剥がし)。一方、入れないと「L1 cap-gated raw read」が handler から呼ばれる構造に逆戻り、本 DR の意義が薄まる |
| 11 | semver 移行戦略 | ✓ 一発 breaking minor | ✓ 3 phase deprecation (deprecated → pub(crate) → 削除) | **Opus** | pre-1.0 + 外部 consumer なしという事実に立てば Opus の一発が筋。Codex の deprecation window は `design-priority.md` 「後方互換を理由に曲げない」と矛盾する |
| 12 | failure_backoffs との関係 | ✓ 第 4 マップとして並置、DR-0022 同型 pattern | × 言及なし | **Opus** | DR-0014 / DR-0022 の「lifecycle が独立した state は独立した map」pattern との整合は Opus が明示。Codex 案は `Store` struct sketch で `failure_backoffs` を残しているが、cap 表との並置 pattern の DR 整合性は語らない |
| 13 | 判定順序 (cap → backoff → lifecycle → runner → auth) | ✓ 明示 (§7) | × 言及なし | **Opus** | DR-0010 re-auth との順序は本 DR の重要 contract。Codex 案には判定順序の Decision が無い。**ここは Opus が不可欠** |
| 14 | Capability の Clone / Copy 判断 | ✓ `Copy` 不採用、`Clone` 採用、debug trace hook 提案 | △ `#[derive(Clone)]` のみ | **Opus** | ただし Opus の `tracing::trace! hook` 提案は撤回推奨 (後述) |
| 15 | holder field の責務 | ✓ diagnostic only と明示、auth に使わない | × 言及なし | **Opus** | Codex 案は cap に holder 概念がないので grep / status での holder 表示ができない。運用観測性で Opus 優位 |
| 16 | `Store::new()` の扱い | △ 維持 (= cap なし stub store) | △ Phase 1 deprecated → Phase 2 pub(crate) → Phase 3 削除 | **両案とも不十分** | 両案で揺れている。Opus 案は `Store::new()` を残すが、その store で secret API を呼ぶと `CapError::Unknown` で fail = 「動くが使えない stub」になる = 設計として悪い (= 半死半生 API)。Codex 案は段階削除を提案するが pre-1.0 でそれは過剰。**推奨: `Store::new()` を `pub(crate)` に一発で下げる + library consumer 向けに `Store::builder().build()` を canonical にする**。これは Opus / Codex のどちらにも書かれていない |
| 17 | test 戦略 | ✓ Red-first 8 項目 | ✓ 5 項目 | **Opus** | Opus は cap 経由の full lifecycle / handler integration / RecordingRunner 不発火確認まで網羅。Codex は table-driven adapter × cap type を提案 (= これは Opus にない筋の良いアプローチ) |
| 18 | DR 文体 | △ 1162 行、判断の理由が縦に長い | ✓ 327 行、各判断が完結 | **Codex** | DR-0022 v2 (272 行) との比較で Codex が近い。Opus は読み返す際に「同じ判断の異なる側面」を別 section で繰り返すきらいがあり、保守性で劣る |
| 19 | Codex review v1 の反映追跡 | ✓ Context section で Critical 3 / Warning 5 / Info 3 を点呼 | △ 反映済前提で個別追跡なし | **Opus** | これは「最終 DR」として 1 度残せば以後は不要 (= journal 行き)。Opus が DR 内に書くのは過剰、Codex のように略すのが正解 |
| 20 | Open Question の質 | △ Q1-Q8、内部実装 detail 寄り (cap ID 安定性 / discover 遅延 / OTP 派生置き場) | ✓ Q1-Q10、本質的 (single cap で十分か / token 生成 / DoS / lint hook の具体形) | **Codex** | Opus の Q1 (cap ID handoff) は「発生したら別 DR」で閉じている = Open Q ではない。Q2 (key 文字列再導出) は内部 impl 詳細。Codex の Q2 (single cap blast radius) は L1.5 への分岐判断、Q10 (lint CI hook の具体形) は運用への着地まで踏み込む |

---

## 3. 観点別詳細比較

### 3.1 設計判断の整合性

#### 両案で同じ判断 (= 確定済)
- raw `Store::get` を public から消す
- Builder pattern で cap 発行
- L1 単一 cap (= chain は別 DR)
- Lost-cap 復旧は in-memory only
- DR-0016 OTP schema 維持
- IPC adapter 身分証明は Phase 3+ defer

#### 両案で違う判断 (= 要 kawaz 裁定)

| 判断 | Opus | Codex | 推奨 |
|---|---|---|---|
| cap の粒度 | per-key (= 1 値 1 cap) | per-Store (= 1 daemon 1 cap、adapter 名は label のみ) | **要裁定**。`L1 単一 cap` の意味次第。「事前合意」の文言「1 値 = 1 cap」を文字通り取るなら Opus、「1 Store 全体に対する単一 cap root」と取るなら Codex |
| `Store::define` の cap | 必須 (`authorized_define`) | 不要 (value-free metadata) | **Codex**。authsock A-3a の startup orchestration が Opus 案だと chicken-and-egg を起こす (Q3 で先送り) |
| OTP の置き場 | handler 内に温存 | OTP adapter として独立 | **Codex 推奨だが本 DR に入れるか別 DR に切るか要判断** |
| handler の cap 選び方 | wire request の key で lookup | socket / listener 種別で dispatch (= `from_adapter` 信じない) | **Codex**。security 観点で Codex の判断が筋良い |
| semver 移行 | 一発 breaking minor | 3 phase deprecation | **Opus** (pre-1.0、`design-priority.md` 整合) |
| `Store::new()` | cap なし stub として残す | deprecated → pub(crate) → 削除 | **両案とも不十分**。新規判断要 |

#### 既存 DR との整合度

| 既存 DR | Opus 整合 | Codex 整合 | 備考 |
|---|---|---|---|
| DR-0003 (core/adapter 責務分離) | ✓ 動機の根本として引用 | ✓ DR-0003 を強める位置付け | 両者一致 |
| DR-0010 (re-auth 順序) | ✓ cap 先 → re-auth 後で明示 | × 言及なし | **Opus 優位** |
| DR-0014 (定義 / 値分離) | ✓ 第 4 map 並置 | △ struct sketch には残るが pattern 議論なし | Opus 優位 |
| DR-0016 (OTP value type) | ✓ 維持、案 C 不採用で根拠 | ✓ 維持、circularity 対応案あり | Codex 優位 (一段深い) |
| DR-0022 (failure_backoffs) | ✓ 同型 pattern 引用 | × 言及なし | Opus 優位 |
| DR-0012 (process access policy) | ✓ 直交軸として明示 | × 言及なし | Opus 優位 |
| DR-0018 (typed sources) | ✓ ValueMeta / SourceMeta との独立軸 | △ adapter wiring の前提として引用のみ | Opus 優位 |

整合度合計: **Opus 6 / Codex 4**。ただし Codex は本 DR の中核設計判断 (define cap-free、OTP adapter 独立、handler 信用境界) で先行している。**重みを内容で測ると引き分け**。

### 3.2 API surface 設計

#### Capability 型

**Opus 案**:
```rust
pub struct Capability {
    pub(crate) id: CapabilityId,
    pub(crate) key: String,
    pub(crate) holder: &'static str,
}
```
- `id` + `key` + `holder` の 3 field
- `Clone` 採用、`Copy` 不採用
- `holder` は diagnostic only と明示
- L1 で per-key 単位

**Codex 案**:
```rust
pub struct StoreAccessCap {
    token: u128,
    _private: (),
}
```
- `token: u128` の equality token のみ
- `Clone` 採用 (= sketch では default)
- per-Store 単位 (= 全 adapter が同 token の clone を持つ)
- `_private: ()` で外部 construct 防止

**評価**:
- Codex 案の `u128` は **predictable token risk** が Q3 で自覚されている (= `rand` 依存 or atomic counter + process salt)。Opus 案の `CapabilityId(u64)` も同じ問題だが Opus は **id を直接 compare に使わない** (= registry に lookup する) ので equality token としての偽装余地は構造的に低い (= attacker が `u64` を当てても `BTreeMap<CapId, RegisteredCapability>` にエントリが無いと `CapError::Unknown`)。**ここは Opus が一段深い**。
- ただし Opus の `key: String` を struct 内に持つのは **`Debug` derive で log に漏れる risk** (= 後述 §3.9)。Codex の `u128 token` は log 出ても害が無い。**ここは Codex 優位**。
- 合成案: `pub struct Capability { id: CapabilityId, holder: &'static str }` (= key を struct から外し、registry のみが真実) + `impl Debug` を手書きで `id` のみ出す。これは両案とも書いていない。

#### `Store::set/get` の signature

**Opus 案**: `authorized_get(&mut self, cap: &Capability, clock: &impl Clock) -> Result<Option<&SecretBytes>, CapError>` (= 引数に `key` なし、cap が key を握る)

**Codex 案**: `get_with_cap(&mut self, key: &str, cap: &StoreAccessCap, clock: &impl Clock) -> Result<Option<&SecretBytes>, AccessError>` (= 引数に `key` あり、cap は token のみ)

**評価**: Opus の「cap が key を握る」が **L1 単一 cap = per-key** の必然。Codex は per-Store なので key 引数が必須。**両者は自己整合**。

しかし Opus 案の caller (= handler) は **「wire request の key で handler_caps を lookup → cap を取得 → authorized_get(cap, clock)」** という 2 段操作になる。これは Codex 案の **「wire request の key を直接 get_with_cap に渡す」** より複雑。**caller の認知負荷で Codex 優位**。

ただし Opus 案には **「cap.key と requested key の二重 check」** という防御 (= §3 `check_cap` 内 `reg.key == cap.key && reg.key == requested`) があり、これは attacker が cap struct の `key` field を mutate した場合の最後の砦になる。Codex 案にはこの層がない (= token equality のみ)。

#### CapError vs AccessError

**Opus 案**: 3 variant (`KeyMismatch / Unknown / Revoked`)。Revoked は L2 予約。
**Codex 案**: 2 variant (`MissingCapability / WrongCapability`)。Revoked なし。

**評価**: Opus の Revoked variant は L2 で削除が必要になる可能性がある (= 「予約しておく」の罠、`no-historical-noise.md` rule 違反候補)。**現時点で使わない variant を入れない Codex 推奨**。ただし `MissingCapability` の出現条件が Codex 案では不明 (= cap を `Option<&Cap>` で渡す API ではないので、いつ Missing が起きるか書かれていない)。**Codex 案の error 定義は意味が曖昧**、Opus 案を簡略化して `enum CapError { KeyMismatch { expected, requested }, Unknown }` の 2 variant が最適解。

#### Builder pattern の正確な形

**Opus 案**: `StoreBuilder { pending_caps: Vec<(CapId, key, holder)>, failure_backoff: Duration, counter: AtomicU64 }` → `build() -> Store`。**cap は builder の中で mint され、build 後は mint 不能** (= 構造的保証)。

**Codex 案**: `StoreBuilder { failure_backoff_duration: Duration }` → `build() -> BuiltStore { store, control_cap, authsock_cap, otp_cap }`。**cap は build 時に hardcoded で 3 つ返る** (= cli / authsock / otp)。

**評価**:
- Opus 案は **動的 cap mint** (= `capability_for(key, holder)` 任意回呼べる) で柔軟、ただし caller が「config から key list を読んで loop で mint する」boilerplate を書く必要がある。
- Codex 案は **固定 3 cap** で hard-coded、4 個目の adapter (= 将来 GUI など) が出たら struct rewrite。
- L1 = per-key の Opus 案だと **N 鍵 = N cap** で `BTreeMap` で持ち回り → builder loop が必要。
- L1 = per-Store の Codex 案だと **adapter 数だけ cap clone を返せばよい** → builder は固定 method 化できる。
- **どちらの粒度を採るかで builder 形が決まる**。粒度判断が先。

#### handler / adapter の cap 持ち回し方

**Opus 案**: `Shared { handler_caps: Arc<BTreeMap<String, Arc<Capability>>>, authsock_caps: Arc<BTreeMap<String, Arc<Capability>>> }` (= per-key 2 表)。

**Codex 案**: `Shared { control_cap: StoreAccessCap, authsock_cap: StoreAccessCap, otp_adapter: OtpAdapter { store_cap: StoreAccessCap } }` (= adapter 数の field)。

**評価**: Codex のほうが lookup が無く lock contention も低い (= `Arc<Cap>` を `clone` して .await を越えるのが軽い)。Opus 案は handler が key ごとに `BTreeMap::get` を毎 request 叩く = 高頻度 path での `Arc` increment 含むコスト。**hot path の性能で Codex 優位**。

### 3.3 完全性 (Codex review v1 のカバレッジ)

両 draft の文面から見る限り、Codex review v1 (= `a54581ebfbef766da`) の Critical 3 / Warning 5 / Info 3 はどちらにも明示反映済を主張している。Opus 案は §Context 末尾で 1 個ずつ列挙、Codex 案は前文で「設計の出発点」として暗黙吸収。

漏れ候補 (両案で扱いが薄い):

| review item | Opus | Codex | 漏れ判定 |
|---|---|---|---|
| Critical #1 raw getter 廃止 | ✓ 削除 | ✓ 削除 | 両方反映 |
| Critical #2 (推定: Lost-cap 永続化禁止) | ✓ 案 F で不採用 | ✓ Decision に書く | 両方反映 |
| Critical #3 (推定: define の扱い) | × `authorized_define` 必須化 (= 反映漏れ疑い) | ✓ define cap-free | **Opus 漏れ可能性**。要 v1 原文確認 |
| Warning #4 `Vec<Capability>` より専用型 | ✓ Opus 案で `Option<Capability>` 系議論なし | △ Codex 案も明示なし | 両者で扱いが薄い |
| Warning #5 DR-0010 順序 | ✓ §7 で明示 | × 言及なし | **Codex 漏れ** |
| Warning #6 ValueMeta 維持 | ✓ 案 C 不採用で明示 | ✓ 維持を Decision に | 両方反映 |
| Warning #7 cap 拒否 →runner/auth 不発火 | ✓ §7 で明示 | × 言及なし (= 暗黙) | **Codex 漏れ** |
| Warning #8 IPC token と remote attestation 分離 | ✓ 案 G で明示 | ✓ Phase 3 defer | 両方反映 |
| Info #9 core 出口判定 / adapter 入口判定 | ✓ Why core §3 で明示 | △ 「Why This Works」で類似主張 | Opus 優位 |

**完全性スコア**: Opus 8/9、Codex 5/9。**Opus 優位だが、Opus の Critical #3 反映が逆方向 (= define cap 必須化) になっている疑いあり**。要 v1 原文との突合。

### 3.4 簡潔性 / 冗長性

**Opus 案 1162 行の内訳概算**:
- Context: 76 行
- Decision: §1-8 で 360 行
- Alternatives: 案 A-G で 130 行
- Why core: 30 行
- Trade-off: 65 行
- Consequences: 75 行
- Implementation Notes: §1-6 で 230 行
- Open Q: Q1-8 で 110 行
- Related: 50 行

**冗長と判定する section** (= 削れる候補):
- §1 capability の概念 = §2 Capability 型 と内容重複 (= 100 行削れる)
- §3 StoreBuilder pattern の「なぜ起動時固定か」 = Why core §1 と重複 (= 30 行削れる)
- §4 命名 `authorized_*` prefix の justification = §5 raw `Store::get` の crate-private 化 と意図重複 (= 40 行削れる)
- Implementation Notes §1 capability.rs 新規 = Decision §2 Capability 型 と重複 (= 50 行削れる)
- Open Q Q1 / Q4 / Q5 / Q7 / Q8 は「発生したら別 DR」で閉じる = Open Q として残す価値が低い (= 60 行削れる)

→ **削減余地 280 行 ≈ 25%**。900 行前後が理論下限。

**Codex 案 327 行の評価**:
- DR-0022 v2 (272 行) とほぼ同等の文量
- Decision section が箇条書きで 12 行に圧縮されている
- ただし **判定順序 / Builder の Rust 詳細 / CapError variant / handler ↔ adapter cap 持ち回し** などの実装着地点が不足

**追加すべき section**:
- 判定順序 (§Decision 内に 20 行)
- StoreBuilder の Rust 型詳細 (= Implementation Notes に 50 行追加)
- CapError 詳細と理由 (= 30 行)
- DR-0010 / DR-0014 / DR-0022 との pattern 整合議論 (= 40 行)

→ **追加余地 140 行 ≈ +43%**。470 行前後が下限。

**DR-0022 v2 (= 質目標) との比較**:
- DR-0022 v2 は「Status note 改訂履歴」「Context」「Decision (詳細)」「Alternatives A-G」「Trade-off 表」「Consequences」「Implementation Notes」「Open Questions」「Related」の構造で 272 行
- Codex 案がこの構造に最も近い
- Opus 案は **「§1-8 という Decision の細分」が DR-0022 v2 にはない冗長性**

**結論**: **Codex 構造を base にして、不足分を Opus から個別注入** が DR-0022 文体への着地点。最終 DR-0024 は **500-600 行** が目安。

### 3.5 Open Questions の質

**Opus 案 Q1-Q8 の内訳**:

| Q | 内容 | 質判定 |
|---|---|---|
| Q1 | cap ID handoff 安定性 | **closeable** (= 別 DR で扱う、Open Q として残さない方が良い) |
| Q2 | wire key と cap key の二重 check | **impl detail** (= Open Q ではない、test で担保すべき) |
| Q3 | discover 遅延と cap mint タイミング | **本質的**、DR-0023 follow-up |
| Q4 | Lost-cap の warning 手段 | **closeable** (= 「warning しない」で閉じている) |
| Q5 | DR-0016 派生処理の置き場 | **closeable** (= 案 C 却下で確定) |
| Q6 | IPC 拡張時の attestation 設計 | **本質的**、L3 への接続 |
| Q7 | `Capability::Display` の log 漏洩 | **closeable** (= key 名は公開済) |
| Q8 | cap-gated API の async 化 | **本質的**、DR-0023 Phase N+ |

→ **本質的 Q は 3 件のみ (Q3 / Q6 / Q8)、closeable が 5 件**。残し方が冗長。

**Codex 案 Q1-Q10 の内訳**:

| Q | 内容 | 質判定 |
|---|---|---|
| Q1 | `Store::new()` 削除タイミング | **本質的** (= migration 戦略) |
| Q2 | single cap で十分か、L1.5 scoped cap への分岐 | **本質的** (= 設計の将来分岐) |
| Q3 | `StoreAccessCap` token 生成方法 (rand vs atomic + salt) | **本質的** (= 実装着地で必ず詰める) |
| Q4 | wrong cap と missing key の error 区別 | **本質的** (= adapter 応答への情報差) |
| Q5 | compile-fail test の手段 (trybuild vs grep) | **本質的** (= 運用着地) |
| Q6 | OTP adapter の crate / module 配置 | **本質的** (= adapter trait 化) |
| Q7 | define cap-free と DoS の境界 | **本質的** (= 別 DR への分岐) |
| Q8 | `StoreKey` newtype issue との実装順序 | **本質的** (= 関連 issue との合流) |
| Q9 | lost-cap recovery UX | **本質的** (= persistence 穴との両天秤) |
| Q10 | lint hook の具体形 | **本質的** (= 運用着地) |

→ **本質的 Q が 10 件、closeable が 0 件**。Open Q の質が桁違いに高い。

**重複 / 欠落**:

| 項目 | Opus | Codex | 推奨 |
|---|---|---|---|
| `Store::new()` 扱い | ✓ Decision で「維持」と明示 | ✓ Q1 で「削除タイミング」を問う | **Codex の問いが正しい**。Opus は「維持」と決めているが「cap なし stub store」は中途半端 |
| L1.5 scoped cap 分岐 | × Alternatives 案 A で却下 | ✓ Q2 で再評価余地を残す | **Codex 推奨**。Opus は早期に閉じすぎ |
| token 生成方法 | × 言及なし (= `AtomicU64::fetch_add` で済ます) | ✓ Q3 で rand vs atomic salt を問う | **Codex 推奨**。Opus 案は test 環境で予測可能になる risk あり |
| lint hook 具体形 | × 言及なし | ✓ Q10 で CI 統合まで踏み込む | **Codex 推奨**。Opus 案では「grep 可能性」を強調するが CI 統合まで届かず |

**結論**: **Open Q は Codex 案を 100% 採用、Opus 案からは Q3 (discover 遅延) / Q6 (IPC L3) / Q8 (async 化) の 3 件を追加注入** が最適。

### 3.6 実装容易性

**Opus 案で躓きやすい箇所**:

1. **`Arc<BTreeMap<String, Arc<Capability>>>` の二重 Arc**: handler が毎 request 叩く path で `BTreeMap::get` → `Arc::clone` の 2 段 indirection。high QPS 想定でなくとも、cap 検証が hot path に入る = lock contention 評価が要る。Opus 案は触れていない。
2. **`#[derive(Clone)] + tracing::trace! hook` の両立**: Opus 案 §2 で「`Capability::clone()` は trace! hook を埋める余地」と書くが、これを実装するには `#[derive(Clone)]` を捨てて手書き `impl Clone` が必要 = 全 cap clone path で side effect が走る (= production でも `tracing::trace` が enable されていれば log が出る)。**実装で痛い**。
3. **`pending_caps: Vec<...>` から `BTreeMap` への build 時変換**: Builder の `pending` を build で `BTreeMap` に flatten するため、build 時間が O(N log N)。N が小さいので実害なしだが、設計として **builder の internal state と build 後の state が異なる shape** は読みにくい。
4. **per-key cap = N 鍵で N cap mint loop**: config の `[kv.*]` を全部 loop で `capability_for` 呼ぶ boilerplate。テスト fixture でも同じ loop が必要、test 全体が builder 経由に書き換わる migration cost が **§Implementation Notes §5 で「既存 fixture を書き換え」と一言で済まされている** = 数百テストの書き換えになる可能性、実装着手前に grep で見積もり要。

**Codex 案で躓きやすい箇所**:

1. **`u128 token` の生成方法未確定**: Q3 で問うているが、Decision に書いていない。実装着手時に `rand` 依存追加か `AtomicU64 + process salt` か即決必要。
2. **OTP adapter の `Arc<Mutex<Store>>` 持ち**: Codex 案 §OTP Adapter Circularity で「OTP adapter は cap と `Arc<Mutex<Store>>` への直接参照を持つ」と書くが、これは **handler と OTP adapter が同じ Mutex を取り合う** = lock order / deadlock リスクが新規発生。Opus 案には無い問題。
3. **`BuiltStore { control_cap, authsock_cap, otp_cap }` の固定 3 field**: 4 個目の adapter (= GUI / IPC 越し / 監視用 status reader) が出たら struct rewrite。
4. **handler が socket / listener 種別で cap を選ぶ dispatch table**: `Decision` §Handler Cap Routing に書くが、具体的な dispatch コードは sketch なし。`control socket → control_cap`、`authsock listener → authsock_cap` の if-else が `server.rs` のどこに入るか未定。

**実装容易性スコア**: Opus 4 / Codex 4 (= 引き分け、躓き方が違う)。

**テスト戦略の明確さ**:

| 項目 | Opus | Codex |
|---|---|---|
| Red-first 提示 | ✓ 8 項目 | ✓ 5 項目 |
| compile-fail test | × 言及なし (= 「`Store` impl に `capability_for` がない」を doctest で確認、と書くが具体策なし) | ✓ Q5 で trybuild vs grep を問う |
| handler integration | ✓ §5 #8 で cap-less key → NotFound を確認 | ✓ §Test Strategy #3 で spoof field 弾きを確認 |
| OTP circularity regression | × 言及なし | ✓ §Test Strategy #4 で direct-call counter による確認 |
| existing test migration cost | △ 「書き換え」と一言 | △ 「test helper builder を用意」と提案 |

→ **テスト戦略は Codex がやや上**。OTP circularity regression test は本 DR の独自性、入れない手はない。

### 3.7 拡張性 (= L3 mTLS / 署名検証への将来余地)

**Opus 案**:
- Alternatives 案 E で trait object 化を却下、代わりに `enum Capability { L1(L1Cap), L3(L3RemoteCap) }` の variant 拡張を提案
- Open Q Q6 で L3 設計の方向性を素描 (attestation context, signature 再 evaluate, cap.granted_key == requested の最終段共通化)
- **L3 への接続が構造的に書かれている**

**Codex 案**:
- L3 / IPC は Phase 3+ defer と書くだけ、enum variant 拡張可能性に触れない
- `_private: ()` field を持つ struct なので、enum 化には struct rewrite が必要
- **将来 L3 を入れるとき API 破壊**

**拡張性で Opus 優位 (大差)**。ただし「将来未定の拡張」を理由に現在の設計を複雑化するのは `design-priority.md` ・ `design-thinking.md` の「将来の仮定的要件のために今の複雑さを増やしていないか」に抵触する余地あり。**enum 化準備は最終 DR には書かない、別 DR で扱う** が筋良い可能性もある。要 kawaz 判断。

### 3.8 Adversarial / 楽観バイアス

**Opus 案の楽観バイアス候補**:

1. **「`pub(crate)` で外部 mutate は型で止まる」(§3 注)**: 同 crate 内に悪意ある code を入れれば pub(crate) は迂回可能。Opus 案は Trade-off §Limits で明文化しているが、その上で `cap.key` と `registry.key` の二重 check を「最後の砦」と呼ぶのは矛盾 (= 同 crate 内の attacker なら registry も mutate できる)。**この二重 check は overengineering**。
2. **「cap ID は外部 wire に出ない」(Q7)**: status 出力 / log 経由で出る可能性は触れていない。Opus 案は `tracing::warn!("cap rejected: holder={holder} requested={key}")` を提案 (Implementation Notes §6) = holder と requested が log 経由で公開される = trust domain 内の観測者 (= operator) は問題ないが、log を外部に送る場合 (= sentry / DataDog 等) は **adapter 関係性を晒す**。Codex Warning #1 系の延長判断が抜けている。
3. **「`Capability::clone()` の trace 不能は debug build で hook」(Trade-off §Limits)**: debug build で hook = 本番では trace 不能 = 本番障害解析で cap がどう clone されたか追えない。これは「hook で足りる」とする楽観。**「production tracing は保証しない」と明文化が必要**。
4. **「Q3 discover 遅延の暫定案 A / B」**: 「2 stage build で旧 store は drop、in-flight request が旧 store を握る race は別 DR」= 別 DR への先送りで本 DR 内で閉じない。これは Q として残すべきだが、Opus 案は「両方とも書くだけ書いて閉じる」= 楽観。

**Codex 案の楽観バイアス候補**:

1. **「`u128` token は process-local equality token、`unsafe` による forge は防がない」(§Core sketch)**: `unsafe` だけでなく **`#[repr(transparent)]` newtype を別 crate で作って `transmute` する経路** や **`std::mem::zeroed()` で全 0 token を作って当たりを引く経路** に触れない。後者は `AtomicU64` 由来 token なら 1 個目が `0` になる risk あり = Opus 案でも同じ問題。**両案で楽観**。
2. **「OTP adapter が `Arc<Mutex<Store>>` を持つ」(§OTP Adapter Circularity)**: lock 取り合いの deadlock risk に触れない。**楽観**。
3. **「`Store::new()` を public で残すと escape hatch」(Alternatives §`register_adapter` pattern)**: deprecated → pub(crate) → 削除の 3 phase だが、Phase 1 deprecated 期間に malicious adapter が `Store::new()` を呼ぶ可能性に触れない。**deprecation window は脅威**。
4. **「single cap で十分」を Decision に置きつつ、Q2 で「scoped cap は L1.5 として分けるべきか」を問う**: 自分の Decision に自分で疑義を呈する形 = **adversarial としては正直**だが、最終 DR としては Decision の確度が低い。

**adversarial 度**: Codex 案の Q (= 自分の Decision を疑う Open Q が 4 件) と「Why This Works / 防がないもの」section が、Opus 案より一段適切。**adversarial framework は Codex 優位**。

### 3.9 「悪い面」の発見 (= 両案が触れていない弱点)

両案が触れていない見落としを列挙:

#### 致命的 (release blocker)

**(A1) `Capability` の `Debug` derive が cap.key を log に漏らす**

Opus 案 §2 で `#[derive(Debug, Clone)]` を明示。`cap.key: String` を含むため、`tracing::warn!("{cap:?}")` や `panic!("unexpected {cap:?}")` が cap.key を log 出力する。

key 名は DR-0017 / DR-0018 で「公開」と確定済なので **直接的な秘密漏洩ではない**。しかし:
- adapter の責務境界 (= 「authsock adapter は op_<id> 系を握る」「handler は user-facing key を握る」) が log で **観測可能になる** = 攻撃者が daemon log を見れれば adapter ↔ key 対応表を構築できる
- DR-0012 process access policy で「key 名で許可される process 集合」を gate しているが、log 経由で key 名 + holder ペアが流れると policy の隠蔽が壊れる

修正案: `impl Debug for Capability` を手書きし、`Capability { id: 42, holder: "authsock-op" }` のように **key を出さない**。`#[derive(Debug)]` を捨てる代わりに、test では `Capability::debug_with_key()` のような explicit method を提供。

Codex 案の `u128 token` は対応する key を struct 内に持たないので、Debug 経由で key が出ない = **Codex 案の方が構造的に安全**。

**(A2) cap registry の race between drop and lookup**

両案とも `Arc<Capability>` を adapter に持たせる。`Arc::strong_count == 0` で `Capability` が drop されるが、`Store::capabilities: BTreeMap<CapId, RegisteredCapability>` の entry は drop されない (= startup-only mint なので)。これは:

- adapter が panic / shutdown で `Capability` を drop しても registry には残る = `CapError::Revoked` を返す機構が今は機能しない
- 再 mint されない (= startup-only) ので、registry に残ったまま「holder 不在」の zombie cap が増える
- Opus 案 Q4 で「warning しない」とするが、registry の lifetime 設計として未定義

修正案: `Capability` の Drop 時に registry から自動削除する `impl Drop for Capability { fn drop(&mut self) { /* notify store */ } }` を実装。ただし `Arc<Capability>` で持ち回ると最後の `Arc::drop` でしか発火しないので、cleanup 経路が複雑。**現実的には「registry は startup 後 immutable」を明文化し、drop 時 cleanup は L2 で扱う** が筋良い。両案とも明文化していない。

#### 重大 (priority fix)

**(B1) test fixture migration cost の過小評価**

`crates/cache-warden/src/store.rs::tests` の cmd_entry / set_then_get_active 等の既存テストは全部 `Store::new()` 経由。Opus 案では「StoreBuilder 経由に書き換え」と一言。実数を grep で見積もると:

```bash
grep -n 'Store::new()' crates/cache-warden/src/store.rs | wc -l
```

→ おそらく 50+ 件。各々 builder 経由に書き換える + secret API 呼出を `authorized_*` に書き換える = 大規模 mechanical edit。

両案ともこの cost を Implementation Notes に書いていない。Codex 案の「test helper builder を用意」(Trade-off #3) は方向性のみで具体策なし。

修正案: `cache_warden::test_helpers::store_with_caps(keys: &[&str]) -> (Store, BTreeMap<String, Capability>)` のような fixture を core crate (`#[cfg(test)]` or `#[cfg(any(test, feature = "test-support"))]`) に用意。これは両案にない section。

**(B2) `expose_secret` の呼出点 audit が DR-0024 の範囲に入っていない**

Codex 案 Q10 で「`SecretBytes::expose_secret` 呼び出し箇所の allowlist」を Open Q として残すが、Opus 案は触れない。本 DR の目的は「raw read を cap-gated にする」だが、`SecretBytes::expose_secret()` 自体は cap と独立に呼べる。authsock の sign path (= `let pem = String::from_utf8_lossy(secret.expose_secret());`) は cap 経由で `secret` を借りた後に `expose_secret()` する path = cap gate は通っているが、**`expose_secret()` 自体を「allowlist された module 内でしか呼べない」**にする必要があるか?

`cache-warden/src/secret.rs` の `SecretBytes::expose_secret` を `pub(crate)` にして、`#[cfg(feature = "expose-secret-for-adapter")]` のような escape hatch を別途用意する案も検討余地あり。**本 DR の射程に入れるか別 DR に切るか、明示判断が要る**。両案とも触れていない (Codex は Q10 で軽く触れる)。

**(B3) `handler.rs::finish_get` の `secret.expose_secret().to_vec()` で in-daemon working buffer に key bytes をコピーする path**

両案とも触れない。cap gate は通っているが、`Vec<u8>` への copy 後はその Vec は zeroize されない (= `Vec<u8>::drop` は zero 化しない) = process memory 上に PEM が残る = DR-0007 mlock の意義を半減させる。

これは DR-0024 の本筋ではないが、cap gate を入れる **同タイミングで `finish_get` の path も DR-0007 / DR-0016 と整合させる動機が生まれる**。両案で「本 DR の射程外」と明示するか、別 issue に切り出すか。

#### 軽微 (improvement)

**(C1) `holder: &'static str` の意味が薄い**

Opus 案 §2 で `holder` を「diagnostic only」と書く。しかし「authsock-op」「handler-kv」のような hardcode string は **enum で表現すべき** (= typo 防止、grep 効率)。

修正案:
```rust
pub enum CapHolder { HandlerKv, AuthsockOp, OtpDerive }
pub struct Capability { id: CapabilityId, holder: CapHolder }
```

これにより `Capability::holder == CapHolder::AuthsockOp` の比較が type-safe。

**(C2) `CapabilityId(u64)` の `Display` 実装**

両案で言及なし。`tracing::warn!("cap rejected: id={}", cap.id())` で出るとき、`CapabilityId(42)` か `42` かで log の grep やすさが違う。

#### 重箱の隅 (nitpick)

**(D1) `RegisteredCapability { key: String, holder: &'static str }` の holder 重複**

Opus 案で `Capability` と `RegisteredCapability` が両方 holder を持つ。registry のみが真実なら `Capability.holder` は不要。

**(D2) Codex 案の `BuiltStore` 命名**

`BuiltStore` より `StoreBundle` / `StoreWithCaps` のほうが意図が明確。

---

## 4. 統合提案

### 4.1 base 案

**base = Codex 案**。理由:
- 設計判断の判断軸が一段深い (= define cap-free / OTP adapter 独立 / handler 信用境界)
- DR-0022 v2 の文体に近い (= 簡潔性)
- Open Q の質が高い (= 10 件すべて本質的)
- adversarial framework として正直 (= 「防ぐもの / 防がないもの」を独立 list)

### 4.2 base 案から取り入れるべき Opus 案の要素 (section 単位)

| Opus section | 取込先 | 理由 |
|---|---|---|
| **§7 authorization 判定の順序** | Codex Decision に新規 subsection 追加 | DR-0010 順序は本 DR の重要 contract、Codex に欠落 |
| **§6 registry = Store の第 4 マップ** | Codex Implementation Notes に新規 subsection 追加 | DR-0014 / DR-0022 pattern との整合議論 |
| **§Implementation Notes §1-3 (capability.rs / StoreBuilder / check_cap)** | Codex Implementation Notes の sketch を Opus の Rust 詳細で置換 | 実装着地点の具体性 |
| **Decision §3 StoreBuilder の `pending_caps` + 後 mint 不能の構造的保証** | Codex Implementation Notes の Builder sketch を置換 | startup-only mint の Rust 型表現 |
| **Alternatives 案 A (L1.5 chain)** | Codex Alternatives に追加 | 「chain は本 DR の射程外」の根拠 |
| **Alternatives 案 E (trait object 化)** | Codex Alternatives に追加 | enum variant 拡張余地の明文化 |
| **Alternatives 案 F (永続化)** | Codex Alternatives に追加 | Lost-cap 永続化禁止の根拠補強 |
| **Alternatives 案 G (in-process token と remote attestation 統合)** | Codex Alternatives に追加 | L3 への接続 |
| **テスト戦略 §5 Red first #1-8** | Codex Test Strategy に統合 | 網羅度向上 |
| **CapError 3 variant のうち KeyMismatch / Unknown** | Codex AccessError を置換 | error 意味の明確化 |
| **§Why core §1-3** | Codex に section 追加 | core 置き場の根拠 |
| **Trade-off §Limits 3 項目** | Codex Trade-off 表に統合 | trust domain 限界の明文化 |
| **Open Q Q3 / Q6 / Q8** | Codex Open Q に追加 | discover 遅延 / IPC L3 / async 化は本質的 |
| **§4 命名 `authorized_*` prefix** | ただし Opus 案の per-key 粒度との整合性次第で再判断 | 粒度判断後に決定 |

### 4.3 両案とも撤回すべき判断

| # | 撤回対象 | 案 | 理由 |
|---|---|---|---|
| 1 | `Capability::clone()` の `tracing::trace! hook` | Opus | `#[derive(Clone)]` を捨てる cost、本番でも log 経由 side effect、debug build 限定の保証は formal でない |
| 2 | `_private: ()` field | Codex | 将来 enum 化で struct rewrite が必要、Opus 案の `pub(crate) field` の方が拡張余地あり |
| 3 | `CapError::Revoked` variant | Opus | L2 予約、現時点で使わない (= `no-historical-noise.md` の futureproof noise) |
| 4 | `Store::new()` を維持 (cap なし stub) | Opus | 中途半端な「動くが使えない」store、`Store::builder().build()` 一本化推奨 |
| 5 | `Store::new()` 3 phase deprecation | Codex | pre-1.0 で `design-priority.md` 後方互換禁則に抵触、一発削除推奨 |
| 6 | per-key cap (= L1 = 1 値 1 cap) | Opus (= 要 kawaz 裁定) | L1 単一 cap 合意の解釈次第。1 Store 1 cap (= Codex) の方が API surface 小、hot path 速い |
| 7 | `authorized_define` 必須化 | Opus | authsock A-3a の chicken-and-egg、Codex の cap-free 判断推奨 |
| 8 | `holder: &'static str` の str 型 | Opus | `CapHolder` enum 化推奨 (上記 C1) |

### 4.4 新規追加すべき section (両案にない)

| # | 新規 section | 配置 | 理由 |
|---|---|---|---|
| **N1** | `impl Debug for Capability` 手書き | Decision Implementation Notes | cap.key の log 漏洩防止 (上記 A1) |
| **N2** | `cap` の Drop semantics と registry lifetime | Decision Open Q | Arc drop 時の registry zombie 問題 (上記 A2) |
| **N3** | test fixture migration cost と helper builder | Consequences / Implementation Notes | 数百テスト書き換え cost の見積もり (上記 B1) |
| **N4** | `SecretBytes::expose_secret` allowlist の射程 | Open Q | 本 DR との境界明示 (上記 B2) |
| **N5** | `finish_get` working buffer の zeroize 整合 | Open Q | DR-0007 mlock との整合 (上記 B3) |
| **N6** | OTP adapter の Arc<Mutex<Store>> deadlock 評価 | Open Q | Codex 案で発生する新規 lock contention (§3.6 #2) |
| **N7** | `tracing` log output policy (= 何を出して何を出さない) | Implementation Notes | adapter 関係性の log 漏洩 (§3.8 #2) |
| **N8** | Token 生成方法の確定 (= rand vs AtomicU64 + salt) | Decision | Codex Q3 を Decision に格上げ |
| **N9** | lint hook の CI 統合手段 (= clippy custom lint or rustdoc JSON grep) | Open Q or Implementation Notes | Codex Q10 を着地点まで詰める |
| **N10** | `Store::new()` 廃止 + `Store::builder()` canonical の段階 | Decision | 両案の中途半端さを解消 |

---

## 5. 最終 DR-0024 への次のステップ (= Opus メイン側のアクション)

優先順位順:

### Step 1: kawaz への裁定依頼 (= ここで止まる)

以下 4 件は kawaz の明示判断が要る。**`AskUserQuestion` 一括 (最大 4 件) を強く推奨**。

| Q | 選択肢 | 影響範囲 |
|---|---|---|
| **裁定 1: cap の粒度** | A. per-key (= 1 値 1 cap、Opus 案) / B. per-Store (= 1 daemon 1 cap、Codex 案) / C. 中間 (= per-adapter group) | API surface 全体、Builder 形、handler の lookup cost |
| **裁定 2: define の cap** | A. 必須 (= Opus) / B. 不要 (= Codex、value-free metadata) | authsock A-3a の startup orchestration |
| **裁定 3: OTP adapter の独立** | A. 本 DR で含める (= Codex) / B. 別 DR (DR-0025 候補) / C. 当面 handler 内のまま | DR-0024 scope の大きさ |
| **裁定 4: `Store::new()` の扱い** | A. 維持 (cap なし stub) / B. `pub(crate)` 即削除 / C. 3 phase deprecation | library consumer 影響 |

### Step 2: 裁定結果に基づき final draft 起草

Codex 案を base に複製 (= `docs/decisions/DR-0024-cap-access-gate.md` 新規)、§4.2 の取込要素を section 単位で merge、§4.3 撤回要素を base から削除、§4.4 新規 section を追加。

**作業手順 (= 機械的にやれる粒度)**:

1. `cp draft-DR-0024-cap-access-gate-CODEX.md DR-0024-cap-access-gate.md` (`draft-` prefix 外す)
2. Status を Accepted に変更、Date を確定日に、Related に DR-0010 / DR-0011 / DR-0012 / DR-0014 / DR-0022 / DR-0023 を追加
3. Decision 内に「§Judgment Order (cap → backoff → lifecycle → runner → auth)」を Opus §7 から注入
4. Implementation Notes の sketch を Opus §Implementation Notes §1-3 で置換 (Rust 詳細)
5. Alternatives に Opus 案 A / E / F / G を追加
6. Trade-off 表に Opus §Limits 3 項目を追加
7. Open Q に Opus Q3 / Q6 / Q8 を追加、§4.4 N2 / N4 / N5 / N6 / N9 を追加
8. Decision §Token generation で Codex Q3 を解決済 Decision に格上げ
9. Decision §`Store::new()` policy で裁定 4 結果を Decision として記載
10. Implementation Notes §test fixture helpers で `test_helpers::store_with_caps` を追加 (§4.4 N3)
11. Implementation Notes §Debug impl で `impl Debug for Capability` 手書きを記載 (§4.4 N1)
12. Implementation Notes §tracing policy で N7 を記載
13. 全体を読み返して DR-0022 v2 文体 (= 272 行) に近いか確認、500-600 行目標
14. **Codex review v2 にかける** (= `codex:codex-rescue` subagent 経由、`/codex:adversarial-review` 相当)

### Step 3: review feedback 反映 → land

- Codex review v2 で Critical / Warning が出たら反映
- 既存 DR (= DR-0010 / DR-0014 / DR-0022) で本 DR を参照する場所を grep、相互参照を追記
- 関連 issue `docs/issue/2026-06-14-internal-key-forget-interface.md` で「DR-0024 採用、`StoreKey` newtype は別 DR (DR-0025 候補)」と更新

### Step 4: 実装着手 (= 別 PR)

- DR が land したら別 PR で実装
- 実装着手前に test migration cost を grep で確定 (= `Store::new()` 呼出点数、`store.get(` 呼出点数、`store.set(` 呼出点数)
- TDD で red-first テスト 8 項目を先に書く
- semver bump (pre-1.0 minor) を CHANGELOG に記載

---

## 6. 補足: kawaz rule 整合性チェック

| rule | チェック | 結果 |
|---|---|---|
| `feedback-evaluation.md` (ヨイショ禁止、悪い面を必ず探す) | 両案の悪い面を §3.9 で 8 件、撤回要素を §4.3 で 8 件指摘 | ✓ |
| `design-priority.md` (後方互換を理由に曲げない) | Opus 案 §5 / Codex 案 Trade-off #8 が pre-1.0 を活かす方向、ただし Codex の 3 phase deprecation は推奨外と指摘 | ✓ |
| `no-historical-noise.md` (跡地コメント禁止) | Opus 案 `CapError::Revoked` を撤回推奨 (= 「予約」名目の futureproof noise) | ✓ |
| `empirical-verification.md` (推測でなく実機検証) | test migration cost の `grep Store::new()` を Step 4 で明示 | ✓ |
| `design-impl-bidirectional-check.md` (設計と実装の双方向確認) | Step 2 #14 で Codex review v2 にかけて B 方向 (= 設計→実装エビデンス) を確認 | ✓ |
| `self-written-rule-blind-spots.md` (対極の側面) | base 案 (= Codex) の弱点を §3.9 + §4.3 で対極評価 | ✓ |
| `retreat-is-last-resort.md` (撤退は最後の手段) | 両案を撤回せず、Codex base + Opus 注入の合成案を提示 | ✓ |
| `top-tier-model-delegation.md` (本気レビューは同 tier) | 本 reviewer は Opus 4.7 1M、メイン (Opus) と同 tier (= ヨイショなし、Critical 級指摘 5 件、要追加判断 4 件) | ✓ |

---

## 付録: 各ペルソナの所見 (= 各観点で「最も気になる 1 件」)

- 🔒 セキュリティ: cap.key が `Debug` derive 経由で log に漏れる (A1)
- 🦹 悪用シナリオ: `holder: &'static str` の hardcode string を文字列比較に使う path が将来生まれる (= log で「authsock-op」を見た attacker が偽 cap を作る) (C1)
- ⚡ パフォーマンス: Opus 案 `Arc<BTreeMap<String, Arc<Cap>>>` の handler hot path lock contention (§3.6 #1)
- 🏗️ 設計原則: define cap-free vs 必須 (= 設計 OK で Codex 推奨、§3.1)
- 📖 可読性: Opus 案 1162 行は「同じ判断を別 section で繰り返す」冗長性 (§3.4)
- 🐛 QA: OTP adapter `Arc<Mutex<Store>>` の deadlock シナリオ未評価 (N6)
- 👤 UX: cap-less caller への error message が両案で曖昧 (= NotFound vs CapMissing で adapter spoof 情報差) (Codex Q4)
- ⚖️ 法務: 該当なし (= 個人 OSS、業務情報なし)
- 🌍 国際化: 該当なし (= log は英語のみ)
- 🔧 運用: `tracing` log の adapter 関係性漏洩 (§3.8 #2、N7)
- 📚 ドキュメント: DR-0022 v2 文体 (= 272 行) との一致度は Codex が大幅優位 (§3.4)
- 🔥 技術的負債: Opus 案 `CapError::Revoked` 予約は futureproof noise (§4.3 #3)
- 🧪 テスト: OTP circularity regression test は Codex 案のみ提案、Opus 案にない (§3.6)
- 🔄 保守: 「per-key vs per-Store」粒度判断を本 DR 内で確定しないと、3 年後の保守者が judgment trail を辿れない (= 裁定 1)

## 付録 B: 優先順位付きアクションリスト

### すぐ手を打つべき (致命的)
1. **裁定 4 件を kawaz に AskUserQuestion で確認** (= cap 粒度 / define cap / OTP scope / `Store::new()`)
2. `Capability` の `Debug` 手書き impl 仕様確定 (A1)

### 次に手を打つべき (重大)
3. Codex 案を base に複製、§4.2 取込 14 件を section 単位で merge
4. test migration cost を `grep Store::new()` で実数把握 (B1)
5. `SecretBytes::expose_secret` allowlist の射程を別 DR に切るか本 DR に入れるか判断 (B2)
6. OTP adapter `Arc<Mutex<Store>>` の deadlock シナリオを Open Q として明文化 (N6)

### 余裕があれば (軽微)
7. `CapHolder` enum 化 (C1)
8. `BuiltStore` / `StoreBundle` 命名再考 (D2)
9. test_helpers crate-internal module の用意 (N3)

### 確認のみ (重箱の隅)
10. Opus §Implementation Notes §6 tracing 表現の見直し (N7)
11. Codex 案 §Test Strategy #2 table-driven test の rows/cols が per-Store 案前提なので per-key 採用なら全面書き換え

以上。
