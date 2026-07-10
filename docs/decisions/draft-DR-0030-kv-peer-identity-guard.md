# draft-DR-0030: kv per-entry peer-identity guard — set 時宣言の読み取り認可

- Status: Draft (kawaz レビュー待ち。codex adversarial review 予定)
- Date: 2026-07-10
- 関連: issue `2026-06-22-kv-get-peer-identity-guard` (動機・constraint カテゴリ案) /
  DR-0012 (key-level process access policy、config 由来) / DR-0022 (`[auth].command` = 再認証ゲート) /
  DR-0024 (Store capability、adapter 粒度) / DR-0029 (StoreSnapshot handoff、record 引き継ぎ必須の裁定) /
  crate `macos-process-inspect` (評価素材の取得 API) /
  draft-DR-0031 (custom TouchID dialog、guard 評価結果の表示先)

## Context

1Password の TouchID dialog は「Ghostty が SSH の許可を求めています」程度しか示さない
白紙委任で、secret の消費側は「自分が set した値を、自分の信頼境界内のプロセスにだけ
expose する」手段を持たない。cache-warden 側にも既存機構が 3 つあるが、いずれも
**「set した本人が、その entry ごとに、get してよい相手を宣言する」** 軸は担っていない:

| 機構 | 粒度 | 出所 | 判定材料 | 答える問い |
|---|---|---|---|---|
| DR-0024 capability | Store (adapter) | build 時 | u128 token | この caller は core の秘密 API を呼べるか |
| DR-0012 `allowed_processes` | key (config) | config 起動時 | 祖先チェーン × プロセス名 | この requester はこの key を読めるか (運用者宣言) |
| DR-0022 `[auth].command` | lifecycle イベント | config | 外部コマンド exit code | 人間がこの再認証を承認したか |

本 DR は第 4 の軸 = **per-entry / set-time / consumer 宣言 / instance-based** の
読み取り認可を追加する。DR-0024 が「per-key cap は L2 の早すぎる導入」と却下したのは
**cap (呼び出し資格) の細粒度化**であり、本 DR の per-entry **policy record (データ)**
とは別物 (kawaz 裁定 2026-07-09: Capability トークンと per-entry policy record は別物、
record は DR-0029 handoff で引き継ぎ必須)。

## Decision (骨子)

### 1. constraint モデル — v1 は 3 種 + 段階拡張

set 時に 0 個以上の constraint を宣言でき、get 時に **全 constraint が成立した場合のみ**
値を返す (AND 合成)。

| constraint | 判定材料 | 意味論 |
|---|---|---|
| `same-user` | `peer_audit_token(fd)` の euid/ruid | getter peer の euid と ruid が setter 記録値と一致 |
| `same-ancestor=<NAME>` | `ancestry(pid)` + 実体 pin | setter の祖先チェーンから NAME に一致した**プロセス実体** (pid + start_time、macOS では unique_id も) を記録。getter の祖先チェーンに**同一実体**が居ることを要求 |
| `command=<NAME or /PATH>` | getter chain の `ProcessInfo::path` | chain 中に該当 basename / full path の実行ファイルを持つプロセスが居る |
| (phase 2) `signed-by=<ID>` | codesign identifier | crate `macos-process-inspect` への SecCode API 追加が前提 |
| (phase 2) `env-marker` | peer env | 同 crate への KERN_PROCARGS2 追加が前提 |

### 1b. 各 constraint の脅威モデル — 何を防ぎ、何を防がないか

「強/弱」の一語ラベルでは誤解を生むため (codex review 指摘)、constraint ごとに
**防げる読み取り / 防げない読み取り**を明記する。この表は doc / `--help` にも
同じ内容を載せる (issue 受け入れ条件の「弱い識別の明示」を全 constraint に拡張):

| constraint | 防げる | 防げない (= 限界、明示必須) |
|---|---|---|
| `same-user` | 別 uid のプロセスからの読み取り | **同一 uid の任意のプロセス** (cache-warden の socket は元々 same-uid 前提なので、単独では「既定の防御の再宣言」に近い。他 constraint との併用が本命) |
| `same-ancestor` 実体 pin | 別セッション・別プロセスツリーからの読み取り、pin 先 exit 後の読み取り (自然失効) | ① pin 先プロセスが **exec で別バイナリに置き換わった**場合 (pid/start_time/unique_id は exec を跨いで同一 = 「同じプロセス実体」の定義通りだが「同じプログラム」ではない)。② **同一ツリー内の任意の子孫** (同 shell から起動した無関係ツールも通る)。③ SSH/socket フォワーディング経由では **ローカル側の中継プロセス (ssh 等) しか観測できず**、リモート実体は識別不能 — 中継プロセスが pin ツリー内なら通る |
| `command=` | カジュアルな誤用 (意図しないツールからの読み取り) | **同 basename / 同 path の別バイナリを配置・実行できる者** (実行ファイルパスの basename 判定であり argv[0] 偽装は効かないが、$HOME 配下に同名バイナリを置ける時点で回避可能)。防御ではなく「ラベル」に近い |

`same-shell` は `same-ancestor` の sugar: setter 祖先のうち**最も近い shell** (組み込み
リスト: zsh / bash / fish / sh / nu 等) を自動選択して実体 pin する。「同じ shell
セッションから set した値は同じセッションからしか読めない」を 1 フラグで表現する。

実体 pin (pid + start_time + unique_id) を name-match より優先する理由: pid は再利用
される (crate doc)、name は詐称できる。実体 pin は「その時生きていたまさにその
プロセス」に束縛され、セッション終了とともに自然失効する (= 失効後の get は拒否、
値は TTL まで残るが到達不能。これは仕様であり、再 set で束縛し直す)。

この guard 全体の位置づけ: **同一 uid 内の誤爆・誤配線に対する区画化**であり、
同一 uid 内の悪意あるコードに対する防御ではない (それは DR-0024 が cap の限界として
述べたのと同じ線引き)。悪意あるローカルコードへの対抗は phase 2 の `signed-by`
(codesign) が初めて意味を持つ。

### 2. record の配置 — core は data、評価は CLI 層

- **core (`cache-warden`)**: `Store` に第 4 マップ `access_guards: BTreeMap<String, GuardRecord>`
  を追加 (DR-0022 `failure_backoffs` の前例に従う。`CacheEntry` は触らない)。
  `GuardRecord` は **評価ロジックを持たない plain data** (constraint 列 + setter identity
  snapshot)。core が chain の解釈をしない原則 (DR-0004、auth.rs doc の「policy 解釈は
  adapter 層の責務」) を維持する
- **CLI 層 (`cache-warden-cli`)**: `daemon/guard.rs` (新設) が evaluator。素材は
  `macos-process-inspect` (peer_audit_token / ancestry / unique_id) と HandlerCtx の
  requester chain。非 macOS では強 constraint は評価不能 = fail-closed 拒否

不採用代替: (a) `GuardRecord` を opaque blob (`serde_json::Value`) にして core から
スキーマも追い出す案 — snapshot round-trip は楽になるが、型の整合検査が実行時まで
遅延し、adapter 間でスキーマが分裂し得る。record は「事実の記録」であって domain
解釈ではないので、ProcessInfo と同じく core の typed data とする。
(b) `CacheEntry` 内に埋める案 — entry の生存 (TTL 失効 / undefine) と guard の生存を
分離できなくなる。backoff が第 3 マップに出た理由と同型。

### 3. snapshot 引き継ぎ (DR-0029 整合)

`SnapshotEntry` に `guard: Option<SnapshotGuard>` を `#[serde(default)]` で追加
(snapshot.rs は additive-evolution 前提の設計、実コード確認済み)。旧 snapshot に
guard が無ければ「constraint なし」として import。**guard 付き entry の引き継ぎは
必須要件** (kawaz 裁定 2026-07-09: graceful restart で record を落とすと「再起動で
認可が消える」事故になる)。

**ダウングレード方向の規定** (codex review 指摘): 旧バイナリは unknown field を
黙って捨てるため、`#[serde(default)]` のみだと「guard 付き snapshot → 旧 daemon へ
graceful restart → guard が消えて entry が無防備で残る」というセキュリティ後退が
起きる。これを防ぐため、**export する snapshot に guard が 1 件でも含まれる場合は
format_version を +1 する** (guard ゼロなら現行 version のまま = 旧 daemon への
ダウングレードも従来通り成功)。guard を使い始めたユーザに限り、ダウングレード
restart は cold start に退化する — 「認可が黙って消える」より「秘密ごと消えて
再認証」の方が安全側、という判断。

### 4. 評価点・順序・失敗時挙動

`handle_get` の評価順序 (現行 handler.rs:422-568 に挿入):

```
① reserved namespace read gate (最優先、現行)
② DR-0012 config 由来 key gate (現行)
③ per-entry guard (本 DR、新設)  ← ②の後: 運用者宣言 > consumer 宣言の順で早期拒否
④ store.get (DR-0024 cap は内部で検証、現行)
```

- 拒否・評価不能 (requester chain 無し / peer_audit_token 取得失敗 / 実体 pin の
  対象が消滅) は **fail-closed で AuthFailed 拒否**。DR-0012 と同じく
  regenerate / 再認証 / TouchID を一切トリガしない (拒否がコスト・音・dialog を
  発生させない)
- 拒否理由は daemon log (tracing) に構造化で残す。クライアント応答には
  「access denied by entry guard」+ どの constraint 種別で落ちたかまで
  (setter の identity 詳細は返さない — get 側に setter 情報を漏らさない)

### 5. CLI / config surface

```
cw kv set FOO BAR --require-same-user --require-same-shell
cw kv set FOO BAR --require-same-ancestor=code --require-command=git
```

```toml
[kv.policy]
default-require-same-user = true   # 既定 OFF で導入 (Open Q1)
```

- constraint は set のたびに宣言し直す。**set は record の全置換**: constraint 付き
  set は record を上書きし、**constraint なしの set は既存 record を削除する**
  (= 残留させない。「今回の set の宣言がすべて」という単純な意味論。うっかり
  無宣言 set で guard が外れるリスクは `default-require-same-user` 等の config
  既定で緩和する)。`kv del` / `undefine` は record も同時に削除し、entries に
  無い key の record は snapshot export / import 時に prune する (orphan を作らない)
- `kv list` / `status` の entry metadata 表示に guard の有無 + 種別を出す
  (value-free、既存 EntryInfo の拡張)

### 6. `[auth].command` (CommandAuthenticator) との関係 — 直交合成、変更なし

- guard = **authorization** (誰が読めるか、set 時宣言の機械判定)
- `[auth].command` = **authentication** (人間がこの lifecycle イベントを承認したか)
- 合成順: guard 拒否なら auth まで到達しない (④より前)。guard 通過後の
  soft/hard expiry 時は従来通り auth が走る。CommandAuthenticator のコード変更なし。
- **dialog 表示との接続 (draft-DR-0031)**: guard 通過後に cache-warden の独自 dialog
  (`CacheWardenApprover`) が出るとき、`ApproveRequest.guard_eval` フィールドに評価済み
  constraint 一覧と setter identity summary を載せる。dialog はこれを緑チップ
  (「Verified: same-shell, same-user」) と展開時の詳細に表示する。**guard 拒否時は
  dialog を出さない** (拒否理由を setter 側に間接的に漏らさないため、§7 の
  「setter identity を get 側 error に返さない」規定と整合)

### 7. set 時の記録経路

`handle_set` で、HandlerCtx の requester chain
+ 接続 fd の `peer_audit_token` から setter identity snapshot を構築し、
`Store::set_guard(key, GuardRecord, cap)` (新 API、set と別呼び出しにせず
`set_with_guard` に一体化するかは実装時判断) で record を固定する。
constraint 宣言なしの set は record を作らない (現行挙動と完全互換)。
guard を宣言できるのは v1 では `kv set` (Static 値) のみ: definition 由来
(config `[kv.*]` / `kv define`) の entry は運用者宣言の DR-0012 `allowed_processes`
が既にカバーしており、set-time 宣言の主体 (consumer) が存在しないため対象外。

## Security considerations

- **pid 再利用**: 実体 pin は pid 単独でなく start_time (+ macOS unique_id) 併記で
  照合。unique_id は private API のため取得失敗があり得る → その場合 start_time
  照合のみに縮退 (両方失敗なら fail-closed)
- **TOCTOU**: `peer_audit_token(fd)` は fd キーで race-free (crate doc)。ancestry は
  pid ベースで race 余地があるため、評価は接続ごとに get 要求受理時点で 1 回
  snapshot し、その時点の chain で判定 (途中の親 exit は「chain 短縮 = 一致失敗 =
  拒否」に倒れる、fail-closed)
- **弱い識別の明示**: `command=` は `--help` / doc / `kv list` 表示のすべてで
  「weak (spoofable)」を明記 (issue 受け入れ条件)
- **guard record は秘密ではないが漏らさない**: setter の chain 情報を get 側
  エラーに含めない。record 自体は snapshot に載る (snapshot は既に secret を
  含むため取り扱い強度は変わらない)

## 実装 phase 分割

- **Phase 1**: same-user + same-ancestor (same-shell sugar 含む) + command。
  core 第 4 マップ + snapshot 拡張 + evaluator + CLI flags + `kv list` 表示
- **Phase 2**: signed-by (crate へ SecCodeCopyGuestWithAttributes 追加後) /
  env-marker (KERN_PROCARGS2 追加後)。crate 側拡張は issue
  `2026-06-22-crate-macos-process-inspect` の archive に将来 scope として記録済み

## Open questions (kawaz 判断待ち)

1. **`default-require-same-user` を既定 ON にするか**: 安全側だが、既存ユーザの
   マルチユーザ運用 (無いはずだが) と「constraint なし set」の完全互換を破る。
   draft は既定 OFF + config opt-in を提案
2. **same-shell の shell リストの置き場所**: 組み込み固定 vs config で拡張可能。
   draft は組み込み + config `[kv.policy] shell-names = [...]` 上書き可を提案
3. **get 拒否時の将来 UX**: custom-touchid-dialog 実装後、「拒否の代わりに人間承認へ
   エスカレーション」経路を作るか。本 DR では作らない (拒否は静かに拒否) とし、
   dialog 側 DR で再訪
