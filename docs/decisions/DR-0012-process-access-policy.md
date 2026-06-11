# DR-0012: socket 層プロセスアクセス制御（`allowed_processes`）と pid 不明時の fail-closed

- Status: Active
- Date: 2026-06-11

## Context

authsock-warden は socket / key の 2 層で「どのプロセスがその鍵を使えるか」を
`allowed_processes`（接続元プロセスの祖先チェーンと突き合わせ）で制限していた。
authsock-adapter 移植の Iteration 5（port plan §2）でこれを cache-warden に取り込む。

cache-warden は既に基盤を持っている:

- コア `cache-warden`: `SystemInspector::ancestry(pid)`（pid → init/launchd への祖先遡上）、
  `ProcessInfo`（pid / ppid / path / start_time）と派生 `name()`（path basename、`Option<&str>`）。
- CLI `cache-warden-cli`: `peer.rs`（`LOCAL_PEERPID` / `SO_PEERCRED` で接続の peer pid 取得）。

足りないのは「祖先チェーンを `allowed_processes` リストと突き合わせるポリシー解釈」と、
config / daemon への配線だけ。

## 移植元（authsock-warden）の挙動

- `policy/process.rs` の `ProcessChain::matches_any(&[String])`: allowed が空なら `true`（全許可）、
  非空なら祖先チェーン中いずれかの `ProcessInfo.name` が allowed に含まれれば `true`。
  `name` は path basename、未解決時は `pid:<N>` のプレースホルダ文字列。
- `policy/engine.rs`: socket 層と key 層を判定。**peer pid / プロセス特定不能時は fail-open**
  （「could not determine client process, allowing by default」のログを残して許可）。
- key ∩ socket の交差: 両方非空なら交差を取るが、**交差が空集合になると `matches_any(&[])==true` に
  転落して全許可になる罠**がある（空 = 全許可の規約と交差空が衝突）。

## Decision

### 1. socket 層のみ実装する（key 層は見送り）

`[authsock.sockets.NAME].allowed_processes`（実行ファイル basename のリスト）のみを実装する。
key 層（warden の `[[keys]].allowed_processes`）は今回は含めない。

- cache-warden は op キーを `[authsock.sources.*]` + socket `source` 参照で持ち、warden の `[[keys]]`
  構造そのものが無い。
- kawaz の実 config は全 socket が `allowed_processes = []`（空 = 制限なし）なので、socket 層だけ実装すれば
  移植後も挙動は不変で実害ゼロ。
- key 層はパリティ達成後の追加とする（port plan §2 に残置）。

### 2. 空配列 = 全プロセス許可（制限なし）= 不変条件

`allowed_processes` が空 / 省略なら制限なし（全プロセス許可）。これは**必須の不変条件**:
kawaz の実 config は全 socket 空なので、移植後も未設定 socket の挙動が従来どおりであること。
空なら祖先遡上自体をスキップして許可する（pid 不明でも許可）。

### 3. 照合 = 全祖先 OR + basename 完全一致

接続元 pid の祖先チェーン（init/launchd まで遡上）のうち**いずれかの**プロセスの `name()`
（path basename）が allowed リストに含まれれば許可。glob も regex も無く純粋な文字列完全一致
（warden 踏襲）。`name()==None`（path 未解決）の祖先はスキップ（照合対象外）。

> warden は未解決プロセスに `pid:<N>` プレースホルダ名を付けていたが、完全一致照合では `pid:<N>` が
> 実 basename と一致することは無いので、「スキップ」と「`pid:<N>` を付けて完全一致照合」は等価。

照合ロジック（`chain_allowed`）は**アダプタ層**（`cache-warden-authsock` の `process_policy.rs`）に置く。
DR-0004 の「汎用プロセス認証 = コア、ポリシー解釈 = アダプタ」に従う。祖先遡上（汎用）はコア、
allowed_processes との突き合わせ（解釈）はアダプタ。

### 4. peer pid 取得失敗 / 祖先遡上失敗時は fail-closed（拒否）

プロセスを特定できないなら署名（および列挙）を拒否する。**warden は fail-open（許可）だが、
cache-warden は安全側に倒して fail-closed（拒否）にする**（差異を明記）。

- 制限を設定した socket では「誰が要求しているか分からない」状態こそ拒否すべきケース。
- ただし `allowed_processes` が空（= 全許可）の socket には影響させない。空なら祖先遡上を行わないので、
  pid 不明でも従来どおり許可。制限を設定した socket でのみ pid 不明を拒否する。

### 5. 接続冒頭で 1 回判定（REQUEST_IDENTITIES でも適用）

socket は接続単位で peer pid が確定するので、`handle_connection` で接続冒頭に
（peer pid → ancestry → `chain_allowed`）を 1 度だけ判定する。不許可ならその接続の全リクエストを
`SSH_AGENT_FAILURE` で返す（列挙も署名も一律拒否）。接続を即閉じるのでなく安全に failure 応答を返す形が
ssh クライアントに優しい（warden 挙動踏襲）。これにより**不許可の呼び出し元はどの鍵があるかも漏れない**
（warden パリティ）。空 allowed_processes の socket は判定をスキップ（全通過）。

### 6. 将来 key 層を足す時は「交差空 = 全拒否」にする

warden の「key ∩ socket が両方非空かつ交差空 → `matches_any(&[])==true` で全許可に転落」する罠は
踏襲しない。key 層実装時は「交差が空集合なら全拒否」に修正する。

## Consequences

- config `AuthsockSocketConfig` / 検証済み `AuthsockSocket` に `allowed_processes: Vec<String>`
  （`#[serde(default)]`、空デフォルト、`deny_unknown_fields` 維持）。
- daemon `SocketState` に `allowed_processes` を注入（`filter` と同じ流儀）。`handle_connection` の冒頭で
  `process_gate_passes(peer, allowed)` を判定。
- アダプタに `chain_allowed(chain, allowed) -> bool` を新設（`process_policy.rs`）。アダプタが
  コア `cache-warden` に依存（`ProcessInfo` 利用）。これは adapter→core の片方向依存（DR-0004 整合）。
- テスト: 照合ロジックを fake `ProcessInfo` チェーンで網羅 + `process_gate_passes`（allow/deny/pid 不明）+
  実 ssh E2E（自プロセス祖先名 allow / 偽名 deny）。

## Alternatives

- **key 層も同時実装**: 却下。cache-warden に `[[keys]]` 構造が無く、実 config も全空なので
  socket 層で実害ゼロ。パリティ後に追加する方が安全（warden の交差空罠を避けた設計で入れられる）。
- **pid 不明時 fail-open（warden 踏襲）**: 却下（決定 4）。制限を明示した socket で要求元不明を許可するのは
  安全方針に反する。
- **照合ロジックをコアに置く**: 却下。DR-0004 でポリシー解釈はアダプタ責務と確定済み。コアは汎用プロセス
  認証（祖先遡上）まで。

## 関連

- [DR-0004](./DR-0004-authsock-warden-succession.md) — コア / アダプタの責務分割（ポリシー解釈はアダプタ）
- [DR-0006](./DR-0006-process-inspection-dependencies.md) — プロセス検査の libc 採用（祖先遡上の基盤）
- [DR-0009](./DR-0009-control-socket-protocol-v1.md) — peer 認証（LOCAL_PEERPID / SO_PEERCRED → ancestry）
- port plan `docs/design/authsock-adapter-port-plan.md` Iteration 5
