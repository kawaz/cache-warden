# DR-0011: TTL 基準の分離（loaded_at / extended_at）と pin API

- Status: Active
- Date: 2026-06-11

## Context

コアの 2 段 TTL ライフサイクル（DR-0003、`CacheEntry` / `EntryState` / `Ttl`）は、
当初 soft / hard の両方を **単一の基準点 `activated_at`** から測っていた。
`activated_at` は `set` / `regenerate` で設定され、`extend`（soft 切れ時の再認証延長）でも
`now` にリセットされていた。

この設計には曖昧仕様があった: **`extend` が `activated_at` をリセットすると hard も一緒に
動く**ため、頻繁に使われ続けるエントリは「extend し続ければ hard が永遠に来ない」。
hard TTL を「値の絶対寿命」として意図していたのに、使用のたびに無限に先送りされ、
hard の存在意義（「どんなに使っていてもこの時刻には必ず破棄する」）が崩れていた。

加えて kawaz の実ユースケースで「明示的に hard を先送りしたい」場面が見つかった:
**hard の期限が夜中に来る。寝る前に『これから 8 時間は soft も hard も切らさない』と
マニュアル操作して、無人の AI 作業を止めないようにしたい**。

この 2 点（曖昧仕様の解消 + 明示先送り手段）を確定するのが本 DR。
authsock アダプタ移植（DR-0004）の前提コア修正でもある
（`docs/design/authsock-adapter-port-plan.md` の Iteration -1、判断 3）。

## Decision

### 1. TTL 基準を 2 つに分離する

`activated_at` を以下の 2 基準に分ける:

- **`loaded_at`**: `set` / `regenerate` 時に固定。**hard TTL の基準**。`extend` では動かさない。
  = 値の絶対寿命の起点。使用を繰り返しても hard 期限は元のスケジュールから動かない。
- **`extended_at`**: `set` / `regenerate` 時に `loaded_at` と同値で初期化。`extend` で `now` に更新。
  **soft TTL の基準**。= 「使うたびに延命」（idle extend）の窓。

state 判定（hard 優先・sticky は現状維持）:

- hard: `now - loaded_at >= hard` → `HardExpired`
- soft: `now - extended_at >= soft` → `SoftExpired`

`extend` は `extended_at` だけを更新する（hard は動かさない）。これが仕様修正の本体。

`Ttl::new` の `soft <= hard` 検証は維持する。load 直後は両基準が一致する
（`extended_at == loaded_at`）ので、「load した値は hard より先に soft が来る」という
初期保証として依然有効。extend が `extended_at` を進めた後は、soft 窓がそこから再スタートし
hard 期限は据え置かれるだけで、検証の意味は壊れない。

### 2. pin API（期限まで失効させない明示操作）

`CacheEntry::pin_until(deadline, clock)`: `deadline` まで soft / hard とも失効判定を抑止する。
state 判定の先頭で `now < pin_deadline` なら `Active` を返す。pin の期限が来たら通常判定に戻る
（本来の hard を過ぎていれば即 `HardExpired` → 次の `evaluate` / `get` で zeroize）。

- 既に `HardExpired` のエントリは pin 不可（`PinError::HardExpired`）。pin は **生きている値**を
  期限まで保持する操作であり、破棄済みの値を蘇生はしない。
- 再 pin（別 deadline で再呼び出し）は上書き可。`unpin` で解除も可能。

Store 層:

- `pin_authenticated(key, deadline, auth, requester, clock)`: **再認証必須**。
  pin はセキュリティ緩和操作（本来失効して zeroize されるはずの値を期限まで生かす）なので、
  **Active 状態からでも必ず認証を要求する**。これは `extend_authenticated` の
  「Active からは認証なし」とは **意図的に非対称**: extend は TTL が既に許す窓を再確認するだけ、
  pin はその TTL を上書きする。だから人間が明示的に「露出延長」を承認する必要がある。
- `unpin(key)`: **認証不要**。reprieve を外すのは「失効側＝安全側」に戻す操作なので gate しない。
- `AuthOperation::Pin` variant を追加（`CommandAuthenticator` には `CACHE_WARDEN_AUTH_OPERATION=pin` で渡る）。

protocol / CLI:

- protocol: `kv.pin`(key, duration_secs) / `kv.unpin`(key)。エラーは NotFound / HardExpired / AuthFailed。
- CLI: `cache-warden kv pin <KEY> <DURATION>`（既存 duration パーサ再利用、1h/30m/45s/秒数）/ `kv unpin <KEY>`。
- pin 状態は status / kv.list の `EntryInfo.pin_remaining_secs`（残り秒、秘密値は出さない）に出す。

## Alternatives Considered

- 案 A: pin の代わりに **hard_deadline を直接ずらす**（`kv extend --hard 8h` 相当）
  - 不採用理由: ユーザ意図は「**T 時刻まで止まらないでほしい**」であって「hard 寿命を N 時間延ばす」
    ではない。deadline 指定（`pin_until`）の方がこの意図に正確。「8h 延ばす」だと既に経過した分との
    合算が直感に反する。pin は「T まで抑止 → T 以降は本来の判定」という素直な意味論になる。
- 案 B: **soft だけ延ばす**（hard はそのまま）
  - 不採用理由: ユースケースを満たさない。夜間に **hard** が来るのが問題で、soft だけ延ばしても
    hard 期限で zeroize されて AI 作業が止まる。
- 案 C: 単一基準 `activated_at` のまま「extend は hard を動かさない」フラグ運用
  - 不採用理由: 2 基準に分けた方が state 判定が素直で、idle extend（soft 延命）と絶対寿命（hard 固定）
    が構造的に独立する。フラグ分岐は `design-thinking` のワークアラウンドフィールドに当たる。

## Consequences

- 「extend し続ければ hard が永遠に来ない」曖昧仕様が解消。hard は値の絶対寿命として確定し、
  明示の pin でだけ期限を先送りできる。
- idle extend（頻用鍵は soft 再認証なしで生き続け、放置すると soft 切れ）が
  authsock アダプタ（DR-0004 判断 3）の前提として正しく配線できるようになった。
- pin の非対称認証（Active からでも再認証必須）は監査ログ上「いつ誰が露出を延長したか」を
  必ず残す。extend のサイレント延長とは扱いを分ける。
- pin 中に本来の hard を超過したエントリは、pin 切れの瞬間に即 `HardExpired` になり zeroize される。
  pin はあくまで「期限までの猶予」で、永続保持ではない。

## 関連

- [DR-0003](./DR-0003-secure-kv-core-and-adapters.md) — 2 段 TTL コアの定義
- [DR-0004](./DR-0004-authsock-warden-succession.md) — authsock 移植（idle extend の前提）
- [DR-0010](./DR-0010-config-and-reauth-command.md) — 再認証コマンド方式（pin もこの Authenticator を使う）
- `docs/design/authsock-adapter-port-plan.md` Iteration -1 / 判断 3 — 本 DR の起点
