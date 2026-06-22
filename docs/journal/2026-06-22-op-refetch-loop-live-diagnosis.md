# DR-0022 fetch failure backoff の live 診断

- 日付: 2026-06-22
- 関連: [DR-0022](../decisions/DR-0022-fetch-failure-backoff.md), [issue: op-refetch-loop](../issue/2026-06-14-op-refetch-loop.md), [runbook: op-refetch-loop-live-diagnosis](../runbooks/op-refetch-loop-live-diagnosis.md)

## TL;DR

`fetch-failure-backoff = 5s` (default) で **DR-0022 が動作することを実機確認**。1 回目 dismiss → 5s 以内の 2 回目は **TouchID UI を発火させず agent refused operation を 16ms で返す**。5s 経過後の 3 回目は通常通り op fetch → TouchID 経路に戻る。

## 検証結果テーブル

稼働環境:
- daemon: v0.22.1 (`/Applications/CacheWarden.app/Contents/MacOS/cache-warden`) を fg 起動、PID 1865 / config 不在 (= default `fetch-failure-backoff = "5s"`)
- 1Password: Lock 状態 + biometric session 切断後
- sign 経路: `SSH_AUTH_SOCK=$HOME/.ssh/agent-kawaz.sock.cw ssh-keygen -Y sign ...` (= ssh_config の Host マッチ無しで SSH_AUTH_SOCK が効く経路)

| 回 | 操作 | ssh-keygen exit | elapsed | sig 生成 | coreauthd 観測 | 判定 |
|---|---|---|---|---|---|---|
| 1 | kawaz dismiss | 255 (agent refused) | 4068ms | なし | UI 表示 → `Code=-9 "Invalidated by client"` | dismiss → backoff 立つ |
| 2 (即) | (操作なし) | 255 (agent refused) | **16ms** | なし | **biometric request 一切無し** | **backoff active で fetch skip** ✅ |
| 3 (sleep 6 後) | kawaz approve | 0 | 16653ms | あり | UI 表示 → `has matched by <private>` + `has finished with {...}` | approve → fetch 成功 + sign |

判定の決め手:
- 2 回目で **16ms / coreauthd の TouchID 発火ログが完全に出ていない** = cache-warden 内で `RegenerateOutcome::Backoff` が即返り、op CLI 起動すらしていない (= DR-0022 の `failure_backoffs` が機能)
- 3 回目で TouchID 出る = 5s 経過後 `failure_backoffs` が expire し fetch 経路に戻る

## 検証中に踏んだ罠 (= 過去セッション再発防止)

学びはすべて [`/.claude/rules/ssh-agent-socket-test-isolation.md`](../../.claude/rules/ssh-agent-socket-test-isolation.md) に反映済み。要点だけ列挙:

1. **ssh_config の `Host *` IdentityAgent**: `~/.ssh/config` の `Host *` で `IdentityAgent ~/.ssh/agent-kawaz.sock` (= `.aw` symlink) が default 適用。`Host` 引数を取るコマンド (ssh / scp / sftp / git ssh) はこれが効き、`SSH_AUTH_SOCK` が無視される
2. **`ssh-keygen -Y sign` は Host 引数なし**: ssh_config の Host マッチが起きようがないので SSH_AUTH_SOCK だけ見られる (= 試験で `.cw` socket に確実に届けられる経路)
3. **1Password biometric session caching**: 直前に別経路 (`op item list` 等) で TouchID 通すと一定時間 cache-warden の op fetch でも biometric が skip される。検証前に **1Password Lock 必須** (Cmd+Opt+L)
4. **daemon の memory cache**: 一度 op fetch 成功した op key は daemon プロセス内に保持 (= entries には出ない別管理)。clean state には **daemon 再起動**必要
5. **検証中の time gap**: 1 回目 → 2 回目で AskUserQuestion 等の対話を挟むと backoff 5s が expire してしまう。**同 Bash で連続実行**する
6. **TouchID 観測の grand truth**: `coreauthd` の `DeviceOwnerAuthenticationWithBiometrics` request + `MechanismTouchId starting` + `will start matching user` の 3 要素で UI 表示判定。`has matched by <private>` で approve 判定。`Code=-9 "Invalidated by client"` で dismiss/timeout 判定 (dismiss vs timeout は elapsed time / op CLI エラーで区別)
7. **daemon 起動経路**: 試験のため fg 起動するときも notarize 済み `/Applications/CacheWarden.app/Contents/MacOS/cache-warden` を使う (dev build だと Gatekeeper ダイアログが鬱陶しい、別 rule `daemon-notarized-binary.md` 参照)
8. **設定ファイルは Read ツールで全行読む**: `~/.ssh/config` + `Include` 先、`~/.config/git/config` + `[include]` / `[includeIf]` 先全部、system gitconfig 等。grep / head で部分抽出すると Host * のような重要 default を見落とす

## 残 TODO

DR-0022 のコア機能 (= A-3b) は動作確認できたが、補助実装が未完:

- [ ] **A-3d (CLI 出力に `backoff_until` 表示)**: `cache-warden status` で `entries: (none)` のみ。DR-0022 で `status` / `kv list` 応答に `backoff_until: Option<seconds>` 追加が範囲だが未実装。backoff 中の key を可視化する CLI 拡張が必要。本 issue (`docs/issue/2026-06-14-op-refetch-loop.md`) の残作業として継続するか、別 issue に切る
- [ ] **A-3c (op の失敗種別区別調査)**: DR-0022 で `pending-sublimation` 判定済み (= 一律 5s で確定)、DR-0024 として follow-up 候補
- [ ] **副次問題 `touchid-blocks-blocking-pool`** (別 issue): DR-0022 範囲外
- [ ] **op discovery の launchd 経路問題**: 別途、launchd 経由の `op item list` が常に timeout する現象を確認 (= `issue/2026-06-13-op-discovery-blocks-startup.md` の症状と一致)。本 verification は fg daemon で回避したが、別 issue で対処要

## issue ステータス遷移候補

`docs/issue/2026-06-14-op-refetch-loop.md` は:
- **コア機能** (A-3b backoff 動作) = 動作確認済み
- **CLI 表示** (A-3d) = 未実装

A-3d を別 issue に切ってからこの issue を close する筋。kawaz と相談。
