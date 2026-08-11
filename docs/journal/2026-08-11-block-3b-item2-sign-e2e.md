# Block 3b Item 2: authsock SIGN 動線の実機 e2e (2026-08-11)

draft-DR-0031 の SIGN dialog 統合 (commit `52b95386`) を実機で e2e 検証した記録。
Item 4 (graceful restart) / Item 5 (helper down) 相当の観測も同時に取れた。

## 隔離環境の構成

- dev daemon: `target/debug/cache-warden` (Developer ID 署名済み、7/13 ビルドのまま
  署名維持) を `--socket /private/tmp/cw-e2e/state/control.sock` で起動
- env: `CACHE_WARDEN_CONFIG=/private/tmp/cw-e2e/config/cache-warden/config.toml` +
  `XDG_STATE_HOME=/private/tmp/cw-e2e/state` +
  `CACHE_WARDEN_APPROVER_BIN=<repo>/target/debug/CacheWardenApprover.app/Contents/MacOS/cache-warden-approver`
  (helper 探索は env 明示 or production パスのみ、`resolve_approver_helper_path`)
- config: `[authsock.sockets.test] path = "/private/tmp/cw-e2e/agent.sock"`,
  `keys = ["test/sshkey"]`
- テスト鍵: `ssh-keygen -t ed25519` の使い捨て鍵を
  `kv set --namespace test --require-same-shell -- sshkey "$(cat ...)"` で投入
  (kawaz のターミナル zsh から。same-shell pin のため set と ssh-add は同一シェル必須)
- 観測: coreauthd `log stream` (user 501 filter) + daemon stderr log

## ハマり所 (準備段階)

1. **静的 keys の agent registry は socket bind 時にのみ構築される**
   (`build_registry`、daemon 起動後の `kv set` は反映されない)。in-memory store を
   保ったまま registry を再構築するには **`daemon restart --graceful`** (DR-0029、
   guard record も handoff される)。set → graceful restart → `ssh-add -L` で鍵が載る
2. **CLI の KEY は `/` 不可** (DR-0017、`--namespace` フラグ一本)。state file の
   準備例 `kv set test/sshkey` は誤りだった
3. **PEM 値の `-----BEGIN` がオプションに誤パースされる** → `--` セパレータで回避
   (`set --namespace test --require-same-shell -- sshkey "<PEM>"`)。clap 移行 issue
   (`2026-07-13-socket-flag-position-doc-mismatch`) の追加実機サンプル

## 観測サイクル (coreauthd = grand truth、時刻 JST)

| # | Mechanism | 操作 | coreauthd | CLI (`ssh-add -T`) | 判定 |
|---|---|---|---|---|---|
| 1 | 196 (22:42:32) | approve | `has matched by <private>` (22:42:36) | 成功 (無出力 exit 0) | 署名成功 ✓ |
| 2 | 197 (22:42:58) | cancel | `Code=-9 Invalidated by client` 即時 | `agent refused operation` | SSH_AGENT_FAILURE ✓ |
| 3 | 198 (22:44:16) | 90s 放置 | (放置中 heartbeat のみ) | 90s 後 `agent refused operation` | daemon timeout ✓ |
| 3' | 198 (22:49:18) | 放置後に指置き | `has matched by` (幽霊承認) | — | daemon が stale 破棄 ✓ |
| 4 | 199-200 | 追加実行分を cancel | `Code=-9` | `agent refused operation` | キュー消化 |
| 5 | 202 (22:57:19) | approve (文言修正後) | `has matched by` | 成功 | "sign with" 表示 ✓ |
| 6 | 203 (22:58:11) | helper SIGKILL 後に実行 | `has matched by` | 成功 | recovery 再 spawn ✓ |

### 幽霊承認の破棄 (fail-closed の決定的証拠)

```
cache-warden: authsock sign denied for "test/sshkey": approver dialog failed (helper did not respond within 90s)
cache-warden: approver: discarding stale response request_id="33470-2" while awaiting "33470-3"
```

timeout 済み request への approve は daemon が明示的に破棄し、秘密鍵での署名は
行われない。CLI のエラーメッセージは cancel と同一 (SSH agent wire に error 詳細
フィールドが無い = 何も漏らさない設計のとおり)。

### dialog wedge / SIGN キュー積み (v1 既知制約の実機サンプル)

- timeout 後も dialog は画面に残り続ける (helper 側 countdown なし)。放置 dialog
  への操作は全て stale 破棄されるが、ユーザには「誰も見ていない dialog」に見える
- 追加の `ssh-add -T` は helper のキューに積まれ、前の dialog の decision 後に
  順番に表示される (#199→#200 と連鎖)
- → `2026-07-12-approver-release-hardening` 項目 5/6 の裏付けサンプル

### Item 4 相当: dialog 表示中の graceful restart

22:56:25 の `daemon restart --graceful` で、画面に残っていた wedged dialog (#201)
が helper SIGKILL により即 `Code=-9` で閉じ、restart は人間承認を待たずに完了
(state-holder exit 0、同一 pid 33470 維持、鍵 registry 1 key 維持)。HIGH-1 修正
(shutdown の SIGKILL 経路) の実機観察。

### Item 5: helper down → recovery

helper を SIGKILL → 次の SIGN 要求で daemon が接続死を検知し **1 回だけ再 spawn +
再送** (Phase 1.6 Block 1 の設計どおり)。新 dialog が出て approve → 署名成功。
「respawn も失敗する場合の fail-closed 拒否」経路は binary 不在にしないと出ない
ため今回は未観測 (unit test では pin 済み)。

## 発見 bug と修正

**dialog summary が operation を無視して常に "read" 表示** (`main.rs` の
`"Allow {} to read {}"` hardcode)。SIGN 経路で "Allow ssh-add to read test/sshkey"
と誤表示されていた。透明性がこの機能の眼目なので即修正 → `summary_line()` で
operation を動詞句化 ("sign" → "sign with"、get/extend/regenerate/pin → "read"、
未知 operation は verbatim)。commit `b8d4ec72`。修正後の実機で "sign with" 表示を
kawaz が確認 (#202)。

## 残作業

- Item 6 (coreauthd 全体照合): 本記録の表が実質それに相当。拒否経路 (cancel /
  timeout / guard) で**余計な TouchID 発火が無い**ことはサイクル表で確認済み
  (dialog 発火 = 要求ごとに 1 回、機械 gate 拒否時の非発火は unit test で pin)
- push (v0.26.0) は PSH-Q1 裁定どおり Block 3b 完了判断後
