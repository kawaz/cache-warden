# Runbook: authsock-warden ↔ cache-warden パリティ検証・切替・引退

- Last Updated: 2026-06-11

cache-warden の authsock アダプタが authsock-warden と機能パリティを達成したことを
実機で突き合わせ (Phase 2)、利用 socket を可逆に切り替え (Phase 3)、最終的に
authsock-warden を引退させる (Phase 4) ための手順。移行パスは
[DR-0004](../decisions/DR-0004-authsock-warden-succession.md)、検証戦略は
[port plan §4](../design/authsock-adapter-port-plan.md) に対応する。

各手順に **[無人可]** / **[同席要]** を付す。TouchID / 1Password プロンプトが絡む手順は
**[同席要]** (op 鍵 fetch・SSH 署名は TouchID を引くため、人の認証操作が必要)。

## 適用ケース

- authsock アダプタの実装が一段落し、warden と並べて挙動を突き合わせたいとき (Phase 2)
- 日常利用を cache-warden 側に寄せたいとき (Phase 3)
- 安定確認後に warden を止めたいとき (Phase 4)

## 前提

- cache-warden バイナリがビルド済み (`just build` → `target/release/cache-warden`)
- authsock-warden が日常稼働中 (launchd `com.github.kawaz.authsock-warden`)。**触らない**
- 並走用 config: `~/.config/cache-warden/parity-draft.toml`
  (実値入り・リポ外。warden 実 config と機能等価・socket パスだけ `.cw` suffix)
- 不変条件 (DR-0004): **全フェーズで日常の SSH 署名 / 1Password 連携を中断させない**。
  切替は可逆に進め、問題が出たら旧経路へ即戻す
- 実値 (op_account / vault / socket パス / フィルタ) は
  `~/.config/cache-warden/parity-draft.toml` 参照。本 runbook はプレースホルダ表記

記法: `<repo>` = cache-warden リポの worktree、`<draft>` =
`~/.config/cache-warden/parity-draft.toml`、`<sockN>` = 各並走 socket パス
(`~/.ssh/agent-<env>.sock.cw`)、`<warden-sockN>` = warden 側の対応 socket
(`~/.ssh/agent-<env>.sock`)。

---

## Phase 2: 並走パリティ確認

warden を従来どおり稼働させたまま、cache-warden を別 socket で並走起動し、両者の挙動を
突き合わせる。**実 `SSH_AUTH_SOCK` は最後まで warden のまま**。cache-warden 側は手動で
`SSH_AUTH_SOCK=<sockN>` を指定したときだけ使う (検証用)。

### 2.0 config 文法検証 **[無人可]**

daemon を起動せず config をパース・検証する (TouchID なし)。

```bash
CACHE_WARDEN_CONFIG=<draft> <repo>/target/release/cache-warden config show
```

期待結果: exit 0。`authsock sockets:` に並走 socket が全件 (warden と同数) 列挙される。
parse 失敗 (未宣言 source / 不正 filter / 不正 kind 等) は exit 1 + エラー行で停止する。

### 2.1 並走 daemon 起動 **[同席要]**

cache-warden daemon をフォアグラウンド or バックグラウンドで起動。起動時に source の
op 鍵発見 (`op item list` / `op item get`) が走ると **TouchID 1 回** を引く可能性がある。

```bash
CACHE_WARDEN_CONFIG=<draft> \
  <repo>/target/release/cache-warden daemon run --socket /tmp/cw-parity-control.sock
```

期待結果: 各 `<sockN>` (`.cw` suffix) が bind される。warden の `<warden-sockN>` は無傷
(別パスなので衝突しない)。`ls -l ~/.ssh/agent-*.sock*` で warden 側と並走側の両方が
存在することを確認。

差異記録: bind 失敗 / 既存 socket 衝突が出たら、`.cw` suffix が warden パスと衝突して
いないか `ls -l` で確認 (本来別パスなので衝突しないはず)。

### 2.2 REQUEST_IDENTITIES 突き合わせ (`ssh-add -l` / `-L`) **[同席要]**

同一 source・同一フィルタの socket どうしで、列挙される公開鍵集合が一致するか確認する。
初回列挙時に op 発見が走れば TouchID を引く (以降キャッシュ)。

```bash
# warden 側
SSH_AUTH_SOCK=<warden-sockN> ssh-add -L | sort > /tmp/parity-warden-<env>.keys
# cache-warden 側
SSH_AUTH_SOCK=<sockN>        ssh-add -L | sort > /tmp/parity-cw-<env>.keys
diff -u /tmp/parity-warden-<env>.keys /tmp/parity-cw-<env>.keys
```

期待結果: `diff` が空 (フィルタ適用後の公開鍵集合がバイト一致)。

差異記録: diff が出たら **フィルタ / op 発見ロジックの移植バグ**。記録するもの =
両 socket の `ssh-add -L` 全文、適用フィルタ (draft の該当 socket の `filters`)、
cache-warden daemon の stderr ログ。特に `comment=` フィルタ socket と
`github=` フィルタ socket は分けて比較する (判定経路が違う)。

### 2.3 フィルタ挙動比較 **[同席要]**

各 socket のフィルタが warden と同じ鍵を「見せる / 隠す」か確認する。2.2 の鍵集合一致が
基本指標。加えて **隠れるべき鍵が隠れているか** を確認:

- `github=<user>` socket: 別ユーザの鍵が列挙に出ないこと
- `comment=*<pat>*` socket: comment 不一致の鍵が列挙に出ないこと

```bash
# 各 env で 2.2 の diff が空であることをもって一致とみなす。
# 隠蔽確認: 全鍵を見せる無フィルタ socket があれば、それとの差集合が
# 「フィルタで隠れた鍵」= warden 側と同じ集合か確認する。
```

期待結果: 各 socket の列挙鍵集合 = warden の対応 socket と一致。

差異記録: 余分に見える / 足りない鍵の comment・fingerprint、draft の filters 表記
(OR / AND の解釈差が原因のことがある = draft 内コメント参照)。

### 2.4 allowed_processes 挙動比較 **[同席要]**

warden 実 config は全 socket `allowed_processes = []` (制限なし)。cache-warden も draft で
全 `[]`。**空のときは両者とも全プロセス通過** が不変条件。

```bash
# 制限なし socket では、任意プロセスから列挙が通ることを確認 (= 2.2 が通ればOK)。
SSH_AUTH_SOCK=<sockN> ssh-add -l   # 通れば制限なしの挙動が一致
```

期待結果: 制限なし socket で列挙が通る (warden と同じ)。

差異記録: 制限なしのはずが拒否される (`SSH_AGENT_FAILURE`) なら、空配列の扱いが
fail-closed に倒れていないか cache-warden daemon ログを確認。
(非空 allowed_processes のパリティは warden 実 config に該当例が無いため Phase 2 の
スコープ外。必要なら別途 fake 設定で検証。)

### 2.5 署名突き合わせ **[同席要]**

同じ challenge を両 socket で署名させ、両方とも検証が通るか確認する。実用的には GitHub への
SSH 認証で代用できる。op 鍵 fetch 済みなら TouchID は soft TTL 内で 0 回。

```bash
# warden 側
SSH_AUTH_SOCK=<warden-sockN> ssh -T git@github.com
# cache-warden 側 (対応する GitHub アカウント名が返るか確認)
SSH_AUTH_SOCK=<sockN>        ssh -T git@github.com
```

期待結果: 両方とも `Hi <user>! You've successfully authenticated...` が返り、
**同じ GitHub ユーザ名**になる (= 同じ鍵で署名できている)。Ed25519 は決定的なので、
厳密にやるなら同一 challenge での署名バイト一致も確認可能。

差異記録: 片方だけ認証失敗 / 別ユーザになる場合、使われた鍵の fingerprint
(`ssh -v` で確認)、cache-warden の署名経路ログ。

### 2.6 TouchID 回数比較 (最重要 UX 指標) **[同席要]**

**署名モデルは両者とも「op 発見鍵 = PEM を fetch してローカル署名」で同型** (warden の
`[auth] method=command` は署名委譲ではなく**ユーザ定義の認証フロー** = cache-warden の
`[auth].command` と同概念)。違うのは**キャッシュ寿命**: warden は鍵キャッシュの TTL が
実質無期限 (TTL コア未配線、port plan §1.3) なのに対し、cache-warden は実 TTL
(soft = idle extend / hard = 絶対寿命) が効く。TouchID の出るタイミングと回数を実測して
この差を確認する。

| シナリオ | warden の想定 | cache-warden の想定 |
|---|---|---|
| 初回 op 鍵 fetch + 初回署名 | fetch 時に認証 1 回、以降キャッシュ | 同じく fetch 時 1 回 (op item get) |
| キャッシュ生存中の連続署名 | 0 回 (無期限キャッシュ) | 0 回 (soft TTL 内、使うたび extend) |
| soft TTL 切れ後の署名 | 発生しない (TTL なし) | `[auth].command` の認証 1 回で extend (warden と同じスクリプトを draft に設定) |
| hard TTL 切れ後の署名 | 発生しない (TTL なし) | op 再 fetch で TouchID 1 回 (値の絶対寿命、設計どおり) |

```bash
# 各シナリオで ssh -T git@github.com を打ち、TouchID プロンプトが出た回数を数える。
# 連続署名は短時間で複数回 ssh -T を打つ。soft 切れは draft の soft-ttl 経過後に再実行。
```

期待結果: キャッシュ生存中は両者とも 0 回 (= 日常体感は同等)。cache-warden だけ
soft/hard 失効時に認証が**増える**が、これは warden で未配線だった TTL が設計どおり
効いている正常動作 (バグではない)。

差異記録: キャッシュ生存中 (soft TTL 内) に cache-warden が TouchID / 認証を要求したら
extend 配線のバグ (port plan §1.3 / §1.4)。記録 = シナリオごとの回数、draft の soft-ttl /
hard-ttl 値、cache-warden daemon ログ (鍵 fetch / extend / regenerate のログ行)。

### 2.7 並走 daemon 停止 **[無人可]**

検証が終わったら cache-warden daemon を止める (warden は無傷のまま継続)。

```bash
# フォアグラウンド起動なら Ctrl-C。バックグラウンドなら pid に SIGTERM。
# warden (launchd) には一切触らない。
rm -f /tmp/cw-parity-control.sock ~/.ssh/agent-*.sock.cw   # 残留 socket 掃除 (.cw のみ)
```

期待結果: `<sockN>` (`.cw`) が消え、warden の `<warden-sockN>` は残る。日常利用は無影響。

---

## Phase 3: 切替 (可逆)

Phase 2 でパリティ確認後、日常利用の `SSH_AUTH_SOCK` を cache-warden 側に向ける。
**1 行差し戻しで即元に戻せる形**にする (DR-0004 可逆性)。

### 3.1 切替前の現状記録 **[無人可]**

```bash
# 現在の SSH_AUTH_SOCK 指定箇所を控える (~/.ssh/config の IdentityAgent / shell env 等)
grep -rn IdentityAgent ~/.ssh/config 2>/dev/null
echo "current SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
```

期待結果: 現在の向き先 (warden socket) を記録。巻き戻しの基準になる。

### 3.2 cache-warden を常設 socket で起動 + 向き先変更 **[同席要]**

切替では `.cw` suffix を外し、warden が使っていた **本来の socket パス** を
cache-warden に握らせる方式と、`.cw` のまま `SSH_AUTH_SOCK` だけ向け替える方式がある。
**可逆性を優先するなら後者** (warden socket を奪わず、向き先だけ変える)。

```bash
# 方式 B (推奨・可逆): warden は止めず、SSH_AUTH_SOCK だけ cache-warden の .cw socket へ向ける。
#   ~/.ssh/config の IdentityAgent または shell env を <sockN> に変更。
#   warden socket は残るので、1 行戻すだけで即フォールバック可能。
```

期待結果: 日常の `ssh` / `git` が cache-warden 経由で署名できる。`ssh -T git@github.com`
が正しいユーザを返す。

差異記録: 認証失敗が出たら 3.3 で即巻き戻し、Phase 2 の diff を取り直す。

### 3.3 巻き戻し (フォールバック) **[同席要]**

問題が出たら向き先を warden に戻す。

```bash
# 3.2 で変更した IdentityAgent / env を 3.1 で記録した warden socket に戻す。
# 1 行戻すだけ。cache-warden daemon は止めてよい (warden が即引き継ぐ)。
```

期待結果: `SSH_AUTH_SOCK` が warden に戻り、日常利用が即復旧。

---

## Phase 4: 引退

切替後に十分安定 (数日〜) を確認してから authsock-warden を止める。**可逆に**進める。

### 4.1 warden 停止 (launchd unload) **[同席要]**

```bash
# launchd から unload (RunAtLoad/KeepAlive を切る)。plist は消さず残す (巻き戻し用)。
launchctl bootout gui/$(id -u)/com.github.kawaz.authsock-warden 2>/dev/null \
  || launchctl unload ~/Library/LaunchAgents/com.github.kawaz.authsock-warden.plist
# warden socket が消えても日常利用が cache-warden で継続することを確認
ssh -T git@github.com
```

期待結果: warden プロセスが消え (`ps aux | grep authsock-warden` で不在)、
日常の SSH 署名は cache-warden で継続。

### 4.2 巻き戻し (warden 再起動) **[同席要]**

引退後に問題が出たら warden を即復活させる。

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.github.kawaz.authsock-warden.plist 2>/dev/null \
  || launchctl load ~/Library/LaunchAgents/com.github.kawaz.authsock-warden.plist
# 必要なら SSH_AUTH_SOCK を warden socket に戻す (Phase 3.3)
```

期待結果: warden プロセスが復活し、socket が再生成される。Phase 3.3 と合わせて日常利用が
warden 経路に戻る。

---

## 失敗時の切り分け

| 症状 | 原因 | 対処 / 記録 |
|---|---|---|
| `config show` が exit 1 | draft の文法エラー (未宣言 source / 不正 filter / 不正 kind) | エラー行の socket 名・フィールドを修正。draft はリポ外なので自由に直す |
| 2.2 の `ssh-add -L` diff が出る | フィルタ / op 発見の移植バグ、OR/AND 解釈差 | 両 socket の `-L` 全文 + draft の filters + daemon ログを記録 |
| 2.6 で TouchID が warden より増える | キャッシュ / TTL 配線バグ (port plan §1.3/§1.4) | シナリオ別回数 + soft/hard-ttl + 鍵 fetch/extend ログを記録 |
| 制限なし socket で署名拒否 | 空 allowed_processes が fail-closed に誤って倒れている | daemon ログの process gate 判定を確認 |
| 切替後に認証失敗 | 向き先 / 鍵集合の不一致 | Phase 3.3 で即巻き戻し → Phase 2 を取り直す |

### ログ位置 / 比較コマンド

- authsock-warden: `~/Library/Logs/authsock-warden/output.log` (JSON audit)
- cache-warden: daemon の stderr (フォアグラウンド起動ならそのまま、バックグラウンドなら
  起動時にリダイレクト先を決める)。両者の構造化ログを `diff` で突き合わせる
- 鍵集合比較: `ssh-add -L | sort` の diff (2.2)
- peer pid / プロセス確認: `lsof <sockN>` / `ps` (allowed_processes の実確認)

## 関連

- [DR-0004: authsock-warden の後継・吸収方針](../decisions/DR-0004-authsock-warden-succession.md) — 移行 Phase 0–4 の定義
- [authsock アダプタ移植計画](../design/authsock-adapter-port-plan.md) — §4 検証戦略 / §4.2 日常利用を壊さない手順
- `~/.config/cache-warden/parity-draft.toml` — 実値入り並走 config 案 (リポ外)
- [DESIGN-ja.md「authsock アダプタ」節](../DESIGN-ja.md) — config 文法・フィルタ・署名モデル
