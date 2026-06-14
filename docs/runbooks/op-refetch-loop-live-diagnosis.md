# Runbook: op-refetch ループの live 診断

- Last Updated: 2026-06-14

dogfood Phase 3 (cache-warden が日常 SSH の本番) 中に TouchID が連発する現象
(issue `docs/issue/2026-06-14-op-refetch-loop.md`) に対し、**kawaz が在席している
タイミング**に本番 daemon を生かしたまま live で調査・診断する手順。

本手順は以下の 3 つを目的とする:

1. **接続元 (rate driver) の特定**: 何が `.cw` agent socket に繰り返し接続して
   SIGN_REQUEST を送っているかを `lsof` で観測する
2. **TouchID 連発の種別判定**: cache-warden の `[auth]` (CommandAuthenticator) 起因か、
   op CLI 自身が出す biometric prompt か区別する
3. **DR-0022 実装前後の比較材料収集**: backoff 実装後に「2 回目以降の SIGN では
   TouchID が出ない」「backoff active ログが出る」ことを観測する

各ステップに **[観測のみ]** / **[操作要]** を付す。**[操作要]** は kawaz の手操作
(TouchID 応答、プロセス kill 等) が必要。

---

## 0. 事前準備 [観測のみ]

### 0.1 daemon 稼働確認

dogfood Phase 3 の現在の稼働状態は以下のとおり (journal `2026-06-13-handoff` §現在の稼働状態 参照):

- launchd ラベル: `com.github.kawaz.cache-warden`
- `.cw` socket: `~/.ssh/agent-kawaz.sock.cw` / `agent-emerada.sock.cw` / `agent-syun.sock.cw`
- control socket: `$XDG_STATE_HOME/cache-warden/control.sock`
  (= `~/.local/state/cache-warden/control.sock` が通常)
- config: `~/.config/cache-warden/config.toml`

daemon が稼働中かを確認する:

```bash
# launchd 登録状態と PID を確認
launchctl print gui/$(id -u)/com.github.kawaz.cache-warden | head -20
```

期待: `state = running`、`pid = <N>` の行が出る。`state = not running` / service not found
なら daemon が停止している (= live 診断の前提が崩れる)。

### 0.2 socket パスの確定

実際に存在する `.cw` socket を確認する:

```bash
ls -la ~/.ssh/agent-*.sock.cw 2>/dev/null
```

存在しない socket は後続の `lsof` コマンドから除外する。以降の手順では
`<cw-socks>` を実在する `.cw` socket の列で読み替える。

### 0.3 daemon ログの出力先確認

launchd plist の `StandardOutPath` / `StandardErrorPath` を確認する:

```bash
# plist ファイルを探す
ls ~/Library/LaunchAgents/com.github.kawaz.cache-warden.plist 2>/dev/null \
  || ls /Library/LaunchAgents/com.github.kawaz.cache-warden.plist 2>/dev/null

# plist 内のログパスを確認
plutil -p ~/Library/LaunchAgents/com.github.kawaz.cache-warden.plist 2>/dev/null \
  | grep -E '(StandardOut|StandardError)'
```

ログパスが不明な場合の代替:

```bash
# launchctl から直接 PID を引いてファイルディスクリプタ確認
daemon_pid=$(launchctl print gui/$(id -u)/com.github.kawaz.cache-warden \
  | awk '/pid =/ { print $3 }')
echo "daemon PID: $daemon_pid"
lsof -p "$daemon_pid" | grep -E '(log|txt|out|err)' | head -10
```

以降の手順では `<daemon-log>` を実際のログパスで読み替える。

### 0.4 注意事項

- **daemon は止めない**: 前 session で daemon を止めて live 証拠を失った教訓がある
  (journal §A)。本手順は全観測を daemon 稼働中に行う
- **launchctl unload / bootout は禁止**: 本番 dogfood を止めるだけでなく、
  live 証拠が得られなくなる
- 補助的に起動した `lsof` / `tail` は Ctrl-C で終了するだけでよい

---

## 1. 観測 1: lsof で agent socket 接続元の特定 [観測のみ]

### 目的

「どのプロセスが `.cw` socket に繰り返し接続しているか」を 1 秒間隔で監視し、
TouchID が出ているタイミングの接続元プロセス名と PID を記録する。

### コマンド (ターミナル A)

```bash
# 実在する .cw socket を列挙して 1 秒間隔でアクセス元を監視
# <sock1> <sock2> ... の箇所は 0.2 で確認した socket パスに差し替える
lsof -r 1 ~/.ssh/agent-kawaz.sock.cw \
           ~/.ssh/agent-emerada.sock.cw \
           ~/.ssh/agent-syun.sock.cw 2>/dev/null
```

`-r 1` は 1 秒間隔の繰り返し表示。`lsof` が利用できない場合の代替:

```bash
# fs_usage で socket ファイルへのアクセスを観測 (要 sudo)
sudo fs_usage -w -f filesys | grep -E 'agent-.+\.cw'
```

### 観測ポイント

- TouchID が出た / 消えた瞬間に表示された `COMMAND` 列 (プロセス名) と `PID` 列を記録する
- 同一 PID が短時間に繰り返し現れる場合、それが接続元の rate driver 候補
- `COMMAND` が `ssh` / `git` / IDE 系 (`GoLand` / `Cursor` / `code`) / `op` などか確認する

### 期待結果

| COMMAND 例 | 意味 |
|---|---|
| `ssh` | SSH クライアント (手動実行 or IDE 統合) |
| `git` | git 操作 (IDE 自動 fetch / push 等) |
| `op` | op CLI が直接 socket に触れている |
| IDE 系プロセス | IDE の git/SSH 自動操作 |

### 終了

接続元 PID を控えたら Ctrl-C。

---

## 2. 観測 2: daemon ログを tail して失敗ログを確認 [観測のみ]

### 目的

daemon が「op fetch 失敗」と「Broken Pipe」のどちらを、いつ、何回出しているかを
リアルタイムで観測する。2 種類のログを**混同しないこと** (DR-0022 §5 参照)。

### コマンド (ターミナル B)

```bash
# <daemon-log> は 0.3 で確認したログパスに差し替える
tail -F <daemon-log>
```

ログパスが不明な場合:

```bash
# /tmp 以下や ~/Library/Logs に出力されている可能性
ls ~/Library/Logs/cache-warden/ 2>/dev/null
ls /tmp/cache-warden*.log 2>/dev/null
```

### 観測ポイント: 2 種類のログを区別する

**ログ A: op fetch 失敗** (`op_private_key.rs:57`)

```
op private key fetch failed for item <item-id>: ...
```

意味: `runner.run` (op CLI 実行) が `Err` を返した。TouchID dismiss / timeout /
認証情報不備などで op CLI が exit 非ゼロになったとき出る。
このログが出た後、該当 key の `store.set` は呼ばれず entry が absent のまま残る。

**ログ B: Broken Pipe** (`authsock.rs:488`)

```
authsock connection error: Broken pipe
```

意味: SIGN_REQUEST の送信元クライアントが応答を待たずに接続を切断した。
コード調査 (2026-06-14) で確定: **fetch 結果 / cache への書き込みとは無関係**。
peer 切断は `write_all` で観測されるだけで、fetch 自体は既に完了している。
ログ B だけが出ている場合、fetch 失敗ループの原因ではない。

**観察フロー**: TouchID が連発するとき、ログ A と B のどちらが先に出るか、
どちらが多いかを観測する。ログ A が繰り返し出ているなら新仮説が支持される。

### 終了

観測が終わったら Ctrl-C。

---

## 3. TouchID 種別の判定 [観測のみ]

### 目的

連発している TouchID が「cache-warden の `[auth]` (CommandAuthenticator)」から
出ているのか「op CLI 自身の biometric prompt」から出ているのかを切り分ける。

### 確認方法

```bash
# config の [auth] 節を確認
grep -A 5 '^\[auth\]' ~/.config/cache-warden/config.toml 2>/dev/null \
  || echo "[auth] セクションなし"
```

#### 判定表

| config 状態 | cache-warden 側 TouchID | 含意 |
|---|---|---|
| `[auth]` 節なし / `AllowAll` | 出ない | 連発は全て op CLI 由来 |
| `[auth].command = "..."` 設定あり | command 実行ごとに出る可能性 | 両方の可能性を考慮 |

dogfood Phase 3 の現 config で `[auth]` 節が未設定なら、
**TouchID は全て op CLI (`__authsock-op-private-key` サブコマンド経由) が出している**
と仮定できる。この場合、SIGN_REQUEST → `lazy_load_op_key` → op fetch (TouchID) の
経路で op が直接 TouchID を出している。

---

## 4. 接続元の追跡: ps で親プロセスチェーンを遡る [観測のみ]

### 目的

観測 1 で得た接続元 PID が何から起動されたか (IDE / shell / launchd 等) を特定し、
「SSH を連続送信しているのは何か」を確定する。

### コマンド

```bash
# <pid> は観測 1 で記録した接続元 PID に差し替える
ps -o pid,ppid,start,command -p <pid>

# 親プロセスを遡る (ppid を順に引く)
ppid=$(ps -o ppid= -p <pid> | tr -d ' ')
ps -o pid,ppid,start,command -p "$ppid"
```

複数の PID が並走している場合:

```bash
# 観測 1 で記録した PID を複数まとめて確認
ps -o pid,ppid,start,user,command -p <pid1>,<pid2>,<pid3>
```

### 判定: 接続頻度の推定

```bash
# 短時間 (10 秒) に何回接続してくるかを lsof で数える
count=0
for i in $(seq 1 10); do
  n=$(lsof ~/.ssh/agent-kawaz.sock.cw 2>/dev/null | grep -c "^")
  count=$((count + n))
  sleep 1
done
echo "10 秒間の観測行計: $count"
```

### 期待結果

| 接続元 | 対処方針 |
|---|---|
| IDE の自動 git fetch / SSH ヘルスチェック | IDE 設定で自動 fetch 頻度を下げる (新 E 案) |
| shell の `ssh` (multiplexer 等) | ControlMaster 設定を見直す |
| 自作スクリプト | スクリプト側に retry limit を入れる |

接続元が判明したら **その情報を issue `docs/issue/2026-06-14-op-refetch-loop.md`
の「要調査」節に追記する** (= E 案実施の根拠になる)。

---

## 5. 隔離 SSH での動作確認 (因果の確証) [操作要]

### 目的

「隔離された SSH が `.cw` socket に接続 → SIGN_REQUEST → op fetch → TouchID」という
経路が確かに成立することを 1 回確認し、接続元 PID と daemon ログの関係を突き合わせる。

この手順は **kawaz の TouchID 操作が必要**。

### 実行前の予告

```bash
say "タッチアイディーの操作をお願いします。これから cache warden の隔離検証を始めます"
```

### 隔離 SSH コマンド

`~/.ssh/config` の `Host *` IdentityAgent が ENV より強いため、`-o IdentityAgent` で
明示指定しないと期待通りの socket を使わない (journal `parity-phase2.md` ハマり所)。
ControlMaster 再利用も排除する。

```bash
ssh -F /dev/null \
    -o IdentityAgent=~/.ssh/agent-kawaz.sock.cw \
    -o IdentitiesOnly=yes \
    -o ControlMaster=no \
    -o ControlPath=none \
    git@github.com 2>&1 | head -5
```

### 観測ポイント

- ターミナル A の `lsof` に `ssh` の行が出ること
- ターミナル B の daemon ログに `op private key fetch failed ...` か fetch 成功ログが出ること
- TouchID プロンプトが出るタイミングとログ出力のタイミングが対応していること

### 期待結果

| kawaz の操作 | 期待される結果 |
|---|---|
| TouchID 承認 | `Hi kawaz! You've successfully authenticated...` が返る |
| TouchID dismiss | `Permission denied (publickey)` / `agent refused operation` |

dismiss した場合、ターミナル B に「ログ A (op fetch 失敗)」が出ることを確認する。
その後、同じコマンドをすぐ再実行して TouchID が**また出る**ことを確認する
(= backoff なし = 現在のループ動作の実証)。

---

## 6. DR-0022 実装後の確認手順 [操作要]

> **前提**: `[daemon].fetch-failure-backoff = "5s"` (または default) が config に入っており、
> DR-0022 実装版の daemon が稼働していること。

### 目的

backoff が機能していることを以下の 3 回連続 SSH で確認する:

| 回 | 操作 | 期待する TouchID | 期待するログ |
|---|---|---|---|
| 1 回目 | SSH 実行 → TouchID dismiss | 出る | `op private key fetch failed ...` |
| 2 回目 (5 秒以内) | SSH 実行 | **出ない** | `... (backoff active until <t>)` |
| (5 秒待機) | — | — | — |
| 3 回目 | SSH 実行 → TouchID 承認 | 再度出る | fetch 成功ログ |

### コマンド

```bash
# 1 回目: 承認しないで dismiss する
say "1回目のタッチアイディーは dismiss してください"
ssh -F /dev/null \
    -o IdentityAgent=~/.ssh/agent-kawaz.sock.cw \
    -o IdentitiesOnly=yes \
    -o ControlMaster=no \
    -o ControlPath=none \
    git@github.com 2>&1 | head -3

echo "--- 2 回目 (すぐ実行) ---"
# 2 回目: backoff 中のはず、TouchID 出ないことを確認
ssh -F /dev/null \
    -o IdentityAgent=~/.ssh/agent-kawaz.sock.cw \
    -o IdentitiesOnly=yes \
    -o ControlMaster=no \
    -o ControlPath=none \
    git@github.com 2>&1 | head -3

echo "--- 5 秒待機 ---"
sleep 5

echo "--- 3 回目 (backoff 解除後) ---"
# 3 回目: backoff 解除、TouchID 再度出る
say "3回目のタッチアイディーを承認してください"
ssh -F /dev/null \
    -o IdentityAgent=~/.ssh/agent-kawaz.sock.cw \
    -o IdentitiesOnly=yes \
    -o ControlMaster=no \
    -o ControlPath=none \
    git@github.com 2>&1 | head -3
```

### 観測ポイント

- 2 回目で daemon ログに `(backoff active until <t>)` が出ること
- 2 回目で TouchID プロンプトが**出ない**こと (= op CLI が呼ばれていない)
- 3 回目で再度 TouchID が出て、承認後に認証成功すること

### fix 確認の判定

| 確認項目 | 期待 | 判定 |
|---|---|---|
| 2 回目で TouchID が出ない | ✅ | backoff 機能 OK |
| 2 回目で `(backoff active until ...)` がログに出る | ✅ | ログ診断 OK |
| 3 回目 (5 秒後) で TouchID が出る | ✅ | backoff 解除 OK |
| 3 回目承認後に SSH 成功 | ✅ | 通常復旧 OK |

---

## 7. 後始末 [観測のみ]

### 補助プロセスの終了

```bash
# ターミナル A (lsof) と ターミナル B (tail) を Ctrl-C で終了
# daemon 自体には触らない
```

### 本番 daemon の確認

```bash
# daemon が引き続き正常稼働していることを確認
launchctl print gui/$(id -u)/com.github.kawaz.cache-warden | grep -E '(state|pid)'
ls -la ~/.ssh/agent-*.sock.cw
```

### 観測結果の記録

診断結果を journal ファイルに記録する:

```bash
# ファイル名は診断実施日に合わせて決める
# 例: docs/journal/2026-06-14-op-refetch-loop-live-diagnosis.md
```

記録すべき内容:
- 観測した接続元 COMMAND / PID / ppid / 起動元
- TouchID 発生回数と daemon ログの対応
- DR-0022 実装前後での比較結果 (実施した場合)
- issue `docs/issue/2026-06-14-op-refetch-loop.md` への追記箇所

---

## 8. 想定 NG パターンと対処

### NG 1: daemon ログが見つからない

**症状**: `tail -F <path>` でファイルが存在しない、または空。

**対処**:

```bash
# launchd の標準出力リダイレクト設定を再確認
plutil -p ~/Library/LaunchAgents/com.github.kawaz.cache-warden.plist 2>/dev/null

# plist に StandardOutPath がない場合、ログは /dev/null 扱い
# cache-warden daemon を起動しているターミナルがあれば、そちらで stderr を見る
```

診断のみの目的なら `cache-warden daemon status` で daemon の健全性だけ確認する。

### NG 2: lsof で .cw socket への接続が見えない

**症状**: lsof が何も返さない、またはデーモン自身の行しか出ない。

**対処**:

```bash
# まず socket が実在するか確認
stat ~/.ssh/agent-kawaz.sock.cw

# socket の所有者と権限を確認
ls -la ~/.ssh/agent-*.sock.cw

# daemon PID が lsof に出るか確認 (daemon 自身は持っているはず)
daemon_pid=$(launchctl print gui/$(id -u)/com.github.kawaz.cache-warden \
  | awk '/pid =/ { print $3 }')
lsof -p "$daemon_pid" | grep sock
```

TouchID が出ていない状態なら接続元の観測機会がないだけ。TouchID が出た瞬間に
新しいターミナルで `lsof ~/.ssh/agent-kawaz.sock.cw` を 1 回だけ実行することで
snapshot を取る方式でも十分。

### NG 3: 隔離 SSH が `-F /dev/null` を忘れて誤陽性

**症状**: 想定外の IdentityAgent が効いて接続先が変わる、または ControlMaster の
既存接続が再利用され認証経路が新規に張られない。

**対処**:

```bash
# ssh -v で実際に使われた IdentityAgent を確認
ssh -F /dev/null \
    -o IdentityAgent=~/.ssh/agent-kawaz.sock.cw \
    -o IdentitiesOnly=yes \
    -o ControlMaster=no \
    -o ControlPath=none \
    -v \
    git@github.com 2>&1 | grep -E '(IdentityAgent|Authentications|debug1: Offering)'
```

`Offering public key:` の行に `.cw` socket 経由の鍵が出ていれば正しい経路。

### NG 4: DR-0022 fix 確認で 2 回目にも TouchID が出た

**症状**: backoff のはずが 2 回目でも op CLI が呼ばれ TouchID が出る。

**考えられる原因**:

- config に `fetch-failure-backoff` が反映されていない (`"0s"` になっているか未設定)
- daemon が旧バイナリのまま (upgrade 後に launchd が古いバイナリを掴んでいる)
- backoff の適用対象 key と SIGN_REQUEST の key が別 item として扱われている

**調査**:

```bash
# config を確認
grep fetch-failure-backoff ~/.config/cache-warden/config.toml

# 稼働中バイナリのバージョンを確認
cache-warden --version
# バイナリパス
daemon_pid=$(launchctl print gui/$(id -u)/com.github.kawaz.cache-warden \
  | awk '/pid =/ { print $3 }')
ls -la /proc/$daemon_pid/exe 2>/dev/null \
  || lsof -p "$daemon_pid" | awk 'NR==2 {print $9}'
```

daemon upgrade が必要な場合は `cache-warden daemon register` で plist を貼り直す
(DR-0019 参照)。

---

## チェックリスト

診断を実施するたびに下記を確認・記録する。

### 事前準備

- [ ] `launchctl print ...` で daemon が `state = running` を確認した
- [ ] `.cw` socket が 3 本 (kawaz / emerada / syun) 存在することを確認した
- [ ] daemon ログの出力先パスを確認した

### 観測 1 (lsof)

- [ ] ターミナル A で `lsof -r 1 <cw-socks>` を起動した
- [ ] TouchID 発生タイミングで接続元 COMMAND / PID を記録した
- [ ] 記録後に Ctrl-C で終了した

### 観測 2 (daemon ログ)

- [ ] ターミナル B で `tail -F <daemon-log>` を起動した
- [ ] ログ A (`op private key fetch failed`) とログ B (`Broken Pipe`) を区別して記録した
- [ ] 記録後に Ctrl-C で終了した

### TouchID 種別判定

- [ ] `config.toml` の `[auth]` 節を確認した
- [ ] `[auth]` 未設定 → TouchID は全て op CLI 由来と判定した / 設定あり → 両方の可能性を記録した

### 接続元追跡

- [ ] `ps -o pid,ppid,start,command -p <pid>` で接続元の親プロセスチェーンを記録した
- [ ] 接続元が何のプロセスか特定した (IDE / shell / script 等)
- [ ] issue `docs/issue/2026-06-14-op-refetch-loop.md` 「要調査」節に追記した

### 隔離 SSH (因果確認)

- [ ] `say` で kawaz に予告した
- [ ] `-F /dev/null -o IdentityAgent=...cw -o ControlMaster=no -o ControlPath=none` を全部つけた
- [ ] TouchID dismiss → ログ A 出現 → 再実行で再度 TouchID という連鎖を確認した

### DR-0022 fix 確認 (実装後のみ)

- [ ] config に `fetch-failure-backoff` が設定されていることを確認した
- [ ] 1 回目: TouchID が出て dismiss した
- [ ] 2 回目 (5 秒以内): TouchID が**出なかった**
- [ ] 2 回目: daemon ログに `(backoff active until ...)` が出た
- [ ] 5 秒待機後、3 回目: TouchID が再度出て承認で SSH 成功した

### 後始末

- [ ] 補助プロセス (lsof / tail) を Ctrl-C で終了した
- [ ] daemon が引き続き `state = running` であることを確認した
- [ ] 診断結果を `docs/journal/YYYY-MM-DD-op-refetch-loop-live-diagnosis.md` に記録した

---

## 関連

- [issue: op-refetch-loop](../issue/2026-06-14-op-refetch-loop.md) — 本 runbook の対象問題
- [DR-0022: fetch 失敗時 backoff](../decisions/DR-0022-fetch-failure-backoff.md) — 修正方針
- [journal §A: 元観測記録](../journal/2026-06-13-handoff-ecdsa-dogfood-stablewhich.md) — TouchID 20 連発の発見起点
- [journal: parity-phase2](../journal/2026-06-12-parity-phase2.md) — ssh 隔離テクニック (`-F /dev/null` / `-o IdentityAgent`) の元記録
- [runbook: parity-verification](./parity-verification.md) — Phase 3 切替手順 (構造参考)
