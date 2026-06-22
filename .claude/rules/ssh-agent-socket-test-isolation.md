# SSH agent socket 試験での socket 強制指定

cache-warden の sshadapter / authsock 経路を試験するときに、**意図した socket
(= `.cw` 等) に SIGN_REQUEST を確実に届ける**ための切替経路の規約。

## 試験前必読 — ファイルは Read ツールで全行読む

ssh / git / agent の挙動が「想定と違う」現象を観測したら、**仮説を立てる前に
関係する設定ファイル群を Read ツールで全行読む**。grep / head / limit / 部分
読みで「節約」しない。何度もハマって context を浪費している。

### 必読 file group (= 全部 Read ツールで全行読む)

| 経路 | file | include 解決 |
|---|---|---|
| ssh / ssh-keygen | `~/.ssh/config` | `Include` directive を辿って先も Read |
| 〃 | `~/.ssh/config` の `Include` 先 (例: `~/.orbstack/ssh/config`) | 〃 |
| git | `~/.config/git/config` | `[include]` / `[includeIf ...]` 先を Read。`includeIf` は **cwd / remote URL マッチ条件付き** なので試験対象 cwd で `git config --list --show-origin` を全行確認 |
| 〃 | `~/.config/git/config.partial/*.gitconfig` (`includeIf` で参照される partial) | 〃 |
| 〃 | `~/.config/git/cache/gitconfig.local` 等の `[include] path = ../../cache/gitconfig.local` の解決先 | 〃 |
| 〃 | system gitconfig (`/opt/homebrew/etc/gitconfig` / `/etc/gitconfig` / nix path) | Read |
| daemon | `~/.config/cache-warden/config.toml` (= 不在なら default 有効) | Read |
| 〃 | `~/Library/LaunchAgents/com.github.kawaz.cache-warden.plist` | Read |

`git config --list --show-origin --show-scope` の出力も head で切らず全行確認
(`cache.partial` の include 解決後の実効値、`includeIf` ヒットの確認のため)。

### env 変数の確認

```bash
echo "SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-(unset)}"
echo "GIT_SSH_COMMAND=${GIT_SSH_COMMAND:-(unset)}"
echo "GIT_SSH=${GIT_SSH:-(unset)}"
```

### 現状 daemon / socket の確認

```bash
ls -la ~/.ssh/agent-*.sock* ~/.local/state/cache-warden/control.sock 2>/dev/null
launchctl print gui/$(id -u)/com.github.kawaz.cache-warden
```

## agent socket 解決の単純なロジック

ssh 系コマンド全部共通の単純な仕組み:

```
Host 引数あり → ssh_config の Host / Match マッチが評価される
              → マッチした block の IdentityAgent が使われる
              → IdentityAgent 指定が無ければ SSH_AUTH_SOCK を見る
              → `-o IdentityAgent=...` 引数があれば全部に勝つ

Host 引数なし → ssh_config の Host/Match マッチが起きようがない
              → SSH_AUTH_SOCK を見るしかない
```

= 「config が強い / env が強い」じゃなく、**Host マッチが成立するかどうか
だけ** で決まる単純な一本経路。

### コマンド別の Host 引数有無 (= 2026-06-22 実機検証)

| コマンド | Host 引数 | ssh_config Host/Match マッチ | 実効 socket 解決 |
|---|---|---|---|
| `ssh <host>` | あり | する (= `Host *` でも全 host マッチ) | ssh_config > `-o` > SSH_AUTH_SOCK |
| `scp` / `sftp` | あり (内部で ssh 使う) | する | 同上 |
| `git push/fetch` (ssh transport) | あり (= remote の host) | する | `core.sshCommand` / `GIT_SSH_COMMAND` で ssh 起動コマンド自体を上書きしない限り ssh と同じ |
| `ssh-add` | なし | しない (Host 概念なし) | SSH_AUTH_SOCK |
| `ssh-keygen -Y sign` | なし (= signing は host 関係ない) | しない | SSH_AUTH_SOCK |
| `ssh-keygen -Y verify` | n/a (agent 不要) | n/a | n/a |

### 実機検証ログ (2026-06-22)

```bash
# 1. ssh-keygen -Y sign は SSH_AUTH_SOCK を読む (= /nonexistent で fail)
$ SSH_AUTH_SOCK=/tmp/nonexistent.sock ssh-keygen -Y sign -f key.pub -n ns data
No private key found for public key "key.pub"
# exit 0 (= agent 接続失敗 → file 探索 → private key 無い)

# 2. .cw socket 不在 + SSH_AUTH_SOCK=.cw でも fail (= SSH_AUTH_SOCK 経路を見てる)
$ ls ~/.ssh/agent-kawaz.sock.cw   # 不在
$ SSH_AUTH_SOCK=$HOME/.ssh/agent-kawaz.sock.cw ssh-keygen -Y sign -f key.pub -n ns data
No private key found for public key "key.pub"
# exit 255

# 3. ssh -G は ssh_config の Host * を引く (= SSH_AUTH_SOCK は弱い)
$ SSH_AUTH_SOCK=/tmp/probe.sock ssh -G git@nohost.invalid | grep identityagent
identityagent /Users/kawaz/.ssh/agent-kawaz.sock
# = SSH_AUTH_SOCK env 関係なく ssh_config の Host * が勝つ
```

### git の ssh 起動コマンド優先順位 (= 2026-06-22 実機検証)

```
1. GIT_SSH_COMMAND 環境変数 (= 引数込みで指定可能)
2. core.sshCommand (config)
3. GIT_SSH 環境変数 (= 実行ファイルパスのみ、引数渡せない)
4. system PATH の ssh
```

検証:

```bash
$ GIT_SSH_COMMAND="echo WINNER=GIT_SSH_COMMAND" \
    git -c core.sshCommand="echo WINNER=core.sshCommand" \
    ls-remote ssh://nohost.invalid/x
fatal: protocol error: bad line length character: WINN
# stderr / 後続の grep で出力先を確認 → "WINNER=GIT_SSH_COMMAND" が echo された
# = GIT_SSH_COMMAND 勝ち
```

## socket 強制指定の正解パターン

### cache-warden の `.cw` socket に SIGN_REQUEST を直接投げる (= 推奨)

```bash
# 1. .cw socket から pubkey を引く (ssh-add は SSH_AUTH_SOCK を読む)
SSH_AUTH_SOCK=$HOME/.ssh/agent-kawaz.sock.cw ssh-add -L > /tmp/cw-test.pub

# 2. 1 鍵だけ抜き出し (-T は単一 pubfile を期待)
head -1 /tmp/cw-test.pub > /tmp/cw-test-key1.pub

# 3. agent に sign challenge を投げる (Host 引数なし = ssh_config 引かれない)
SSH_AUTH_SOCK=$HOME/.ssh/agent-kawaz.sock.cw ssh-add -T /tmp/cw-test-key1.pub
```

`ssh-add -T` は agent に対し「この pubkey に対応する private key で challenge
を sign してみろ」と要求し、返ってきた sig を verify する。

### ssh-keygen -Y sign で `.cw` socket 経由 sign (実機検証 OK)

```bash
SSH_AUTH_SOCK=$HOME/.ssh/agent-kawaz.sock.cw ssh-keygen -Y sign \
  -f /tmp/cw-test-key1.pub -n test-ns /tmp/data
```

ssh-keygen -Y sign は Host 引数を取らないので ssh_config の Host/Match マッチが
起きず、SSH_AUTH_SOCK がそのまま効く。

### 隔離 ssh 接続経由で SIGN_REQUEST を発火する場合

接続経路 (= handshake / kex) を試験する場合、ssh_config を `-F /dev/null` で
完全無効化 + `-o IdentityAgent` で明示:

```bash
ssh -F /dev/null \
    -o IdentityAgent=$HOME/.ssh/agent-kawaz.sock.cw \
    -o IdentitiesOnly=yes \
    -o ControlMaster=no \
    -o ControlPath=none \
    -o BatchMode=yes \
    git@github.com
```

注: `.cw` の鍵が接続先 (= github 等) に登録されていないと `Permission denied
(publickey)` で **SIGN まで届かず終了** する。SIGN 発火を確実にするには
`ssh-add -T` か `ssh-keygen -Y sign` 経路が確実。

### git 経由 (= push / fetch / clone) で socket 強制

`core.sshCommand` / `GIT_SSH_COMMAND` を全層で確認した上で、上書きするか
明示する:

```bash
# 1 回限り override
GIT_SSH_COMMAND="ssh -F /dev/null -o IdentityAgent=$HOME/.ssh/agent-kawaz.sock.cw -o IdentitiesOnly=yes" \
  git fetch origin

# 1 コマンド限り (config 経由)
git -c core.sshCommand="ssh -F /dev/null -o IdentityAgent=..." fetch origin
```

## NG パターン

### ssh コマンドでの SSH_AUTH_SOCK 単独指定

```bash
# NG: ssh_config の Host * IdentityAgent が勝つ
SSH_AUTH_SOCK=$HOME/.ssh/agent-kawaz.sock.cw \
  ssh -o ControlMaster=no -o ControlPath=none git@github.com
# → 実際は ~/.ssh/agent-kawaz.sock (= .aw symlink) に行く
```

`-F /dev/null` + `-o IdentityAgent=...` の組合せが必要。

### `git config --get core.sshCommand` 単発確認

```bash
# NG: includeIf 適用前の値しか取れない
git config --global --get core.sshCommand
```

```bash
# OK: 試験対象 cwd で全 source 表示 (= includeIf 解決済み実効値)
git -C <試験対象 cwd> config --list --show-origin --show-scope
# (head なしで全行確認)
```

### ssh_config を grep で部分確認

```bash
# NG: include 先や Match exec の条件を見落とす
grep -E '^Host |IdentityAgent' ~/.ssh/config
```

`Include` directive と include 先、`Match exec` の判定条件 (= cwd / git remote)
は文字列マッチで漏れる。`Read` ツールで全行読み + `Include` 先も再帰的に
Read。

## TouchID 発火の grand truth = `coreauthd` ログ

「TouchID 出た / 出ない / dismiss / approve」を体感やタイムラグで判定しない。
macOS の `coreauthd` (= LocalAuthentication framework の server) が **biometric
認証要求のたびにログを出す**。これが grand truth。

### 定型コマンド (= 思考不要)

```bash
# 1. 過去 N 分の biometric request 一覧 (= TouchID 発火履歴)
/usr/bin/log show \
  --predicate 'process == "coreauthd" AND eventMessage CONTAINS "DeviceOwnerAuthenticationWithBiometrics"' \
  --info --last 5m

# 2. リアルタイム監視 (= 試験中に Monitor ツールで張る)
/usr/bin/log stream \
  --predicate 'process == "coreauthd" AND eventMessage CONTAINS "DeviceOwnerAuthenticationWithBiometrics"' \
  --style syslog
```

注: zsh の組込み `log` と衝突するので **`/usr/bin/log` で絶対パス指定**。

### 出力解釈 (2026-06-22 実機学習)

1Password app (PID = `1Password` プロセス) は **1 回の op operation で 10+ 個の
`evaluatePolicy` ログを出す**。多数は内部評価 (= `uiDelegate:0` + `User
interaction is required.` で即終了) で、**実際に画面に TouchID が出るのは特定
の 1 セットだけ**。混同しないこと。

#### 「TouchID UI が実際に画面に出た」判定 (= 3 要素揃う)

```
coreauthd: [com.apple.LocalAuthentication:Server,Interactive,Biometry] evaluatePolicy:1 options:{...} uiDelegate:1 ... rid:NNN
coreauthd: (MechanismBase) [com.apple.LocalAuthentication:Server,Interactive,Biometry] MechanismTouchId[NNN] starting
coreauthd: (MechTouchId) [com.apple.LocalAuthentication:Server,Interactive,Biometry] MechanismTouchId[NNN](run) will start matching user 501
```

判定 key:
- `Interactive,Biometry` (= UI 表示 path)
- `uiDelegate:1` (= UI delegate あり)
- `MechanismTouchId[N] starting` (= biometric mechanism が起動)
- `will start matching user` (= 指紋待ちに入った)

#### dismiss / cancel 判定

```
coreauthd: (ModuleBase) [com.apple.LocalAuthentication:AuthenticationManager] canceling running authentication: <AuthenticationInProgress: ... pid:NNNNN, started: ... mechanism: MechanismTouchId[NNN](run)
coreauthd: [com.apple.LocalAuthentication:Server,Interactive,Biometry] evaluatePolicy rid:NNN returned Error Domain=com.apple.LocalAuthentication Code=-9 "Invalidated by client." UserInfo={... NSLocalizedDescription=認証はキャンセルされました。}
coreauthd: (MechanismBase) [com.apple.LocalAuthentication:Server,Interactive,Biometry] MechanismTouchId[NNN](run) has finished with Error Domain=com.apple.LocalAuthentication Code=-9 "Invalidated by client."
```

判定 key: `LAError Code=-9 "Invalidated by client."` (= ユーザが「キャンセル」
押した or app/CLI 側 timeout)

#### approve / success 判定 (= 確定指標)

```
coreauthd: (MechTouchId) [...] MechanismTouchId[NNN](run)(par:NNN) has received finger-on from <BKMatchTouchIDOperation: ...>
coreauthd: (MechTouchId) [...] MechanismTouchId[NNN](run)(par:NNN) has received finger-off from <BKMatchTouchIDOperation: ...>
coreauthd: (MechTouchId) [...] MechanismTouchId[NNN](run)(par:NNN) has matched by <private> (unlocked:0, credential:1, resultIgnored:0)
coreauthd: (MechanismBase) [...] MechanismTouchId[NNN](run)(par:NNN) has finished with { 14 = 1; 7 = ...; 1 = 1; 8 = 501; }
```

判定 key:
- `has received finger-on` / `finger-off` = ユーザが指を置いた / 離した
- **`has matched by <private>` = 指紋マッチ成功 (= 決定的 success 指標)**
- `has finished with { ... }` (= 結果 dictionary 付き finish) = success
- 比較対象: cancel は `has finished with Error ... Code=-9`

#### timeout 判定 (= 放置による失敗)

```
# 約 60s 後 (放置時間が op CLI の timeout に達する)
coreauthd: (ModuleBase) [...] canceling running authentication: <AuthenticationInProgress: ... started: <60s 前>...>
coreauthd: (MechanismBase) [...] MechanismTouchId[NNN](run) has finished with Error Domain=com.apple.LocalAuthentication Code=-9 "Invalidated by client." UserInfo={... NSLocalizedDescription=認証はキャンセルされました。}
```

**timeout も cancel と同じ `Code=-9 "Invalidated by client"` ログを出す** (=
coreauthd 視点では区別できない)。判別したければ:

- **op CLI 側のエラーメッセージ** (= 一次情報):
  - dismiss → `[ERROR] authorization prompt dismissed, please try again`
  - timeout → `[ERROR] authorization timeout`
- **elapsed time** (= 試験中の経験則):
  - dismiss → 即時 (数秒以内)
  - timeout → 約 60s 経過後

途中で `pause` ログ (`Dropping Touch ID assertion because MechanismTouchId[NNN]
is being paused`) が出ることがあるが、これは別の `evaluatePolicy` が並行で
発火したときの内部処理 (= 一時 pause)。final な「dismiss / timeout」判定とは
別事象。

### 試験中の biometric event の出処区別

`coreauthd` ログには **1Password の PID (= 31069 等) しか出ない** (= 真の
呼出元 cache-warden / op CLI / 別アプリは区別できない)。試験中は kawaz が
別経路 (= 直接 `op item list` 等) を叩かないこと、または elapsed time で
区別すること。

#### TouchID が出なかった (= backoff / cache hit) 判定

「UI 表示の 3 要素」が **一切出ない** = TouchID は画面に出ていない。`evaluatePolicy:1`
が出ても `uiDelegate:0` + `Code=-1004 "User interaction is required."` で
終わる場合は **内部評価のみで UI 表示なし**。混同しないこと。

#### より絞り込んだ filter (= noise 減らす)

```bash
# UI 表示 + 結果のみ拾う
/usr/bin/log stream --predicate '
  process == "coreauthd" AND (
    (eventMessage CONTAINS "Interactive,Biometry" AND eventMessage CONTAINS "starting") OR
    eventMessage CONTAINS "will start matching" OR
    eventMessage CONTAINS "Invalidated by client" OR
    eventMessage CONTAINS "has finished with Error" OR
    eventMessage CONTAINS "Succeeded"
  )' --style syslog
```

### 試験テンプレ

```bash
# A. 試験前に過去ログをチェックポイントとして取る
echo "=== checkpoint: $(date +%H:%M:%S) ==="

# B. Monitor で log stream を張る (= リアルタイム TouchID 観測)
#   Monitor ツールで:
#   /usr/bin/log stream --predicate 'process == "coreauthd" AND eventMessage CONTAINS "DeviceOwnerAuthenticationWithBiometrics"' --style syslog

# C. 試験コマンド実行
SSH_AUTH_SOCK=$HOME/.ssh/agent-kawaz.sock.cw ssh-keygen -Y sign -f /tmp/key.pub -n test /tmp/data

# D. Monitor からの通知行数 = TouchID 発火回数
```

## ハマり所の典型 (= biometric session 混同)

cache-warden の op fetch が「TouchID 出ない / 0 秒 sign 成功」と観測されたら、
socket 経路 (= 上記) が正しいことを確認した上で、次のレイヤを切り分け:

- **1Password biometric session キャッシュ**: 直前に別プロセス (`op item list`
  等) で TouchID 通していれば、cache-warden 経由でも一定時間は biometric が
  skip される。完全 reset には **1Password Lock** (Cmd+Option+L) が必要
- **cache-warden memory cache**: 一度 op fetch 成功した op key は daemon
  プロセス内に保持される (`Store::entries` には載らないが別管理)。daemon 再起動で reset
- **op CLI 自体の session token**: `op signin` の session token が残ってる
  可能性。`unset OP_SESSION_*` で env から落とす

= 「TouchID 出ない」を即「socket が違う」と決めつけず、biometric session /
memory cache を順に潰す。

## 関連

- DR-0009 (control socket protocol)
- DR-0022 (fetch failure backoff) — 検証時にこの罠を踏み回って context を浪費した (2026-06-22)
- `docs/runbooks/op-refetch-loop-live-diagnosis.md` — 隔離 SSH 手順 (= ssh 接続経路)
- `.claude/rules/daemon-notarized-binary.md` — daemon を fg 起動する場合の前提
