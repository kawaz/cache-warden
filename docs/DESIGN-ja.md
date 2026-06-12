# cache-warden 設計

> [English](./DESIGN.md) | 日本語

## ドメイン

### 解こうとしている問題

秘密値（API トークン、DB パスワード、SSH 鍵など）の取り扱いには、相反する二つの要求がある:

- **安全に保ちたい**: メモリ上で保護し（mlock / zeroize）、取得元はセキュアな経路
  （1Password / op CLI など）を通したい。
- **速く使いたい**: op CLI は item あたり 0.5〜1 秒かかり、毎回叩くと体感が悪い。一方で
  環境変数に平文で置くと `/proc/PID/environ` などから漏れる。

この緊張を解くのが、**TTL 付きの秘密値キャッシュ + プロセス認証 + 再認証（TouchID 等）** の
組み合わせである。「速くてセキュアで、TTL が切れたら生体認証で延長する」キャッシュを提供する。

SSH 鍵もまた「キャッシュされる秘密値の一種」であり、SSH agent protocol はそのコアの上に乗る
一つのプロトコルアダプタにすぎない、と捉え直せる。cache-warden はこの捉え直しを製品構造に
反映する（背景の構想は authsock-warden リポ `docs/decisions/DR-018-kv-cache-warden.md` を継承。
本リポはその「別プロジェクト化」の実現にあたる。DR-0003）。

### 扱う概念

- **キャッシュエントリ**: 名前付き（KEY）の秘密値。value ソースと TTL、保護状態を持つ。
- **value ソース**: 値の供給元。二種類:
  - `static`: `set` 時に直接与えられた値（パイプ / 引数）。hard TTL 切れ後は再取得不可（再 set が必要）。
  - `command`: 上流コマンド（例 `op read ...`）の実行結果。`define` で定義を登録し、初回 get で lazy に実行して生成する。
    hard TTL 切れ後はコマンド再実行で再生成できる。
- **soft TTL / hard TTL**: 二段階のライフサイクル。soft と hard は **別々の基準点**から測る（DR-0011）。
  - **soft TTL 切れ**: 上流に取りに行かず、ユーザを再認証（TouchID 等）してキャッシュを延長する。
    基準は `extended_at`（最後の extend 時刻）。使うたびに延命される（idle extend）。
  - **hard TTL 切れ**: メモリから zeroize して破棄する。`command` 型は再取得、`static` 型はエラー。
    基準は `loaded_at`（set / regenerate 時刻に固定）。extend では動かないので **値の絶対寿命**であり、
    使い続けても元のスケジュールで必ず破棄される。
- **pin**: hard / soft の失効判定を指定期限まで明示的に抑止する手動操作（DR-0011）。「夜中に hard が
  来るが、これから 8 時間は止めたくない」用途。**再認証必須**（Active からでも要求、extend と非対称）。
  期限が来たら通常判定に戻り、本来の hard を過ぎていれば即破棄。`unpin` で解除（認証不要）。
- **プロセス認証**: 要求元プロセスをプロセスツリー遡上で検証し、誰が値を取れるかを制御する。
- **再認証**: soft TTL 切れ時 / pin 時のユーザ認証手段（TouchID / LocalAuthentication など）。
- **アダプタ**: コアの上に載るプロトコル境界。SSH 鍵を扱う authsock アダプタ、KV を直接扱う
  KV アダプタ（CLI / socket API）など。

### 主なユースケース

```bash
# command ソース: valuesource 付きキーを定義（登録のみ、upstream は実行しない・冪等）
# --command は以降全部を argv として取るので最後に置く
cache-warden kv define DB_PASSWORD --soft-ttl 1h --hard-ttl 24h --command op read 'op://vault/item/password'

# 初回 get で初めて upstream を実行してキャッシュ投入（以降はヒットで数 ms、soft TTL 切れは再認証で延長）
cache-warden kv get DB_PASSWORD

# static ソース: その場の値をキャッシュ (VALUE は位置引数、省略時は stdin から読む。
# 秘密値は argv に乗ると ps / shell history に残るので pipe 推奨)
cat cert.pem | cache-warden kv set TEMP_CERT --soft-ttl 8h

# run: env 中の cache-warden://KEY 参照を実値に解決して子コマンドを exec
DB_PASSWORD='cache-warden://DB_PASSWORD' cache-warden run -- ./migrate

# inject: テンプレート中の参照を実値に展開（--dry-run なら配線だけ検証、値は出ない）
cache-warden inject --in config.tmpl --out config.toml
```

> 上記の CLI 表記はドメインを説明するためのイメージであり、サブコマンド体系の正式仕様ではない
> （control socket プロトコル設計とセットで確定する。下記 open question 参照）。

## アーキテクチャ

### レイヤ構造（コア KV ↔ アダプタ群）

```
cache-warden コア（セキュア KV キャッシュ）
  ├─ TTL 管理（soft / hard の二段階ライフサイクル）
  ├─ プロセス認証（プロセスツリー遡上）
  ├─ 再認証（TouchID 等）
  └─ メモリ保護（mlock / zeroize / anti-debug）
        ▲
        │ コア上に載る
        │
  プロトコルアダプタ群
  ├─ authsock アダプタ（SSH agent protocol / 鍵フィルタ / ポリシー / 1Password 署名 / 鍵ライフサイクル）
  └─ KV アダプタ（KV CLI、将来 KV socket API）
```

- 秘密値ドメインの基盤（TTL / プロセス認証 / 再認証 / メモリ保護）は**コアに集約**し、複数アダプタで共有する。
- SSH 鍵管理は「SSH 鍵という秘密値の種別」を扱う**アダプタ**として位置づける。
- **ソケットは cache-warden 自身（サーバ側）が作る**。外部プログラムが作ったソケットに後から
  関与するのではなく、cache-warden がエンドポイントを提供する。

### デーモン構成（単一プロセス直担型、DR-0008）

`cache-warden daemon run` は 1 プロセス（tokio ランタイム）であり、全アダプタを同一プロセス内で直接担う。

```
cache-warden daemon run（単一プロセス / tokio ランタイム）
  ├─ コア（secret / clock / source / entry / store / auth / process）を中心に配線
  ├─ listener task: authsock アダプタ（SSH agent socket）
  ├─ listener task: KV アダプタ
  └─ listener task: control socket（管理 CLI ↔ デーモン）
```

- **全アダプタは同一プロセス内の listener task として直担**し、サブプロセスに分割しない。
  決定打は**秘密値の 1 プロセス閉じ込め**で、子プロセス化すると秘密値が IPC を渡り、
  mlock / zeroize / プロセス認証の保護境界がプロセス間に分散して壊れる。in-process なら
  コアのメモリ保護がそのまま全アダプタに効く。
- **管理 CLI ↔ デーモンは control socket（Unix domain socket）経由**。`kv get / set / del` /
  `status` / `refresh` 等の管理系はこのソケットで通信する。KV を他プロセスからプログラマティックに
  叩く経路（KV socket API）も同じプロトコルに統合する。プロトコル詳細は DR-0009 で確定済み
  （下記「control socket プロトコル v1」節）。
- **コアをデーモンの中心に配線する**。コア（実装済み）を run 経路の中心に置き、アダプタはその上に
  薄く乗せる。
- **サービス登録（launchd / systemd）は単一バイナリ + `daemon run` 引数**で行う（将来は
  `daemon register` / `daemon unregister` でラップ）。
- **同期処理（op CLI 呼び出し等）は `spawn_blocking` で隔離**する。
- **起動時ハードニング（プロセス全体保護、port plan §3 判断 5）**: 秘密値が Store に入る前に
  2 段の防御を適用する。(a) **コアダンプ抑制**（`RLIMIT_CORE=0`）でクラッシュ時の秘密値ディスク
  流出を防ぎ、(b) **デバッガアタッチ拒否**（macOS は `ptrace(PT_DENY_ATTACH)`、Linux は
  `prctl(PR_SET_DUMPABLE, 0)`。コアダンプは (a) で別途抑止済みなので dumpable=0 は「非特権
  `PTRACE_ATTACH` を EPERM 拒否 + `/proc/<pid>/mem` 所有者を root 化」という attach 防御目的で使う）で
  稼働中プロセスのメモリ読み取りを塞ぐ。両者とも **fail-open**（失敗は警告 1 行で続行、DR-0007 の
  mlock と同方針）。(b) は `[daemon].allow-debug-attach = true` で **opt-out 可能**（開発・プロファイル
  用途）だが、無効化時は stderr に警告 1 行を出し、静かに弱体化しない。

### control socket プロトコル v1（DR-0009）

管理 CLI ↔ デーモンの通信プロトコル。詳細・代替案は
[DR-0009](./decisions/DR-0009-control-socket-protocol-v1.md)。

- **transport**: Unix domain socket。デフォルトパス
  `$XDG_STATE_HOME/cache-warden/control.sock`（未設定時 `~/.local/state/...`）。
  パーミッション 0600。起動時に既存 socket へ connect 試験 → 成功なら二重起動として
  `AddrInUse` でエラー終了、失敗なら stale として除去して bind。
- **framing**: JSON Lines（リクエスト 1 行 / レスポンス 1 行）。`nc` / `socat` で手で
  叩けるデバッグ容易性を優先。
- **値のエンコーディング**: 秘密値はバイナリ安全のため base64（`value_b64` のように
  `_b64` サフィックスで明示）。エラーメッセージには秘密値を含めない。
- **コマンド v1**: `ping` / `status`（デーモン情報 + エントリ一覧。**値は含めない**。「定義のみ（値未生成）」のキーも列挙し defined / has_value / state を区別。pin 中は残り秒を併記）/
  `kv.define`（key + source `{command: argv} | {uri}` + soft/hard TTL 秒。valuesource 付きキーの定義を登録するのみで upstream は実行しない。完全一致 no-op / 不一致 `bad_request`。DR-0014）/
  `kv.set`（**static 専用** = `value_b64`、soft/hard TTL 秒）/
  `kv.get`（値不在 or HardExpired でも定義があれば lazy 生成。SoftExpired は再認証で延長、HardExpired + regenerable は再生成して値を返す。`dry_run: true` 指定時は通常の取得経路（lazy 生成・extend・regenerate・認証）を完走した上で応答に `value_b64` を**含めず**成功/失敗と状態のみ返す＝値はデーモンから出ない。DR-0015）/
  `kv.del`（値のみ破棄して定義は残す＝次の get で再生成。`with_define: true` で定義ごと削除）/ `kv.list`（定義のみのキーも列挙）/
  `kv.pin`（key + duration 秒。期限まで失効抑止、再認証必須。DR-0011）/
  `kv.unpin`（key。pin 解除、認証不要）。
  レスポンスは `{"ok":true,...}` / `{"ok":false,"error":{"kind":...,"message":...}}`。
- **peer 認証**: 接続ごとに LOCAL_PEERPID（macOS）/ SO_PEERCRED（Linux）で peer pid を
  取得し、`SystemInspector::ancestry` で祖先チェーンを得て Store の auth ゲートに
  requester として渡す。UDS 0600 + 同一 uid が第一防壁、ancestry は監査・将来ポリシーの
  材料（**ポリシー判定はまだしない**）。
- **再認証**: config 由来（DR-0010）。`[auth].command` 設定時は `CommandAuthenticator`
  （外部コマンドに委譲、exit 0 = 承認）、未設定時は `AllowAll`。ビルトイン TouchID は将来
  iteration（同じ `Authenticator` trait の別実装として差し込む）。

CLI サブコマンド体系 v1: `daemon run` / `ping` / `status` /
`kv define|set|get|del|list|pin|unpin` / `run` / `inject` / `config show|path|edit`（引数なしは help、ロングオプション）。
`kv get` / `run` / `inject` の 3 動詞は `--dry-run` / `--reveal` を持つ（デフォルトは実値 reveal、`--dry-run` は
マスク値で配線検証して値を出さない。極性は config / 環境変数で切替可、DR-0015。`run` / `inject` の詳細は
「secret reference 注入（run / inject / dry-run）」節）。
`kv define KEY (--command ARGV... | --source URI) [--soft-ttl D] [--hard-ttl D]` は valuesource 付きキーの
定義登録（upstream は実行せず初回 get まで遅延、冪等＝完全一致 no-op / 不一致エラー）。`--source URI` は
op:// URI を `["op","read","<URI>"]` へ展開する糖衣（op:// 以外はエラー）。`kv set KEY` は static 専用
（command ソースは `kv define` で登録する）。`kv get KEY` は値不在 / HardExpired でも定義があれば lazy 生成する。
`kv del KEY` は値のみ破棄（定義は残り次の get で再生成）、`kv del KEY --with-define` で定義ごと削除。
`kv pin <KEY> <DURATION>` は TTL を無視して値を期限まで Active 保持（再認証必須）、`kv unpin <KEY>` は解除。

- **`daemon` グループ**: デーモンのライフサイクル操作を隔離する。`daemon run`（フォアグラウンド起動）
  のみ実装済み。`daemon register` / `daemon unregister`（launchd/systemd サービス登録）/
  `daemon status`（プロセス・登録状態）は将来実装で、未実装のうちはグループ help に出さない。
  トップレベルに `run` を出さないのは、`kv get` 等を日常的に叩くクライアントとして使う中で、
  デーモン起動コマンドを誤操作（意図しない二重起動）する事故を避けるため。
- **`status` の対比**: トップレベル `status` = キャッシュエントリ一覧（ユーザ向け、値は含めない）。
  将来の `daemon status` = プロセス・サービス登録状態（運用向け）。同じ語で関心が違うので分ける。
- **トップレベル `run` / `inject`**: トップレベル `run` は op run 相当（秘密値を env 注入して
  子コマンドを exec）、`inject` は op inject 相当（テンプレート中の `cache-warden://KEY` 参照を実値に展開）。
  どちらも control socket クライアントとして実装済み（詳細は「secret reference 注入（run / inject / dry-run）」節、
  DR-0013 / DR-0015）。

### 設定（TOML config・再認証コマンド、DR-0010）

デーモンの設定は TOML（`#[serde(deny_unknown_fields)]`）。config 無しでも全デフォルトで
起動する。探索順（高優先順位が先）: `$CACHE_WARDEN_CONFIG` → `$XDG_CONFIG_HOME/cache-warden/config.toml`
→ `~/.config/cache-warden/config.toml`。詳細・代替案は [DR-0010](./decisions/DR-0010-config-and-reauth-command.md)。

```toml
[daemon]
socket = "~/.local/state/cache-warden/control.sock"  # CLI --socket > [daemon].socket > デフォルト

[cli]
default-mode = "reveal"               # "reveal"（既定・実値）| "dry-run"（マスク検証）。DR-0015

[auth]
command = ["/path/to/reauth-prompt"]  # 省略時は AllowAll（再認証なし）

[kv.DB_PASSWORD]                       # 起動時は定義登録のみ（command ソースのみ）、実行は初回 get まで lazy
command = ["op", "read", "op://vault/item/password"]
soft-ttl = "1h"
hard-ttl = "24h"

[kv.SLOW_SECRET]                       # preload = true で起動時に eager 実行してキャッシュ投入
command = ["op", "read", "op://vault/item/slow"]
soft-ttl = "1h"
hard-ttl = "24h"
preload = true
```

- **再認証コマンド**: `CommandAuthenticator`（ライブラリ）が `[auth].command` の argv を実行し、
  exit 0 = 承認 / 非ゼロ = 拒否 / spawn 失敗 = 利用不能。`AuthContext` の情報（key・operation・
  requester チェーン）を環境変数で渡すが**秘密値は渡さない**。timeout なし（ユーザ入力待ちが正常系）。
- **起動時は定義登録、preload は opt-in（DR-0014）**: `[kv.*]` は起動時に**定義登録のみ**行い、upstream の
  実行は初回 get まで遅延する（デフォルト lazy）。起動時に eager 実行してキャッシュ投入する挙動は
  `preload = true` で opt-in する。preload エントリの実行が失敗しても fatal でなく、stderr に 1 行警告（値なし）を出して
  定義は登録したまま起動継続する。**例外: `[authsock.sockets.*].keys` に参照されている鍵は preload フラグに
  関わらず自動で eager 実体化する**（socket 宣言が「起動時に公開鍵が要る」という意思表示なので、`preload = true`
  を二重に書く必要はない）。
- **static を config に書けない**: `[kv.*]` は command ソースのみ。リテラル値（`value` 等）を
  書くと設定エラー（平文秘密値が config に残る漏洩を構造的に防ぐ）。リテラル値は実行時に
  pipe で投入する（`... | cache-warden kv set KEY`）。
- **`[cli].default-mode`（DR-0015）**: `kv get` / `run` / `inject` のデフォルト極性を
  `"reveal"`（実値・既定）/ `"dry-run"`（マスク検証）から選ぶ。優先順位は
  `--reveal` / `--dry-run` フラグ > 環境変数 `CACHE_WARDEN_DRY_RUN`（`=1` で dry-run）>
  `[cli].default-mode` > ビルトイン既定（reveal）。AI エージェント環境にだけ
  `CACHE_WARDEN_DRY_RUN=1` を仕込めば「エージェントはデフォルト dry-run、人間は素のまま」を
  1 つの仕組みで実現できる。

### authsock アダプタ（SSH agent socket、port plan Iteration 1–4）

cache-warden は config で宣言した SSH agent socket を自ら listen し、KV にキャッシュした
秘密鍵 PEM で SSH クライアントの署名要求に応える。`SSH_AUTH_SOCK` をこの socket に向けた
クライアント（`ssh` / `ssh-add` / git 等）から見ると、通常の SSH agent として振る舞う。

```toml
[kv.GITHUB_KEY]                              # 秘密鍵 PEM の command 定義（preload 不要）
command = ["op", "read", "op://vault/github/private_key"]
soft-ttl = "1h"
hard-ttl = "24h"
allowed_processes = ["ssh"]                  # 鍵単位のプロセス制限（key 層、config 専用、空=制限なし、省略可）

[authsock.github]                            # github= フィルタ共通設定（省略可）
cache_ttl = "1h"                             # 取得した鍵リストの再取得間隔（既定 1h）
timeout = "10s"                              # 1 回の取得タイムアウト（curl --max-time、既定 10s）

[authsock.sockets.default]
path = "~/.ssh/cache-warden.sock"            # agent socket（leading ~/ 展開）
keys = ["GITHUB_KEY"]                        # ローカル署名する KV キー名のリスト
upstreams = ["~/.1password/agent.sock"]      # 鍵をマージし署名を転送する上流 agent（省略可）
filters = ["github=kawaz"]                   # 見せる/署名する鍵を絞る（github= は公開鍵リスト照合、省略可）
allowed_processes = ["ssh"]                  # この socket を使えるプロセス（実行ファイル basename、空=制限なし、省略可）
```

- **socket は cache-warden が作る**: `[authsock.sockets.NAME]` ごとに listener task を 1 本
  起動（DR-0008 単一プロセス）。control socket と同じ 0600 / stale 復旧 / 二重起動拒否 /
  shutdown 共有。`SSH_AUTH_SOCK=<path>` でクライアントが接続する。
- **公開鍵レジストリ**: 起動時に `keys` の各 KV キーの PEM から公開鍵を一度導出してレジストリに
  保持する。REQUEST_IDENTITIES（`ssh-add -l`）はこのレジストリから応答し、**秘密値に触れない**。
  公開鍵は常に列挙でき、秘密値の在否は完全にコアの TTL 状態に委ねられる（warden の NotLoaded を
  アダプタ側で吸収、DR-0004）。`keys` で参照される KV キーは（DR-0014 で `[kv.*]` が lazy デフォルトに
  なった後も）公開鍵導出のため起動時に**自動で eager 実体化**されるので、`preload = true` を別途書く必要はない。
- **署名**: SIGN_REQUEST が来ると、key_blob からコアの KV キーを引き、**control socket と同じ
  認証ゲート**で秘密値を取得する（SoftExpired は再認証して extend、command 型の HardExpired は
  再生成、peer pid → 祖先チェーンを requester として渡す）。取得した PEM を `expose_secret()` で
  短命に借りてプロセス内で署名し、**成功時は extend で idle 延命**する（使い続ける鍵は再認証なしで
  生き続ける、DR-0011）。
- **upstream agent の転送（Iteration 2）**: socket は `upstreams` に別の agent socket（1Password
  agent、システム ssh-agent 等）を列挙できる。その鍵は秘密素材を持てないので**署名を転送**する。
  REQUEST_IDENTITIES は KV 鍵 + 各 upstream の鍵をマージして応答し、blob 重複は **KV 優先**で dedup。
  落ちている upstream はスキップして残りで応答する（stderr に 1 行警告 = graceful degradation）。
  SIGN_REQUEST は、KV 鍵ならローカル署名、upstream 鍵なら「列挙時にその blob を出した upstream」へ転送
  （記録が無ければ全 upstream を順次試行）。upstream 接続は要求ごとに張る（揮発する 1Password agent
  socket のキャッシュ複雑化を避ける、コストは署名/TouchID レイテンシに対し無視できる）。macOS では
  Group Containers 配下の 1Password agent socket を state dir の安定 symlink 経由にして TCC ダイアログを
  回避する（Linux では不要、cfg 分岐）。
- **鍵フィルタ（Iteration 3）**: socket は `filters` で「見せる/署名する鍵」を絞れる。socket A には
  GitHub 用鍵だけ、socket B には全部、のような分離を実現する。各 TOML 要素は **OR 項**で、文字列は
  単一ルール項（`"comment=github*"`）、配列は AND グループ（`["comment=*@work*", "type=ed25519"]`）。
  項どうしは OR、グループ内のルールは AND（= OR of AND）。`filters` が空/省略なら絞り込みなし（全鍵）。
  ルール形式は `comment=` / `type=` / `fingerprint=` / `pubkey=` / `keyfile=` / `github=`（各 `not-` で
  否定可、authsock-warden 互換）。`comment` は exact / glob（`*`/`?`）/ `~regex`。フィルタは**公開側のみ**
  （blob / comment / type / fingerprint / github 公開鍵）を見て判定し、秘密値には触れない。
  - **REQUEST_IDENTITIES**: KV 鍵 + upstream 鍵をマージした後にフィルタを適用し、通過した鍵だけを
    列挙する。フィルタで隠れた upstream 鍵は転送ルートにも記録しない。
  - **SIGN_REQUEST**: フィルタ通過鍵のみ署名を許可する。**列挙に出ない鍵への直接署名要求も拒否**する。
    ローカル鍵はレジストリの comment 込みで判定するので comment フィルタも直接署名経路で効く。upstream
    鍵は列挙で記録した転送ルート経由のみ許可（comment-only フィルタは「列挙してから署名」を要求する）。
    blob から判定できる `fingerprint` / `type` / `pubkey` / `github` フィルタは列挙なしの署名でも正確に評価する。
  - **github フィルタ（`github=<user>`）**: `github.com/<user>.keys` の公開鍵リストを取得し、提示鍵の wire
    公開鍵 blob がそのリストに含まれる鍵のみ通す。取得は **curl shell-out**（新規 HTTP クライアント依存を入れず、
    op と同じく外部 CLI を叩く）。`FilterEvaluator::matches()` は同期でホットパスから呼ばれるため、matcher は
    `Arc<RwLock<キャッシュ>>` を持ち **照合はキャッシュ read のみ**（同期・ネットワークなし）。取得は daemon の
    バックグラウンド refresh task（初回 fetch + `[authsock.github].cache_ttl` 間隔の再取得、`spawn_blocking` で
    curl 実行、shutdown で停止）が担いキャッシュへ書き戻す。**fail-closed**: 取得失敗（ネット断 / timeout /
    非ゼロ / パース不能）や未取得時はその鍵を一切通さない（安全側）。`[authsock.github]` で `cache_ttl`（既定 1h）/
    `timeout`（既定 10s）を設定。`source`（op 発見）併用可。
- **プロセスアクセス制御（`allowed_processes`、Iteration 5）**: socket に `allowed_processes`（実行ファイル
  basename のリスト）を設定すると、その socket を使えるプロセスを制限できる。**空/省略なら制限なし**（全プロセス
  許可、これは不変条件 = 未設定の socket の挙動は従来どおり）。非空なら、接続元 peer pid の**祖先チェーン**（コアの
  `SystemInspector::ancestry`、init/launchd まで遡上）を取得し、そのチェーン中の**いずれかの**プロセスの
  basename が allowed リストに**完全一致**（glob / regex なし、warden 踏襲）すれば許可。判定は **接続単位で 1 回**
  （peer pid は接続中固定なので、`handle_connection` で 1 度だけ判定し、不許可ならその接続の全リクエストを
  `SSH_AGENT_FAILURE` で返す = 列挙も署名も一律拒否し、どの鍵があるかも漏らさない）。照合ロジックはアダプタ層
  （DR-0004、ポリシー解釈はアダプタ責務）、祖先遡上はコア。path 未解決（`name()==None`）の祖先はスキップ。
  **peer pid 取得失敗 / 祖先遡上失敗時は fail-closed（拒否）**（プロセスを特定できないなら制限 socket は拒否、
  DR-0012。warden は fail-open だが cache-warden は安全側に倒す差異）。空 allowed_processes の socket では祖先遡上
  自体を行わないので、pid 不明でも従来どおり全通過する。
- **プロセスアクセス制御 key 層（`[kv.NAME].allowed_processes`、DR-0012 key 層）**: 個々の KV キーにも
  `allowed_processes`（実行ファイル basename のリスト、socket 層と同一セマンティクス）を設定でき、その**値の取得**を
  制限できる。**空/省略なら制限なし**（socket 層と同じ不変条件）。**config 専用**（defs ファイル / `kv define` CLI
  からは設定不可）= ポリシーは秘密値の持ち主＝config 管理者が決めるもので、クライアントが define 時に自己申告する
  ものではない（よって `KvDefinition` には載せず、daemon が config から `key → list` の policy table を構築して
  共有状態に保持。コア `Store` には入れない＝アダプタ/ハンドラ責務、DR-0004）。判定は socket 層と**直列**にかかる
  （socket 層は接続時に判定済み、key 層はその上に重なる＝socket を通れても key で拒否され得る。「交差空＝全拒否」は
  両層がそれぞれ独立に通過する必要があるという意味で実装。空＝全許可は「省略」の意味のみで、制限付きキーは判定中に
  空集合へ転落しない＝warden の罠を踏まない）。照合は requester（接続元 peer pid の祖先チェーン、control / 署名
  双方で解決済み）に対し socket 層と共有の `chain_gate_passes` を適用＝**祖先 OR + basename 完全一致**、
  **requester 不明時は fail-closed**。適用面は 2 つ:
  - **control socket `kv.get`**（lazy 生成 / dry-run 含む）: 取得チェーンの**前**にゲート（拒否 requester は
    source コマンドや再認証プロンプトを一切起動しない）。拒否は `auth_failed`。キーの存在は `kv.list` で既に見える
    ので隠さず、値・詳細のみ出さない。**`kv.del` / `kv.pin` / `kv.unpin` 等の変更系はゲート対象外**（取得制御が
    目的であり、ポリシーは値の取得を制御するもの＝エントリのライフサイクル管理ではない、という設計判断）。
  - **authsock SIGN_REQUEST**: KV ローカル鍵を引くとき、その鍵の `allowed_processes` を requester で照合。拒否は
    `SSH_AGENT_FAILURE`（payload 空＝既存の何も漏らさない流儀）。**REQUEST_IDENTITIES の列挙からは除外しない**
    （warden の鍵単位挙動および cache-warden の「キー存在は list で見えてよい、値・詳細は出さない」原則に合わせ、
    列挙はするが署名時に拒否）。op 鍵の内部 KV 名 `__authsock_op:*` は config `[kv.*]` に出ないので自然と無制限。
- **失敗は何も漏らさない**: 未知鍵 / フィルタ除外 / 認証拒否 / hard 切れ static / 不正要求 / 署名失敗 /
  全 upstream 失敗はすべて `SSH_AGENT_FAILURE`（payload 空）。エラー詳細を agent protocol に出さない。
- **隔離**: KV ローカル署名のハンドラは control socket と同じく `spawn_blocking` で隔離する（再認証
  コマンドはプロンプト待ちで分単位ブロックし得るため、async ワーカーを占有させない）。upstream への
  I/O は async（non-blocking socket）でランタイム上。

> 現状は static / command 定義（起動時 eager 実体化）の鍵によるローカル署名 + upstream agent への鍵マージ・署名転送 +
> socket 単位の鍵フィルタ（github= 含む）+ op 鍵発見 + socket 単位 + 鍵単位（key 層）の
> プロセスアクセス制御（`allowed_processes`）まで。

### secret reference 注入（`run` / `inject` / dry-run、DR-0013 / DR-0015）

CLI を「複数の秘密値をまとめて子プロセスや設定ファイルに渡す」主経路にするための 2 動詞。
どちらも authsock・認証コアとは独立で、control socket クライアント（`kv.get`）として完結する。

- **参照構文**: `cache-warden://[NS/]KEY`（スキームは 1 種のみ・エイリアスなし、DR-0017）。
  KEY / NS の文字種は `[A-Za-z0-9_]+`。**未修飾の KEY は呼び出し文脈の namespace に解決され、
  `NS/KEY` 修飾は絶対参照**。dry-run のマスクは解決後の絶対キー
  （`<cache-warden:NS/KEY:masked>`）で表示される。解決は単一パス＝解決後の値に
  参照が含まれても**再帰展開しない**（展開爆発・二次展開を構造的に排除）。同一 KEY の重複参照は
  解決 1 回に dedup（TouchID 連打を増やさない）。本番は **fail-closed**（1 つでも解決失敗したら
  子プロセス起動・出力生成を一切せず非ゼロ終了）。
- **`run` — env 注入 + exec**: `run [--env NAME=VALUE]... [--defs FILE]... [--dry-run|--reveal] -- CMD [ARGS...]`。
  継承 env と `--env` 指定のうち、**値が全体一致**で `cache-warden://KEY` のものだけを解決して置換する
  （op run と同じ whole-value 規則。部分置換は `inject` の責務）。**argv は注入面にしない**: 子プロセスの
  argv は `ps` / `/proc/PID/cmdline` で他ユーザからも見えるため、argv 置換は構造的漏洩になる。ARGS 中に
  参照らしき文字列があれば stderr に 1 行警告した上で verbatim に渡す（子プロセス自身が解決する正当な
  使い方を壊さない）。解決後は `exec` でプロセスイメージを置換し、解決済み秘密値を抱えたまま生き続ける
  親を残さない（exec 失敗は not found = 127 / 実行不能 = 126）。
- **`inject` — テンプレート置換**: `inject [--in FILE] [--out FILE] [--defs FILE]... [--dry-run|--reveal]`。
  既定は stdin → stdout。テンプレート中の参照を**部分文字列として**全て実値に置換し、バイト列処理で
  バイナリ安全。全参照の解決が完了してから出力を書き始める（部分出力を残さない）。`--out FILE` は
  **0600 で作成**する（umask 非依存。秘密値ファイルをグループ/他者可読で生まない）。
- **`--defs FILE`（DR-0014 連携）**: 参照解決に使う定義をファイルから読む（`kv define --defs` と同じ defs
  ファイル形式、自動探索なし）。
- **dry-run（DR-0015）**: `kv get` / `run` / `inject` の 3 動詞共通。デフォルトは実値（reveal）、
  `--dry-run` は**配線だけを full-chain で検証して値を出さない**モード。検証の深さは妥協せず、未ロード
  定義の upstream 実行・SoftExpired の extend・HardExpired の regenerate・認証ゲート（TouchID）まで通常どおり
  完走する（「dry-run OK = 本番も通る」を保証。**副作用あり**＝キャッシュが温まる）。**値はデーモンから
  出ない**: マスクはクライアント側で隠すのではなく `kv.get {dry_run}` の value-free 応答でそもそも値が
  クライアントに届かない。マスク形式は成功 `<cache-warden:KEY:masked>` / 失敗 `<cache-warden:KEY:failed>`
  （本物と見間違えず key 名だけ読める）。dry-run は途中で止めず**全参照を評価**してから、1 つでも失敗が
  あれば非ゼロ終了 + stderr サマリ。極性切替（`[cli].default-mode` / `CACHE_WARDEN_DRY_RUN`）は設定節参照。

実装はすべて `cache-warden-cli` crate に閉じる（コア / authsock crate 変更なし、DR-0002）。参照のインライン
define（`cache-warden://KEY?argv=...`）は v1 では未実装（DR-0014）。

### KV namespace（`--namespace` / `NS/KEY` 合成、DR-0017）

複数プロジェクトが同じ KEY 名（`DB_PASSWORD` 等）を別定義で使えるようにする分離機構。
namespace は **CLI / プロトコル層の概念**で、内部キーは `NS/KEY` に合成されてコアの flat な
Store に流れる（コアは不変）。デフォルト NS は `"default"`。

- **文字種**: KEY / NS とも `[A-Za-z0-9_]+`（単一セグメント）。`kv.set` / `kv.define` の
  プロトコル境界で生成時に強制され、「参照も config 記述もできない不整形キー」は存在しない
  （authsock 内部キー `__authsock_op:*` はプロトコルを通らないため適用外）。
- **CLI**: kv 全動詞 + `run` / `inject` / `status` に `--namespace NS`。KEY 引数への
  `ns/key` 埋め込みは拒否（指定経路はフラグ一本）。デフォルトの解決は
  `--namespace` > `CACHE_WARDEN_NAMESPACE` > `[cli].namespace` > `"default"`
  （direnv で `.envrc` に export すればプロジェクトに入った瞬間に切り替わる）。
- **list / status**: 既定は現在 NS のみ（`NS/` プレフィックスを外した素のキー名で表示）。
  `--all-namespaces` で全 NS を `NS/KEY` 表記で列挙。
- **config / defs**: `[kv.NAME]` に省略可能な `namespace = "NS"` フィールド
  （あり = 絶対指定 / なし = 文脈デフォルト。daemon config の文脈は `"default"`、
  defs は `kv define --defs F --namespace NS` の指定値）。TOML テーブルキーは一意なので
  同一ファイル内に同じ NAME を別 NS で 2 回書けない（既知の制限）。authsock の
  `keys = [...]` は `"NS/KEY"` 修飾可（未修飾 = default NS）。
- **定義永続化**: `[kv.NS.KEY]` の dotted ネスト（kv → NS → KEY の均一 2 階層マップ）で
  保存して round-trip する。機械生成で全エントリの NS が正規化済み = 深度が均一であり、
  文字種に `.` が無いので全セグメントが bare key（quoting 不要）かつパス深度 = 意味が一意。
  同 KEY 別 NS の共存も自然に表現できる。

### OTP 値型（`kv define --type otp`、DR-0016）

TOTP の **seed**（raw base32 / otpauth:// URI）をキャッシュし、6 桁コードは get のたびに
デーモン側で導出する派生ビュー。キャッシュするのは seed なので TTL / mlock / zeroize /
extend / pin / regenerate がすべてそのまま効き、コードの 30 秒ウィンドウは直交概念。

- **`kv define` 専用の `--type otp`**: 値型メタデータ。パラメータは
  `--otp-digits`（既定 6）/ `--otp-period`（既定 30s）/ `--otp-algorithm sha1|sha256|sha512`
  （既定 sha1）。otpauth:// URI の値なら URI からパラメータを読み、明示フラグが優先。
  defs ファイル・定義永続化にも型ごと乗る。**型は定義に乗る** ので、型付きキーは必ず
  定義を伴う。`kv set` は opaque な static バイト列専用で `--type` / `--otp-*` を受け付けず、
  渡すと「`kv define` で登録して」と誘導してエラーになる（static seed は再起動で消え、
  再投入のため seed を平文保持する運用を誘発する＝ DR-0016 のアンチフィーチャー）。
- **seed は write-only**: otp 型キーへの `kv get` は常に導出済みコードを返し、seed は
  デーモンから二度と出ない。クライアント（エージェント含む）に渡るのは
  常に寿命 ~30 秒の減衰した権限になる。`run` / `inject` の参照解決もコードを注入する。
  dry-run は通常どおりマスク。
- **コアは OTP を知らない**: 値型は **定義** が持つ不透明なメタデータスロット（型ラベル +
  文字列マップ、コアは解釈せず保持・比較のみ）で表現し、値エントリ自体は常に opaque バイト列。
  型判定（status / get）はすべて定義レジストリ（`definition_of(key).meta()`）を参照する。
  TOTP の語彙と導出（RFC 4226 / 6238、RustCrypto hmac + sha1/sha2）は CLI crate のハンドラ層に
  閉じる。将来の別の派生ビュー型もコア変更なしで同スロットに乗る。
- **footgun ガード**: `--type otp` と `?attribute=otp` source の組合せは define 時エラー
  （op が計算した 30 秒コードのキャッシュは構造的誤り。source は seed の field を指す）。
- 推奨パターン: seed を op に置き `kv define --type otp --source op://vault/item/field`
  （lazy regenerate により daemon 再起動後も自己修復）。値のみ `del` しても定義が残り、
  次の get で再び otp として導出される。`del --with-define` で型ごと消える。

### Workspace 構成（DR-0002）

| Crate | 役割 | 依存 | Publish |
|---|---|---|---|
| `cache-warden` | ライブラリ（コアロジック） | 最小（std のみ目標） | crates.io |
| `cache-warden-authsock` | authsock アダプタ（SSH agent protocol / signer / 公開鍵レジストリ） | ssh-key, ed25519-dalek, rsa, pkcs8 等 | No（安定化まで保留） |
| `cache-warden-cli` | CLI バイナリ | 両ライブラリ, serde 等 | No（Homebrew 配布） |

設計原則:

- ライブラリは依存最小（`Serialize` 等の serde 依存は CLI 側に寄せる）。ライブラリ利用者に
  孫依存を強制しない。
- stable-which と同じ workspace 分離パターン（Rust エコシステムの王道）。
- CLI は Homebrew / GitHub Releases で配布。

### value ライフサイクル（概念）

soft と hard は別基準（DR-0011）。soft = `extended_at`（extend で延命）、
hard = `loaded_at`（set/regenerate で固定、extend では不動 = 絶対寿命）。

```
       static は set / command は define + 初回 get(lazy 生成)
                  extend (使うたびに soft を延命、hard は不動)
                  ┌────────────────────────────┐
                  ▼                            │
load ──> [キャッシュ保持] ──soft TTL 切れ(extended_at 基準)──> 再認証(TouchID)
            │                                       │成功→延長して保持
            │                                       │失敗→取得不可
            └──hard TTL 切れ(loaded_at 基準)──> zeroize で破棄
                                  │ command 型: コマンド再実行 → 再認証 → 再生成
                                  │ static 型 : エラー（再 set が必要）

pin(期限) ─── 期限まで soft/hard とも失効抑止(Active 扱い) ───> 期限後は通常判定
            （再認証必須。Active からでも要求。unpin で解除＝認証不要）
```

## open question（未確定・「朧げ」な部分）

正直に列挙する。決めすぎず、実装フェーズで詰める。

- **コア / アダプタの層の精密な切り方**: 特に「プロセス認識アクセス制御」をコア（汎用プロセス認証）と
  アダプタ（ソケット / 鍵ごとのポリシー解釈）にどう分けるか（DR-0004 で初期方針のみ）。
- **サービス登録（launchd / systemd）の所属**: コア（サーバ起動）側かアダプタ側か。
- **ビルトイン TouchID 実装方式**: security-framework / objc2 のどちらを使うか（authsock-warden
  DR-018 でも未決）。**ビルトイン化する iteration で決める**（現フェーズは再認証コマンド方式
  `CommandAuthenticator` で充足、DR-0010）。
- **static 型の hard TTL 切れ時のユーザ通知方法**。

## authsock-warden との関係・移行パス

cache-warden は authsock-warden の**後継コア**であり、authsock-warden の機能を「authsock アダプタ」
として移植する。authsock-warden は将来引退する。詳細は
[DR-0004](./decisions/DR-0004-authsock-warden-succession.md)。

移行は段階的・可逆に進め、全フェーズで kawaz の日常の鍵利用を中断させない:

| Phase | 内容 |
|---|---|
| Phase 0（現状） | authsock-warden が日常稼働。cache-warden は雛形のみ |
| Phase 1（並走） | cache-warden に KV コア + authsock アダプタを実装、authsock-warden と別ソケットで並走 |
| Phase 2（パリティ） | authsock アダプタが authsock-warden と機能パリティを達成 |
| Phase 3（切替） | 利用ソケットを cache-warden 側へ切替。authsock-warden はフォールバック残置 |
| Phase 4（引退） | 安定確認後、authsock-warden を引退 |

移植対象資産のコア / アダプタ振り分けは DR-0004 を参照。

## スコープ外

- **外部ソケットのパス安定化 / 安定 symlink 提供**: 外部プログラムが作る volatile なソケット
  （docker.sock / 各種 agent socket 等）のパスを後追いで安定化する用途は扱わない。cache-warden が
  作るのはソケットそのもの（サーバ側）である（旧 DR-0001 の構想は DR-0003 で Supersede）。
- cache-warden コアが直接担わないプロトコル変換は、各アダプタの責務。

## 将来検討

- **control socket / KV socket API**: 管理 CLI ↔ デーモンの通信と、他プロセスからプログラマティックに
  KV を操作する経路を 1 本の Unix domain socket プロトコルに統合する（DR-0008、設計は次ステップ）。
- **自前 TouchID**: 上流（op）に頼らず cache-warden 自身が LocalAuthentication で再認証を発行する。
  SSH 鍵署名のゲートにも転用できる。
- **アダプタの追加**: SSH / KV 以外の秘密値プロトコルを扱うアダプタ。
- **KV definition モデル（`kv define` / 定義レイヤ / 定義永続化）**: 動詞の責務を
  define（定義登録のみ・lazy 実行）/ set（static 専用）/ get（読み専念）に分離し、
  定義レジストリを値ストアと分けて持つ。設計は
  [DR-0014](./decisions/DR-0014-kv-definition-model.md) で確定済み。**実装済み**: `kv define` 動詞 /
  `--source URI`（op:// 糖衣）/ 値ストアと分離した定義レジストリ / `kv get` の lazy 生成 /
  `kv del --with-define` / config `[kv.*]` の lazy デフォルト + `preload` opt-in（authsock 参照鍵は自動 eager）/
  defs ファイル（`kv define --defs FILE`、自動探索なし）/ オンライン定義の永続化
  （`[daemon].persist-definitions` opt-in、値は書かない、起動時は config 優先マージ + 正規化 re-write）。
  さらに secret reference 注入（`run` / `inject`、DR-0013）と dry-run 検証モード（3 動詞の
  `--dry-run` / `--reveal`、`[cli].default-mode`、`CACHE_WARDEN_DRY_RUN`、`kv.get {dry_run}`、DR-0015）も
  実装済み（本文「secret reference 注入（run / inject / dry-run）」節）。
  **未着手**: 参照のインライン define（`cache-warden://KEY?argv=...`）。

詳細は [ROADMAP.md](./ROADMAP.md) を参照。

## 関連ドキュメント

- [decisions/INDEX.md](./decisions/INDEX.md) — DR 一覧
- [DR-0002-workspace-structure](./decisions/DR-0002-workspace-structure.md) — Workspace 構成
- [DR-0003-secure-kv-core-and-adapters](./decisions/DR-0003-secure-kv-core-and-adapters.md) — コアドメインとアダプタ構造
- [DR-0004-authsock-warden-succession](./decisions/DR-0004-authsock-warden-succession.md) — authsock-warden 後継・吸収方針
- [DR-0008-single-daemon-hosting](./decisions/DR-0008-single-daemon-hosting.md) — 単一デーモンプロセス直担型のホスティング形態
- [DR-0009-control-socket-protocol-v1](./decisions/DR-0009-control-socket-protocol-v1.md) — control socket プロトコル v1
- [DR-0010-config-and-reauth-command](./decisions/DR-0010-config-and-reauth-command.md) — TOML config と再認証コマンド方式
- [STRUCTURE.md](./STRUCTURE.md) — 物理構造
- [ROADMAP.md](./ROADMAP.md) — 将来検討
