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
  - `command`: 上流コマンド（例 `op read ...`）の実行結果。hard TTL 切れ後はコマンド再実行で再生成できる。
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
# command ソース: 上流を遅延キャッシュし、soft TTL 切れは再認証で延長
cache-warden kv set DB_PASSWORD --command "op read 'op://vault/item/password'" --soft-ttl 1h --hard-ttl 24h

# static ソース: その場の値をキャッシュ
cache-warden kv set TEMP_CERT --value "$(cat cert.pem)" --soft-ttl 8h

# 取得（キャッシュヒットは数 ms）
cache-warden kv get DB_PASSWORD
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
- **コマンド v1**: `ping` / `status`（デーモン情報 + エントリ一覧。**値は含めない**。pin 中は残り秒を併記）/
  `kv.set`（static + `value_b64` または command + `argv`、soft/hard TTL 秒）/
  `kv.get`（SoftExpired は再認証で延長、HardExpired + regenerable は再生成して値を返す）/
  `kv.del` / `kv.list` /
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
`kv set|get|del|list|pin|unpin` / `config show|path|edit`（引数なしは help、ロングオプション）。
`kv pin <KEY> <DURATION>` は TTL を無視して値を期限まで Active 保持（再認証必須）、
`kv unpin <KEY>` は解除。

- **`daemon` グループ**: デーモンのライフサイクル操作を隔離する。`daemon run`（フォアグラウンド起動）
  のみ実装済み。`daemon register` / `daemon unregister`（launchd/systemd サービス登録）/
  `daemon status`（プロセス・登録状態）は将来実装で、未実装のうちはグループ help に出さない。
  トップレベルに `run` を出さないのは、`kv get` 等を日常的に叩くクライアントとして使う中で、
  デーモン起動コマンドを誤操作（意図しない二重起動）する事故を避けるため。
- **`status` の対比**: トップレベル `status` = キャッシュエントリ一覧（ユーザ向け、値は含めない）。
  将来の `daemon status` = プロセス・サービス登録状態（運用向け）。同じ語で関心が違うので分ける。
- **将来 `run`**: 空けたトップレベル `run` は op run 相当（秘密値を env 注入して子コマンドを実行）に
  充てる予定（「将来検討」節参照）。

### 設定（TOML config・再認証コマンド、DR-0010）

デーモンの設定は TOML（`#[serde(deny_unknown_fields)]`）。config 無しでも全デフォルトで
起動する。探索順（高優先順位が先）: `$CACHE_WARDEN_CONFIG` → `$XDG_CONFIG_HOME/cache-warden/config.toml`
→ `~/.config/cache-warden/config.toml`。詳細・代替案は [DR-0010](./decisions/DR-0010-config-and-reauth-command.md)。

```toml
[daemon]
socket = "~/.local/state/cache-warden/control.sock"  # CLI --socket > [daemon].socket > デフォルト

[auth]
command = ["/path/to/reauth-prompt"]  # 省略時は AllowAll（再認証なし）

[kv.DB_PASSWORD]                       # 起動時プリロード（command ソースのみ）
command = ["op", "read", "op://vault/item/password"]
soft-ttl = "1h"
hard-ttl = "24h"
```

- **再認証コマンド**: `CommandAuthenticator`（ライブラリ）が `[auth].command` の argv を実行し、
  exit 0 = 承認 / 非ゼロ = 拒否 / spawn 失敗 = 利用不能。`AuthContext` の情報（key・operation・
  requester チェーン）を環境変数で渡すが**秘密値は渡さない**。timeout なし（ユーザ入力待ちが正常系）。
- **起動時プリロード**: `[kv.*]` の command エントリを起動時に実行してキャッシュ投入。失敗しても
  fatal でなく、stderr に 1 行警告（値なし）を出してエントリ未登録のまま起動継続。
- **static を config に書けない**: `[kv.*]` は command ソースのみ。リテラル値（`value` 等）を
  書くと設定エラー（平文秘密値が config に残る漏洩を構造的に防ぐ）。リテラル値は実行時に
  `cache-warden kv set --value-stdin` で投入する。

### authsock アダプタ（SSH agent socket、port plan Iteration 1–4）

cache-warden は config で宣言した SSH agent socket を自ら listen し、KV にキャッシュした
秘密鍵 PEM で SSH クライアントの署名要求に応える。`SSH_AUTH_SOCK` をこの socket に向けた
クライアント（`ssh` / `ssh-add` / git 等）から見ると、通常の SSH agent として振る舞う。

```toml
[kv.GITHUB_KEY]                              # 秘密鍵 PEM を command でプリロード
command = ["op", "read", "op://vault/github/private_key"]
soft-ttl = "1h"
hard-ttl = "24h"

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
  アダプタ側で吸収、DR-0004）。
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
- **失敗は何も漏らさない**: 未知鍵 / フィルタ除外 / 認証拒否 / hard 切れ static / 不正要求 / 署名失敗 /
  全 upstream 失敗はすべて `SSH_AGENT_FAILURE`（payload 空）。エラー詳細を agent protocol に出さない。
- **隔離**: KV ローカル署名のハンドラは control socket と同じく `spawn_blocking` で隔離する（再認証
  コマンドはプロンプト待ちで分単位ブロックし得るため、async ワーカーを占有させない）。upstream への
  I/O は async（non-blocking socket）でランタイム上。

> 現状は static / command プリロードの鍵によるローカル署名 + upstream agent への鍵マージ・署名転送 +
> socket 単位の鍵フィルタ（github= 含む）+ op 鍵発見 + socket 単位のプロセスアクセス制御
> （`allowed_processes`）まで。鍵単位の `allowed_processes`（key 層）は後続 iteration（port plan §2）。

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
                  extend (使うたびに soft を延命、hard は不動)
                  ┌────────────────────────────┐
                  ▼                            │
set ──> [キャッシュ保持] ──soft TTL 切れ(extended_at 基準)──> 再認証(TouchID)
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
- **トップレベル `run`（op run 相当）**: デーモン起動を `daemon run` へ移したことで空いたトップレベル
  `run` を、秘密値を env 注入して子コマンドを実行する用途（`cache-warden run -- cmd`）に充てる。
  `cache-warden://KEY` 参照の置換機能（`inject`）とあわせて control socket クライアントとして実装する。
  設計は [DR-0013](./decisions/DR-0013-secret-reference-injection.md) で確定済み（参照構文 /
  env は whole-value のみ・argv 非置換 / 解決後 exec / `inject` は substring 置換）。実装は未着手。

- **KV definition モデル（`kv define` / 定義レイヤ / 定義永続化）**: 動詞の責務を
  define（定義登録のみ・lazy 実行）/ set（static 専用）/ get（読み専念）に分離し、
  定義レジストリを値ストアと分けて持つ。defs ファイル（`--defs`）・オンライン定義の
  永続化（opt-in、値は書かない）・`--source URI`（op:// 等）を含む。設計は
  [DR-0014](./decisions/DR-0014-kv-definition-model.md) で確定済み。実装は未着手
  （現実装は `kv set --command` の eager 実行のまま）。

- **OTP 値型（`--type otp`）**: TOTP の seed をキャッシュし、`kv get` / 参照解決のたびに
  デーモン側で 6 桁コードを導出して返す。seed は write-only（デーモンから出ない）。
  設計は [DR-0016](./decisions/DR-0016-otp-value-type.md) で確定済み。実装は未着手。

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
