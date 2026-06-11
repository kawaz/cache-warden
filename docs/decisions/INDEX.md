# Decision Records 一覧

## Active

- [DR-0002](./DR-0002-workspace-structure.md) — Workspace 構成: lib（依存最小・crates.io）/ cli（Homebrew 配布）の分離（stable-which パターン）
- [DR-0003](./DR-0003-secure-kv-core-and-adapters.md) — コアドメインを「秘密値のセキュア KV キャッシュ」と定める（TTL / プロセス認証 / 再認証 / メモリ保護）。SSH 鍵管理はその上のプロトコルアダプタ。authsock-warden DR-018 構想の別プロジェクト化。命名 `cache-warden` 維持。DR-0001 全体を Supersede
- [DR-0004](./DR-0004-authsock-warden-succession.md) — authsock-warden 後継・吸収方針。warden 機能を「authsock アダプタ」として移植 / 移植対象資産の整理（コア vs アダプタ）/ 並走 → パリティ → 切替 → 引退の移行パス
- [DR-0005](./DR-0005-core-security-dependencies.md) — コアの秘密値ゼロ化に `zeroize` crate を例外採用（DR-0002 の依存最小原則に対する意図的例外）。自作 volatile write 案・secrecy 案の却下理由つき
- [DR-0006](./DR-0006-process-inspection-dependencies.md) — プロセス検査（pid → path / ppid / 開始時刻）に `libc` を最小依存として採用（DR-0002 への 2 つ目の意図的例外）。sysinfo 案・raw syscall 案・依存ゼロ案の却下理由つき。authsock-warden の libc 直叩き前例を踏襲
- [DR-0007](./DR-0007-mlock-memory-pinning.md) — 秘密値ページを `mlock` で常時ピン留めしスワップ漏洩を抑止。失敗は fail-open（`is_locked()` で検知可能）/ munlock→zeroize 順 / 不変バッファ設計で Vec 再確保問題を構造的に回避 / feature gate にせず常時有効。追加依存なし（libc は DR-0006 で導入済み）。DR-0005 が「別 DR で判断」とした mlock 採用の決定
- [DR-0008](./DR-0008-single-daemon-hosting.md) — 単一デーモンプロセス直担型。`cache-warden run` = 1 プロセス（tokio）で全アダプタを listener task として in-process 直担（決定打は秘密値の 1 プロセス閉じ込め）。管理 CLI ↔ デーモンは control socket（KV socket API と統合、プロトコル詳細は次ステップ）。サービス登録は単一バイナリ + `run`。内部サブコマンド方式・アダプタ別デーモンを却下。DR-0003 / DR-0004 が残したホスティング形態・デーモン境界を確定
- [DR-0009](./DR-0009-control-socket-protocol-v1.md) — control socket プロトコル v1。transport = UDS（0600 / stale 検知 / 二重起動拒否）、framing = JSON Lines、秘密値は base64（`*_b64`）。コマンド = `ping` / `status`（値非露出）/ `kv.set` / `kv.get` / `kv.del` / `kv.list`。peer 認証 = LOCAL_PEERPID / SO_PEERCRED → ancestry を requester として渡す（解釈はまだしない）。Authenticator は AllowAll 暫定配線。length-prefixed バイナリ・gRPC/CBOR・素 JSON 文字列を却下。DR-0008 が残したプロトコル設計を確定
- [DR-0010](./DR-0010-config-and-reauth-command.md) — TOML config と再認証コマンド方式。実 Authenticator = `CommandAuthenticator`（lib、exit 0=承認/非ゼロ=拒否/spawn失敗=Unavailable、AuthContext を env で渡し秘密値は渡さない、timeout なし、warden DR-009 踏襲）。TOML config（CLI、`deny_unknown_fields`、`$CACHE_WARDEN_CONFIG`→`$XDG_CONFIG_HOME`→`~/.config` 探索、`[daemon].socket`/`[auth].command`/`[kv.*]` 起動時プリロード）。**static を config に書けない設計**（平文秘密値の流出防止、書いたら設定エラー）、auth 省略時=AllowAll、socket 優先順位 CLI>config>default、`config show|path|edit` 追加。ビルトイン TouchID 先行・config への static 値許可・config 必須化を却下。DR-0009 の AllowAll 暫定配線を置換
- [DR-0012](./DR-0012-process-access-policy.md) — socket 層プロセスアクセス制御（`allowed_processes`）。socket 層のみ実装（key 層は warden の `[[keys]]` 構造が無く実 config 全空なのでパリティ後に後送り）/ 空配列=全許可（不変条件）/ 照合=全祖先 OR + 実行ファイル basename 完全一致（glob/regex なし、warden 踏襲）/ `name()==None` の祖先はスキップ / **pid 取得失敗・祖先遡上失敗時は fail-closed（拒否）**（warden は fail-open だが安全側に倒す差異）/ 接続冒頭で 1 回判定し不許可なら全リクエスト SSH_AGENT_FAILURE（列挙も署名も隠す）/ 照合はアダプタ層（DR-0004）/ 将来 key 層は交差空=全拒否（warden の罠を踏襲しない）。port plan Iteration 5。
- [DR-0016](./DR-0016-otp-value-type.md) — OTP 値型。キャッシュするのは seed（base32 / otpauth:// URI、TTL・mlock・zeroize が全部効く）、6 桁コードは get 毎にデーモン側で導出する派生ビュー（A 案の UX を B 案のレイヤリングで = ハンドラ層変換 1 枚、コアは OTP を知らない）/ **seed は write-only**（デーモンから出ない、クライアントには寿命 30 秒のコードのみ = op より強い）/ `--type otp` 定義メタデータ、digits/period/algorithm は URI < フラグ / `?attribute=otp` source との組合せは define 時エラー（30 秒で死ぬ値のキャッシュ防止）/ 推奨 = seed を op に置き `--source` 定義（lazy regenerate で再起動自己修復）/ hmac+sha1 は CLI crate（コア依存最小は不変）。独立翻訳アダプタ・クライアント側導出・コードのキャッシュ・seed 読出許可・暗号手書きを却下
- [DR-0015](./DR-0015-dry-run-verification-mode.md) — dry-run 検証モードと reveal デフォルトの統一。`kv get` / `run` / `inject` はデフォルト実値（op の「移送 = 実値」と同極性）/ `--dry-run` = 値を出さない full-chain 検証（upstream 実行・再認証・regenerate まで完走、認証ゲート有効、値は応答に載せない = クライアントに届かない）/ マスク値 `<cache-warden:KEY:masked>` / 失敗 `<cache-warden:KEY:failed>`、dry-run は途中 fail-closed せず全評価 + 非ゼロ終了 / デフォルト極性は `[cli].default-mode` と `CACHE_WARDEN_DRY_RUN` で切替（エージェント環境だけ dry-run 既定にできる）/ help に dry-run の存在を明記（エージェント発見性）/ `kv.get` に `dry_run` 追加。非対称デフォルト・全 masked・浅い dry-run・クライアント側マスキングを却下
- [DR-0014](./DR-0014-kv-definition-model.md) — KV definition モデル。動詞の責務分離: `kv define`（定義登録のみ、実行は初回 get まで lazy、冪等 = 完全一致 no-op / 不一致エラー）/ `kv set`（static 専用、`--command` 廃止）/ `kv get`（読み専念、定義があれば regenerate 経路で lazy 生成）。定義レジストリは値ストアと分離（NotLoaded を EntryState に作らない、DR-0004 同型）/ `kv del` = 値のみ破棄、`--with-define` で定義ごと / `--source URI`（v1 は op:// ビルトイン、scheme テーブルは follow-up）/ 定義 4 レイヤ（config lazy 化 + `preload` opt-in + authsock 参照鍵は自動 eager、オンライン定義の永続化 opt-in（値は書かない・config 優先マージ）、`--defs FILE` 一括 define、純オンライン）/ defs 自動探索なし（データ→コード防止）/ 参照クエリ拡張（インライン define）は opt-in 設計で後送り。get-or-init 案・eager define・NotLoaded 追加・declarative 上書き・値永続化を却下。DR-0010 / DR-0013 を一部改訂
- [DR-0013](./DR-0013-secret-reference-injection.md) — secret reference 注入（`run` / `inject`）。参照構文 = `cache-warden://KEY`（スキーム 1 種、KEY は env 変数風文字種、再帰展開なし）/ 解決 = control socket `kv.get`（dedup、fail-closed）/ `run` = env のみ注入面（whole-value 規則、op run 互換）+ `--env` + 解決後 exec（親プロセス残置なし、127/126 慣習）、**argv は置換しない**（ps 漏洩防止、警告して verbatim）/ `inject` = テンプレ substring 置換（バイナリ安全、`--out` は 0600）/ 実装は CLI crate に閉じる。argv 置換・出力マスキング・env 部分置換・短縮スキーム・`--env-file` を却下。実装は未着手（issue 参照）
- [DR-0011](./DR-0011-ttl-base-separation-and-pin.md) — TTL 基準の 2 分離と pin API。`activated_at` を `loaded_at`（set/regenerate 固定 = hard 基準）と `extended_at`（extend で動く = soft 基準）に分離し、「extend し続ければ hard が永遠に来ない」曖昧仕様を解消（extend は soft だけ延命、hard は値の絶対寿命として固定）。明示の `pin`（`pin_until(deadline)`）= 期限まで soft/hard とも失効抑止、本来の hard を過ぎていれば pin 切れで即 HardExpired、HardExpired への pin 不可、再 pin/unpin 可。Store 層 `pin_authenticated` は **再認証必須**（Active からでも要求、extend の非対称）、`unpin` は認証不要（安全側）。`AuthOperation::Pin` 追加、`kv.pin`/`kv.unpin` protocol + CLI、status/list に pin 残り秒。Alternatives: hard_deadline 直接ずらし案（pin の deadline 指定の方がユーザ意図に正確）/ soft だけ延長案（夜間 hard を満たさず却下）。DR-0004 authsock 移植の前提コア修正（Iteration -1）

## Archived

<!-- なし -->

## Moved to research/

<!-- なし -->

## Superseded

- [DR-0001](./DR-0001-concept.md) — cache-warden コンセプト（外部 volatile ソケットパスの安定 symlink 提供）。**Superseded by DR-0003**（コアが「セキュア KV キャッシュ」へ転換、symlink 路線は廃止）。本文は歴史記録として保持
