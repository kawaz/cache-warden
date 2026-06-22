# op discovery がデーモン startup を同期ブロックする

- status: open
- 発見: 2026-06-13 (DR-0021 のシグナル調査中に sample で観測)
- last_read: 2026-06-22T20:25:26+09:00

## 現象

`[authsock.sockets.*].keys` を持つ config で起動すると、`run()` の
`spawn_listeners` → `op_discovery::discover_keys` → `RealOpClient::item_list_json`
が **`op` CLI を同期実行してブロック**する。`op` が遅い / プロンプト待ち / ネット
待ちの間、`run()` は `wait_for_shutdown` の await 地点に到達できない。

その結果、**startup 中に来た SIGINT/SIGTERM に即応できない**。シグナルは
ブロックされ pending になり (DR-0021)、`op` discovery が返って `run()` が await に
到達するまで graceful shutdown が始まらない。

## 影響

- 停止応答性: DR-0021 の watchdog (5s) が最終的にプロセスを強制終了するので
  「停止不能」にはならない。ただし startup 中の停止応答性が `op` の所要時間に
  律速される。`op` がハングすると watchdog 発火まで (最大 `SHUTDOWN_GRACE`)
  待たされる。
- **運用上の致命症状 (2026-06-17 dogfood で観測、journal 参照)**:
  `op` 完了を `spawn_listeners` の前段で `await` しているため、`op` が永久に
  返らない場合 **listener が一切作られない**。socket file は (clean shutdown
  しなかった前回起動の残骸を除き) 作られず、client は `connect(2)` で
  `ENOENT` 相当の "No such file or directory" を受け、SSH agent 経由の
  signing が完全停止する。`op` の永久 hang は 1Password.app の force-quit /
  アップデート再起動で in-flight な op connection が EOF も SIGPIPE も
  受けないまま残る (= `op` 側 read timeout なし) ことで発生し、launchd 経由
  起動の cache-warden で再現性高く起こる (= biometric 認可路が launchd
  context に届かないため `op item list` がそもそも返ってこない)。watchdog
  は startup 完了後の SIGTERM 救済機構であって、startup 中の永久 block を
  救う設計ではない点に注意。

## 観測根拠

DR-0021 調査中、本番 config (dogfood) で起動した多数 daemon を並列 SIGTERM した際、
`sample` のスタックが全ハング daemon で
`spawn_listeners → discover_keys → RealOpClient::run` を指していた
(clean config = authsock なしでは再現しない)。

## 対応案 (未着手)

- `discover_keys` / 起動時 `op` fetch を非同期化 or `spawn_blocking` 化し、shutdown
  watch と select できるようにする。
- もしくは起動時 discovery にタイムアウトを設け、超過時は lazy discovery に
  フォールバック (鍵列挙は初回 SIGN 時に解決)。
- DR-0018 の prefetch 実装と合わせて設計するのが自然 (起動時 op アクセスの整理)。

## 関連

- DR-0021 — シグナル shutdown 処理 (本 issue を観測した調査の本体)。watchdog が
  最終防壁になっている。
- DR-0018 — 型付き source / prefetch。起動時 op アクセスの設計はこちらと一体。
- [2026-06-14-ssh-agent-provider-architecture](./2026-06-14-ssh-agent-provider-architecture.md) —
  UpstreamAgent Provider (= 1Password agent socket からの pubkey 列挙) を含む大設計。
  本 issue を「pubkey 列挙と秘密鍵 fetch の分離」で解消する方向性。
- [2026-06-17 journal: cw-discovery-block-incident](../journal/2026-06-17-cw-discovery-block-incident.md) —
  dogfood で本 issue が致命症状として発火した事故記録。`op` CLI 子に
  wall-clock timeout を被せる小修正だけ先行 land。

## 2026-06-22 追観測

DR-0022 backoff 検証のため fg daemon (= terminal 経由起動、UI session 内) と launchd daemon (= `launchctl bootstrap` 経由) を比較した結果、本 issue の症状を裏付ける観測:

- **launchd 経由起動**: `op item list timed out after 30s` で discovery 失敗、3 socket とも `0 key(s)` で serving (= 既存記述の typical 症状を 2026-06-22 にも再現確認)
- **fg 経由起動** (`/Applications/CacheWarden.app/Contents/MacOS/cache-warden daemon run` を terminal から fg 実行): 同 op item list が 7-9s で成功、6 keys discovery 完了 + TouchID UI が UI session に正常 prompt → kawaz approve で通る

= 「launchd context では biometric 認可路が UI session に届かないため op item list が永久 hang」の既存仮説 (本 issue 「## 影響」節記述) が更に強い傍証で支持される。

未解決継続。本 issue は dogfood の致命症状として open のまま。
