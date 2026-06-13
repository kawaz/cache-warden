# op discovery がデーモン startup を同期ブロックする

- status: open
- 発見: 2026-06-13 (DR-0021 のシグナル調査中に sample で観測)

## 現象

`[authsock.sockets.*].keys` を持つ config で起動すると、`run()` の
`spawn_listeners` → `op_discovery::discover_keys` → `RealOpClient::item_list_json`
が **`op` CLI を同期実行してブロック**する。`op` が遅い / プロンプト待ち / ネット
待ちの間、`run()` は `wait_for_shutdown` の await 地点に到達できない。

その結果、**startup 中に来た SIGINT/SIGTERM に即応できない**。シグナルは
ブロックされ pending になり (DR-0021)、`op` discovery が返って `run()` が await に
到達するまで graceful shutdown が始まらない。

## 影響

- 実害は限定的: DR-0021 の watchdog (5s) が最終的にプロセスを強制終了するので
  「停止不能」にはならない。
- ただし startup 中の停止応答性が `op` の所要時間に律速される。`op` がハングすると
  watchdog 発火まで (最大 `SHUTDOWN_GRACE`) 待たされる。

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
