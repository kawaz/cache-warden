# DR-0019: daemon サービス登録（launchd / systemd user の統一 CLI）

- Status: Active
- Date: 2026-06-12

## Context

DR-0008 が予約した `daemon register` / `daemon unregister` / `daemon status` を実装する。
パリティ検証 (Phase 2 完了) の並走 daemon は手書き plist で launchd 常駐化したが、
これを CLI 化して macOS (launchd) / Linux (systemd) を同一インターフェースで扱えるように
する。きっかけは kawaz の「mac/linux を同じ CLI でいけるか？」— 答えは yes で、
**per-user サービスに統一**すれば launchd LaunchAgents と `systemd --user` の意味は
ほぼ 1:1 に対応する。

## Decision

### 1. CLI (両 OS 共通)

```
cache-warden daemon register [--socket PATH] [--label NAME] [--print]
cache-warden daemon unregister [--label NAME]
cache-warden daemon status
```

- `register`: サービス定義を生成して登録 + 即起動。
  - macOS: `~/Library/LaunchAgents/<label>.plist` を書き、`launchctl bootstrap gui/$UID`
    (新 API。bootout 済みなら再 bootstrap)。
  - Linux: `~/.config/systemd/user/<label>.service` を書き、
    `systemctl --user daemon-reload && systemctl --user enable --now <label>`。
  - `--print` は登録せずサービス定義をstdout に出す (監査・手動運用・dry-run 用)。
  - 既に登録済みなら**定義を更新して再起動** (冪等。バイナリパス更新の主経路)。
- `unregister`: 停止 + 登録解除 + 定義ファイル削除。未登録なら no-op (冪等)。
- `daemon status`: 登録の有無 / running か / pid / 定義ファイルパスを両 OS 共通の
  形式で表示 (DR-0008 の「プロセス・サービス登録状態 (運用向け)」)。
- デフォルト label: `com.github.kawaz.cache-warden` (macOS) /
  `cache-warden` (systemd)。`--label` で複数インスタンス (並走検証等) を併存可能。

### 2. 生成するサービス定義の内容

両 OS で同じ意味になるよう対応させる:

| 意味 | launchd | systemd user |
|---|---|---|
| 起動コマンド | `ProgramArguments` = [現バイナリの絶対パス, daemon, run, --socket?, ...] | `ExecStart=` 同 |
| 自動起動 | `RunAtLoad` | `WantedBy=default.target` |
| 再起動 | `KeepAlive` | `Restart=on-failure` |
| 環境 | `EnvironmentVariables` (CACHE_WARDEN_CONFIG が env 指定なら引き継ぐ) | `Environment=` 同 |
| ログ | `StandardOutPath/StandardErrorPath` → `~/Library/Logs/cache-warden/daemon.log` | journald (デフォルト、指定不要) |

- バイナリパスは `current_exe()` の絶対パス (authsock の内部サブコマンド解決と同じ流儀)。
- config は**パスを焼き込む**: register 時点の探索結果 (`$CACHE_WARDEN_CONFIG` > XDG >
  `~/.config`) を `CACHE_WARDEN_CONFIG` としてサービス定義に明示する。サービスの env は
  シェルと違うため、暗黙の探索に任せると「register したときと違う config で動く」事故が
  起きる。config 未存在なら焼き込まない (全デフォルト起動)。
- PATH はサービス定義に最小限を明示 (`/opt/homebrew/bin` 等、op CLI が見つかる範囲)。
  ユーザシェルの PATH 全体は持ち込まない (warden plist の轍 = セッション固有パスの混入)。

### 3. Linux 固有の注意 (register 時に hint)

`systemd --user` は **lingering なしではログアウトで停止**する。SSH agent 用途では
常駐が前提なので、register 時に `loginctl show-user --property=Linger` を確認し、
無効なら「`loginctl enable-linger` を推奨」の hint を stderr に 1 行出す
(自動では実行しない — 管理者権限が要る環境もある)。

### 4. 実装配置

- `daemon register/unregister/status` は CLI crate の daemon グループ配下。
  backend (plist 生成 / unit 生成 / launchctl / systemctl 呼び出し) は cfg 分岐。
- 非対応 OS では「unsupported platform」エラー。
- サービス管理コマンドの呼び出しは外部コマンド (`launchctl` / `systemctl`) の
  shell-out (op と同じ方針。デーモン管理 API の FFI を持ち込まない)。

## Alternatives Considered

- **system レベル (root) サービスにも対応する**
  - 不採用理由: cache-warden は per-user の秘密値を扱う製品で、ユーザ境界 (UDS 0600 +
    同一 uid) が防御の第一層。root daemon は脅威モデルが別物になる。
- **plist / unit を手書きさせる (register を実装しない)**
  - 不採用理由: パリティ検証で実際に手書きしたが、バイナリパス・config パス・ログパスの
    焼き込みは間違えやすく、Linux まで考えると二重保守になる。DR-0008 で予約済みの形。
- **launchctl load (旧 API)**
  - 不採用理由: deprecated。bootstrap/bootout の新 API が現行の正。
- **config パスを焼き込まず暗黙探索に任せる**
  - 不採用理由: サービス環境はシェルと env が違うため、「register したときと違う config
    で動く」フットガンになる。明示焼き込みが一目で監査できる。

## Consequences

- `daemon` グループの help に register / unregister / status が現れる (DR-0008 の
  「未実装のうちは出さない」状態が解消)。補完も更新。
- 並走検証の手書き plist (`com.github.kawaz.cache-warden-parity`) は register の
  `--label` + `CACHE_WARDEN_CONFIG` で置き換え可能になる。
- Homebrew 配布後は `brew services` との関係を案内する必要が出るかもしれない (将来)。

## 関連

- [DR-0008-single-daemon-hosting](./DR-0008-single-daemon-hosting.md) — register/unregister の予約元
- [docs/journal/2026-06-12-parity-phase2.md](../journal/2026-06-12-parity-phase2.md) — 手書き plist による常駐化 (本 DR が置換)
