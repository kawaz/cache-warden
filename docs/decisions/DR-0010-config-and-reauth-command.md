# DR-0010: TOML config と再認証コマンド方式

- Status: Active
- Date: 2026-06-10

## Context

DR-0009 で control socket プロトコル v1 とデーモン骨格（iteration 5）を確定した。
その時点では再認証境界に `AllowAll` を暫定配線し（TouchID は将来 iteration）、
デーモンの設定手段（socket パス・再認証手段・起動時に投入するエントリ）はまだ無く、
`--socket` 引数とコード上のデフォルトだけで動いていた。

本 DR（iteration 6）は次の 2 点を確定する:

1. **実 Authenticator** をどう実装するか（`AllowAll` の置き換え）。
2. **TOML config** のスキーマ・探索順・優先順位。

後継元 authsock-warden は同じ問いに DR-009 で「再認証手段は **re-auth command を
優先実装**（外部スクリプトに委譲。exit 0 = 承認）」と答え、TOML config
（`#[serde(deny_unknown_fields)]`、`$XDG_CONFIG_HOME` 探索、env override）を実装済み。
本 DR はその判断・構造を cache-warden に踏襲する。

DR-0002 はライブラリ（`cache-warden`）の依存を最小に保つ方針。config パーサ（toml crate）
は CLI crate に閉じ、ライブラリには持ち込まない。一方 `Authenticator` 実装はコアの提供物
（trait と同じ層、warden の re-auth command 前例と同じ立ち位置）なので、`CommandAuthenticator`
はライブラリに置く（依存追加なし — `std::process` のみ）。

## Decision

### 実 Authenticator = 再認証コマンド方式（warden DR-009 踏襲）

ライブラリ `auth.rs` に `CommandAuthenticator` を追加する。設定された argv（program 先頭）を
実行し、その exit status を判定に使う:

- exit 0 → **承認**（`Ok(())`）。
- 非ゼロ exit / シグナル kill → **拒否**（`AuthError::Denied`）。
- spawn 自体に失敗（program が無い等）→ **利用不能**（`AuthError::Unavailable`）。

コマンドには `AuthContext` の情報を環境変数で渡す（**秘密値は渡さない**）:

- `CACHE_WARDEN_AUTH_KEY` — 対象キー名。
- `CACHE_WARDEN_AUTH_OPERATION` — `extend` / `regenerate` / `pin`（`pin` は DR-0011 で追加）。
- `CACHE_WARDEN_AUTH_REQUESTER` — requester の祖先チェーンを `pid:name <- pid:name`
  表記で（`AuthContext::requester` がある場合のみ。immediate requester が先頭）。

コマンドの stdin/stdout/stderr は `Stdio::null` に接続する（プロンプト UI はコマンド側の
責務 — osascript / TouchID CLI / push 通知等。デーモンの stream を汚さない）。
**timeout は設けない**: ユーザ入力待ちが正常系であり、bound するとまさに依存する対話を
殺す（`CommandRunner` の default-unlimited と一貫）。

ビルトイン TouchID（LocalAuthentication）は将来 iteration のまま据え置く。`Authenticator`
trait の別実装として `CommandAuthenticator` の隣に差し込める形になっている。

### TOML config（CLI crate）

形式は TOML、全テーブルに `#[serde(deny_unknown_fields)]`（warden 踏襲）。
toml crate は CLI 側にのみ追加（ライブラリは依存最小を維持）。

探索順（高優先順位が先）:

1. `$CACHE_WARDEN_CONFIG`（env override、verbatim）
2. `$XDG_CONFIG_HOME/cache-warden/config.toml`
3. `~/.config/cache-warden/config.toml`

config 無しでも起動可能（全フィールドにデフォルトあり）。

スキーマ v1:

```toml
[daemon]
socket = "~/.local/state/cache-warden/control.sock"  # 省略時デフォルト。CLI --socket が最優先

[auth]
command = ["/path/to/reauth-prompt"]  # 省略時は AllowAll（再認証なし）

[kv.DB_PASSWORD]                       # 起動時プリロードするエントリ
command = ["op", "read", "op://vault/item/password"]
soft-ttl = "1h"
hard-ttl = "24h"
```

> **[後続改訂]** config スキーマはその後 DR-0018 §1/§3 で改訂された:
> `[kv.*]` は `source = "command"` + `command.argv` 形式（bare 配列 `command = [...]` は廃止）、
> `[auth]` は `type` フィールドが必須（`type = "command"` + `command`）。
> 現行スキーマの詳細は `crates/cache-warden-cli/src/config.rs` を正とする。

#### static エントリを config に書けない設計（平文秘密値の流出防止）

`[kv.*]` は **`command` ソースのみ**許可する。リテラル値を config に書く手段は無い:
`value` / `value-stdin` / `static` キーを書いたら **設定エラー**にする。

理由: config に平文の秘密値を書くと dotfiles リポ・バックアップ・`cat` 可能なパスに
平文が残り、これはまさにキャッシュが防ごうとしている漏洩である。リテラル値は実行時に
`cache-warden kv set --value-stdin` で投入し、config には永続化しない。

#### auth 省略時 = AllowAll

`[auth].command` が無ければ `AllowAll` を配線する（soft 期限切れの延長・command の再生成が
プロンプトなしで通る = 「このホストは信頼するから速くキャッシュだけしたい」設定）。
`[auth].command` を設定すると全 TTL ゲート解錠時に再認証を要求する。

#### 起動時プリロード

`[kv.*]` の command エントリをデーモン起動時に実行してキャッシュに投入する（最初の get を
ヒットにする）。失敗（spawn エラー・非ゼロ exit・TTL 不整合）は **fatal ではない**:
デーモンは起動を継続し、stderr に 1 行警告（値は含めない）を出し、当該エントリは未登録のまま
（後から `kv set` 可能）。上流が一時的に落ちていてもデーモンは上がるべき、という方針。

#### 優先順位

socket パスの解決順: **CLI `--socket` > `[daemon].socket` > 組込みデフォルト**
（`$XDG_STATE_HOME/...`）。`config show` / `config path` / `config edit` を追加する。
`config show` は有効 config を表示するが、config は構造上秘密値を持てないので redact 不要。

## Alternatives Considered

- 案 A: ビルトイン TouchID（LocalAuthentication）を先行実装する
  - 不採用理由: プラットフォーム依存で、`security-framework` / `objc2` のどちらを使うかが
    未決（authsock-warden DR-018 でも未決）。再認証コマンド方式なら同じユースケース
    （ローカル TouchID・リモート passkey・push 通知）を外部委譲で全てカバーでき、実装コストが
    最小。TouchID はその command のラッパーとして後からビルトイン化でき、互換も保てる。

- 案 B: config に static の値（リテラル秘密値）を書けるようにする
  - 不採用理由: 平文秘密値が config ファイルに残り、dotfiles・バックアップ・`cat` 経由で
    漏洩する。キャッシュの存在意義に反するので、構造的に禁止する（書いたら設定エラー）。

- 案 C: config 無しを fatal にする（config 必須）
  - 不採用理由: 全フィールドにデフォルトがあり、config 無しでも有意に動く（`kv set` で
    実行時に投入できる）。必須化は導入障壁を上げるだけ。

## Consequences

- 再認証境界が config 駆動になる: `[auth].command` 設定時は `CommandAuthenticator`、
  未設定時は `AllowAll`。デーモンは起動時に 1 度だけ Authenticator を構築し、全リクエストで
  共有する（`server::run_request` の配線が DR-0009 の `AllowAll` ハードコードから差し替わった）。
- `CommandAuthenticator` はライブラリの提供物として `auth.rs` に入り、依存は増えない
  （`std::process` のみ）。trait object（`&dyn Authenticator`）で配線するため、
  `Store::extend_authenticated` / `Store::regenerate` の auth 引数を
  `&(impl Authenticator + ?Sized)` に緩和した（依存追加なし、trait object を受けられる）。
- config スキーマ v1 が確定し、起動時プリロードと socket 優先順位が入る。toml crate は
  CLI 側のみ。ライブラリの依存最小（DR-0002）は維持。
- DESIGN（ja/en）の open question「TouchID 実装方式（security-framework / objc2）」は
  「**ビルトイン化する iteration で決める**」へ更新（現フェーズでは再認証コマンドで充足）。
  config 節を DESIGN に追加し、再認証配線の記述を「AllowAll 暫定」から「config 由来」へ同期。
- 副次的に、デーモンが `SystemClock` をリクエストごとに作り直していた欠陥
  （毎回 base を now に rebase し TTL 評価が無効化されていた）を、プロセス生存中
  1 個の clock を共有する形に修正した（プリロード導入で TTL が初めて実際に効くようになり表面化）。

## 関連

- [DR-0009-control-socket-protocol-v1](./DR-0009-control-socket-protocol-v1.md) — 本 DR が置き換える `AllowAll` 暫定配線・CLI 体系を確定した DR
- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — lib 依存最小 / serde・toml は CLI 側（CommandAuthenticator を lib に置く根拠との対比）
- [DR-0005-core-security-dependencies](./DR-0005-core-security-dependencies.md) — 秘密値保護の方針（config に平文を書かせない判断と整合）
- authsock-warden リポ `docs/decisions/DR-009-auth-method-command-first.md` — 再認証コマンド優先の前例（本 DR が踏襲）
