# DR-0013: secret reference 注入（`run` / `inject`）

- Status: Active
- Date: 2026-06-11

## Context

`cache-warden kv get` で値を 1 つずつ取り出せるが、実用では「複数の秘密値を環境変数として
子プロセスに渡したい」（op run 相当）「設定ファイルのテンプレート中の参照を実値に展開したい」
（op inject 相当）の 2 形態が日常の主経路になる。CLI 再構成（`run` → `daemon run`、2026-06-11）で
トップレベル `run` をこの用途のために空けてあり、DESIGN-ja の「将来検討」と
issue（2026-06-11-secret-reference-injection）で構想だけが起票されていた。

本 DR は参照構文 / 解決経路 / 注入経路の安全性 / `run` と `inject` の責務分担を確定する。
authsock アダプタ・認証コアとは独立で、control socket のクライアント（DR-0009）として完結する。

## Decision

### 参照構文: `cache-warden://KEY`

- スキームは `cache-warden://` の 1 種のみ。短縮形（`cw://` 等）のエイリアスは設けない
  （正規表記を 1 つに保つ。CLI 設計方針「エイリアスを指示なく増やさない」と整合）。
- 参照可能な KEY は `[A-Za-z0-9_][A-Za-z0-9_.-]*`（先頭は英数字または `_`）。
  コアの KV キー自体は任意文字列だが、**この文字種の外にあるキーは参照構文では指せない**
  （テンプレート中で参照の終端を曖昧さなく決めるための制約。env 変数風の命名なら全部入る）。
- 解決は単一パス。解決後の値の中に参照が含まれていても再帰展開しない
  （秘密値はバイト列として verbatim に扱う。展開爆発・意図しない二次展開を構造的に排除）。
- エスケープ構文は v1 では持たない（リテラルに `cache-warden://KEY` という文字列を出力したい
  ケースは想定薄。必要になったら追加を検討）。

### 解決経路: control socket クライアント（既存 `kv.get`）

- `run` / `inject` は既存の同期クライアント（`round_trip`）で `kv.get` を叩く。
  デーモン側の再認証（SoftExpired → extend）・再生成（HardExpired + command）は
  DR-0009 / DR-0011 のステートマシンがそのまま効く。
- peer 認証も既存どおり: requester は `run` / `inject` プロセスの祖先チェーンとして
  デーモンに渡る（再認証プロンプトの帰属が呼び出し元に正しく紐づく）。
- 同一 KEY が複数回参照されても **解決は 1 回**（dedup）。複数 KEY の TouchID 連打を増やさない。
- **fail-closed**: 1 つでも解決に失敗（not_found / auth_failed / not_regenerable / 接続不能）
  したら、子プロセス起動・出力生成を一切行わず非ゼロ終了する。
  「参照が一部未解決のまま走る / 出る」状態を作らない。

### `cache-warden run` — env 注入 + exec（op run 相当）

```
cache-warden run [--socket PATH] [--env NAME=VALUE]... -- CMD [ARGS...]
```

- **env のみが注入面**。継承環境変数と `--env` 指定のうち、値が**全体一致**で
  `cache-warden://KEY` であるものだけを解決して置換する（op run と同じ whole-value 規則。
  値の一部に参照を埋め込む部分置換は env では行わない — 合成が必要なら `inject` を使う）。
- `--env NAME=VALUE` は子プロセスの env を追加/上書きする（値が参照なら解決、リテラルなら
  そのまま）。シェルに参照を export せず one-shot で渡したいケース向け。継承 env より優先。
- **argv は注入面にしない**。子プロセスの argv は `ps` で他ユーザからも見えるため、
  argv への秘密値置換は構造的な漏洩になる。ARGS 中に参照らしき文字列を検出したら
  stderr に 1 行警告（「argv は置換しない、env を使え」）を出した上で **verbatim に渡す**
  （子プロセス自身が解決する正当な使い方を壊さない）。
- 解決完了後は **`exec`（`CommandExt::exec`）でプロセスイメージを置換**する。
  親プロセスが残らないので、解決済み秘密値を抱えたまま生き続けるプロセスがいない。
  シグナル・exit code・TTY の扱いも自然に子へ引き継がれる。
  exec 失敗時はシェル慣習に合わせ、not found = 127 / 実行不能 = 126 で終了する。
- 値に NUL（`\0`）を含む秘密値は env に載せられないためエラー（env の構造的制約）。

### `cache-warden inject` — テンプレート置換（op inject 相当）

```
cache-warden inject [--socket PATH] [--in FILE] [--out FILE]
```

- 既定は stdin → stdout。`--in` / `--out` でファイル指定。
- テンプレート中の参照を**部分文字列として**全て実値に置換する（こちらは env と違い
  埋め込み合成が目的なので substring 置換）。バイト列として処理し、バイナリ安全。
- 全参照の解決が完了してから出力を書き始める（fail-closed: 部分出力を残さない）。
- `--out FILE` は **0600 で作成**する（umask に依存しない。秘密値を含むファイルを
  グループ/他者可読で生まない）。

### `run` / `inject` の責務分担と実装配置

| | `run` | `inject` |
|---|---|---|
| 注入面 | env（whole-value のみ） | テキストストリーム（substring） |
| 出口 | exec で子プロセスに変身 | stdout / 0600 ファイル |
| 用途 | コマンド実行時の env 供給 | 設定ファイル・テンプレの展開 |

- 参照の検出・解決・dedup は共有モジュール（CLI crate 内 `refs`）に置き、両コマンドが使う。
- 実装はすべて `cache-warden-cli` crate に閉じる（コア / authsock crate の変更なし。
  DR-0002 の依存方針どおり）。
- クライアント側に滞留する解決済み値は使用後に best-effort で zeroize する。
  client 側 mlock はしない（短命プロセスであり、値は直後に子 env / 出力ファイルへ
  出て行くため、クライアント側ピン留めに実益がない）。

## Alternatives Considered

- **argv への置換も許す**（issue 起票時の構想に含まれていた）
  - 不採用理由: 子プロセスの argv は `ps` / `/proc/PID/cmdline` で**他ユーザからも**見える。
    mlock / zeroize / プロセス認証で守ってきた値を world-readable 面に出すことになり、
    本末転倒。env は同一 uid にしか見えず（`/proc/PID/environ` は owner のみ）、
    op run も同じ判断で env のみを注入面にしている。
- **op run 同様の出力マスキング**（子プロセスの stdout/stderr 中の秘密値を伏せる）
  - v1 不採用理由: マスキングには親が常駐して子の出力をパイプ経由で仲介する必要があり、
    「exec で秘密値保持プロセスを残さない」設計と両立しない。マスキング自体も
    ヒューリスティック（エンコード・分割出力で容易にすり抜ける）で防御強度は低い。
    必要性が実証されたら opt-in（`--mask`、常駐型に切替）として再検討する。
- **env 値の部分置換**（`DSN=postgres://u:cache-warden://PW@h` のような埋め込み）
  - 不採用理由: whole-value 規則（op run 互換）の方が「この env は秘密参照である」が
    機械的に判定でき、誤検出がない。合成が必要なユースケースは `inject` が担う
    （責務分担を崩さない）。
- **短縮スキーム `cw://` の併設**
  - 不採用理由: 正規表記が 2 つになると grep / 監査 / ドキュメントが割れる。
    長さが問題になる場面は shell alias で各自解決できる。
- **`--env-file`（.env 読み込み）**
  - v1 では見送り（将来検討）。`--env` の反復と継承 env で当面足りる。quoting / 展開規則
    など .env 方言の互換問題を v1 に持ち込まない。

## Consequences

- DESIGN-ja / DESIGN の「将来検討」にあったトップレベル `run` 構想が設計確定となる。
  実装後に DESIGN の本文（CLI サブコマンド体系）へ反映する。
- CLI サブコマンドに `run` / `inject` が加わる。help / 補完の更新が実装タスクに含まれる。
- 参照可能キーに文字種制約が生まれる（コアは任意キーのまま）。env 変数風の命名を外れた
  キーを参照したい場合は `kv get` で個別取得する逃げ道が残る。
- 出力マスキングを持たないため、子プロセスが秘密値を標準出力に echo する事故は防げない
  （op run との明示的な差異。利用者向けドキュメントに記載する）。
- 解決は control socket 経由のため、デーモン未起動時は明確なエラーで失敗する
  （既存 `kv get` と同じ挙動・同じメッセージ系）。

## 関連

- [DR-0009-control-socket-protocol-v1](./DR-0009-control-socket-protocol-v1.md) — 解決経路（`kv.get` / peer 認証 / 再認証・再生成の委譲先）
- [DR-0011-ttl-base-separation-and-pin](./DR-0011-ttl-base-separation-and-pin.md) — 解決時の TTL ステートマシン（extend / regenerate）
- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — 実装を CLI crate に閉じる根拠
- [docs/issue/2026-06-11-secret-reference-injection.md](../issue/2026-06-11-secret-reference-injection.md) — 起票 issue
