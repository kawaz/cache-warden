# DR-0006: プロセス検査に libc を最小依存として採用する

- Status: Active
- Date: 2026-06-10

## Context

DR-0003 / DR-0004 は KV コアの責務に「プロセス認証（プロセスツリー遡上による要求元検証）」を
含めた。iteration 3 でこの基盤——任意 pid のプロセス情報取得（実行ファイルパス / 親 pid /
開始時刻）と、自分から init/launchd 方向への祖先遡上——を実装する。

ここで OS の生のプロセス情報を読む手段が必要になる。プラットフォームごとに経路が異なる:

- **macOS**: `proc_pidpath`（実行ファイルパス）、`proc_pidinfo(PROC_PIDTBSDINFO)`（親 pid /
  開始時刻 = `pbi_start_tvsec`）。これらは libproc / sysctl 系の C API で、`/proc` は存在しない。
- **Linux**: `/proc/{pid}/exe`（実行ファイルパス）と `/proc/{pid}/stat`（親 pid = field 4 /
  開始時刻 = field 22 の starttime ticks）。starttime を秒へ正規化するには
  `sysconf(_SC_CLK_TCK)`（C API）が要る。

DR-0002 は lib crate を「依存最小（std のみ目標）」とし、DR-0005 は秘密値ゼロ化のため
`zeroize` 1 つを意図的例外として追加した。本 DR はプロセス検査のための依存を判断する。

## 前例調査（authsock-warden）

移植元の authsock-warden `src/policy/process.rs` は **libc を直接使用**しており、
追加のプロセス情報 crate（sysinfo 等）は導入していない。具体的には:

- macOS: `libc::proc_pidpath` / `libc::proc_pidinfo(PROC_PIDTBSDINFO)` で path / ppid /
  uid / gid / start_time（`pbi_start_tvsec`）を取得。`libc::sysctl(KERN_PROCARGS2)` で argv。
- Linux: `std::fs` で `/proc/{pid}/{exe,stat,status,cmdline}` を読み、`libc::sysconf(_SC_CLK_TCK)`
  で starttime を秒換算。
- ピア pid: macOS `LOCAL_PEERPID` / Linux `SO_PEERCRED`（本 DR の射程外 = デーモン層）。

実績ある前例が「libc 直叩き」を選んでおり、これを踏襲するのが自然。なお authsock-warden の
`ProcessInfo` は `serde::Serialize` を derive しているが、これは CLI 層の都合（JSON 出力）で
あり、本 DR ではコアに serde 依存を持ち込まない（DR-0002 の孫依存最小に従う）。

## Decision

プロセス検査の OS 経路に限り、`libc` crate を lib crate の依存として採用する。

- `libc = "0.2"`。利用範囲はプロセス検査の OS 実装（`process.rs` の `cfg(target_os)`
  ブロック内）に限定する。
- pub API には libc 型を露出させない（`ProcessInfo` は pid: u32 / ppid: Option<u32> /
  path: Option<PathBuf> / start_time: Option<Duration> という std 型のみで構成する）。
  これにより利用者側へ libc 依存は伝播しない（DR-0005 と同じ「pub に出さない」方針）。
- 取得する情報は最小（pid / ppid / 実行ファイルパス / 開始時刻）。uid / gid / cwd / argv は
  コアの「汎用プロセス認証」に不要なので持たない（前例は持つが、それは authsock CLI の
  表示都合。必要になればアダプタ層 or 後続 iteration で足す）。
- ピア pid 取得（`LOCAL_PEERPID` / `SO_PEERCRED`）は本 iteration のスコープ外（デーモン層の
  関心）。本 DR では追加しない。

## Alternatives Considered

- 案 A: `sysinfo` crate を使う
  - 不採用理由: sysinfo はクロスプラットフォームのプロセス / システム情報 crate だが、
    (1) 多数の孫依存（windows-sys 等を含む大きな依存ツリー）を引き込み、DR-0002 の「孫依存を
    利用者に強制しない」原則に反する。(2) 全プロセス列挙やメモリ / CPU 統計など本コアに不要な
    機能まで抱える。(3) 開始時刻の粒度や取得経路がプラットフォーム差で揺れ、pid 再利用対策に
    使う start_time の意味論を自分で制御しづらい。必要なのは「単一 pid の path / ppid /
    start_time」だけなので、libc 直叩きのほうが小さく、意味論も明確。

- 案 B: 自前で raw syscall を呼ぶ（libc を使わず `asm!` / 直接 FFI 宣言）
  - 不採用理由: macOS の `proc_pidinfo` / `proc_bsdinfo` 構造体レイアウトや
    `PROC_PIDTBSDINFO` 定数を自前宣言するのは ABI 追従の負担が大きく、誤りやすい。libc は
    これらの構造体・定数をプラットフォーム別に正しく提供しており、デファクトかつ広くレビュー
    されている。zeroize と同じく「この領域の標準を薄く使う」判断。

- 案 C: 依存ゼロを貫く（Linux は `/proc` の std::fs 読みのみ、macOS は諦める）
  - 不採用理由: Linux 単独なら `/proc` を `std::fs` で読めば libc 無しでも path / ppid は
    取れる（starttime の秒換算には `_SC_CLK_TCK` が要るので tick のまま保持する妥協は要る）。
    しかし macOS には `/proc` が無く、`proc_pidpath` / `proc_pidinfo` は C API 経由が事実上
    唯一の手段。本マシン（macOS）が最優先ターゲットである以上、依存ゼロは成立しない。
    Linux だけ libc を避けても両 OS で経路がちぐはぐになり保守が増えるため、両 OS とも
    libc に揃える。

## Consequences

- lib crate `cache-warden` は runtime 依存に `libc` を 1 つ追加する（`zeroize` に続く 2 つ目の
  意図的例外）。いずれも依存ゼロ〜極小の well-vetted crate で、孫依存最小の精神は保たれる。
- `ProcessInfo` は std 型のみで構成し、libc 型を pub に出さないため利用者への依存伝播はない。
- Linux 経路（`/proc` 読み + `sysconf`）は本マシンが macOS のため実機テスト不可。コードは
  `cfg(target_os = "linux")` で分岐し、CI（GitHub Actions = Linux）でコンパイル + テストが
  走ることで担保する。
- uid / gid / cwd / argv / ピア pid は本 DR では持たない。将来アダプタ層やデーモン層が必要と
  すれば、その時点で別途判断する。

## 関連

- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — lib 依存最小の原則（本 DR が 2 つ目の例外を追加）
- [DR-0003-secure-kv-core-and-adapters](./DR-0003-secure-kv-core-and-adapters.md) — コア責務にプロセス認証を含む
- [DR-0004-authsock-warden-succession](./DR-0004-authsock-warden-succession.md) — コア（汎用プロセス認証）/ アダプタ（ポリシー解釈）の層分け
- [DR-0005-core-security-dependencies](./DR-0005-core-security-dependencies.md) — zeroize を例外採用した先例（本 DR は同じ形式・判断軸）
- authsock-warden リポ `src/policy/process.rs` — libc 直叩きによるプロセス遡上の前例
