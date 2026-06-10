# DR-0007: 秘密値ページを mlock で常時ピン留めし、失敗は fail-open とする

- Status: Active
- Date: 2026-06-10

## Context

DR-0003 はコアの責務に「メモリ保護（mlock / zeroize による秘密値のメモリ上保護）」を挙げ、
DR-0005 はそのうち zeroize（drop / purge 時の確実なゼロ化）を先行採用した。DR-0005 は
「mlock は本 iteration ではスコープ外。将来 mlock を入れる際は `libc` 依存が必要になるが、
それは別 DR で判断する」と明記しており、本 DR がその判断にあたる。`libc` 依存自体は DR-0006
（プロセス検査）で既に lib crate に導入済みなので、追加依存は発生しない。

解決したい問題は「スワップ経由の秘密値漏洩」である。zeroize はプロセス生存中〜drop 時の
平文残留を防ぐが、OS がページをスワップ（ディスク）へ追い出すと、平文がディスク上に複製される。
スワップ上のコピーは zeroize の射程外で、プロセス終了後もディスクに残り得る。秘密値キャッシュの
根幹要件として、これを `mlock(2)` でページを物理メモリに固定し抑止する。

## Decision

`SecretBytes` 構築時に backing buffer を `mlock` でピン留めし、drop / purge 時に `munlock` →
zeroize する。以下を方針として確定する。

### 1. 常時有効（feature gate にしない）

mlock はコアの根幹要件（DR-0003）なので、feature gate で optional にせず常時有効とする。
`libc` は既に必須依存（DR-0006）であり、gate 化は条件分岐の複雑さを増やすだけで利益がない。
プラットフォーム差（`cfg(unix)` / それ以外）は内部モジュール `secret/mlock.rs` に閉じる。

### 2. fail-open（mlock 失敗で機能を壊さない）

`mlock` が失敗（`RLIMIT_MEMLOCK` 超過、権限不足、非対応プラットフォーム）しても、秘密値は
ピン留め無しで通常どおり格納・使用できる。mlock はあくまで多層防御の 1 層であり、これを
hard requirement にすると、ロック上限の小さい環境（コンテナ / 非特権環境）でキャッシュ自体が
使えなくなる。前例（authsock-warden `src/security/memory.rs`）も `mlock` 失敗を warn のみで
継続する fail-open。

検知可能性のため `SecretBytes::is_locked() -> bool` を pub API に追加し、現在ピン留めが
効いているかを利用者が問い合わせられる。これにより「黙って劣化」ではなく、アダプタ層が
degraded 状態を surface できる（self-written-rule の対極ペア: 成功時だけでなく失敗時も検知可能に）。

### 3. Vec 再確保問題への対処（不変バッファ設計）

`mlock` はアドレス範囲を固定するので、`Vec` が再確保（capacity 拡張）でバッファを別アドレスへ
移動すると、ピンは旧アドレスに残り新バッファは無防備になる。`SecretBytes` は **構築後に
バッファを伸長する API を持たない**（`push` / `extend` 無し）設計なので、この問題は構造的に
発生しない。バッファが変わるのは次の 3 箇所のみで、いずれも安全に扱う:

- 構築（`new` / `from`）: 新バッファを lock。
- `duplicate`: 新規 allocation を作り、それを独立に lock（元とは別ピン）。
- `purge`: 旧バッファを munlock → zeroize し、空 Vec（未ピン）に差し替え。

### 4. munlock のタイミング

`munlock` は **zeroize の直前**に、ピンがまだ有効な生きたバッファに対して行う（drop / purge
共通の内部ヘルパ `zeroize_buffer` に集約）。順序は「unlock → wipe」。先に unlock してから wipe
することで、「unlock 後 wipe 前」の隙間でページがスワップに追い出される窓を最小化する
（wipe 自体は即座に行われ、その後に allocation が解放される）。

### 5. 空バッファの扱い

長さ 0 の秘密値はピン対象が無い（`mlock(ptr, 0)` は no-op）。`is_locked()` が実ピンを反映する
よう、空バッファは常に `locked == false` とする。

### 6. pub API に libc 型を出さない

DR-0005 / DR-0006 と同じ方針。`mlock` / `munlock` のラッパは `secret/mlock.rs` に閉じ、
raw pointer + len を受けて `bool` を返すだけ。pub API に出るのは `is_locked() -> bool` のみで、
libc 型は一切露出しない（利用者へ依存伝播なし）。

## Alternatives Considered

- 案 A: mlock を hard requirement にする（失敗時はエラー / panic）
  - 不採用理由: `RLIMIT_MEMLOCK` の既定値は環境差が大きく（コンテナ / 非特権ユーザでは数十 KiB〜
    0 のこともある）、hard にするとキャッシュ自体が起動不能になる環境が出る。mlock は多層防御の
    1 層であり、それ単体の失敗で製品全体を止めるのは過剰。fail-open + `is_locked()` 問い合わせで
    「効いているかを知れる」ほうが実用的。

- 案 B: feature gate で optional 化する（`mlock` feature）
  - 不採用理由: `libc` は DR-0006 で既に必須依存。gate 化しても依存は減らず、ビルド構成の
    組合せと条件コンパイルの複雑さが増えるだけ。常時有効 + fail-open のほうが単純で、コアの
    根幹要件（DR-0003）とも整合する。

- 案 C: `mlockall(MCL_CURRENT|MCL_FUTURE)` でプロセス全体をロックする
  - 不採用理由: プロセス全体のロックは秘密値以外のページまで固定し、`RLIMIT_MEMLOCK` を
    急速に食い潰す。秘密値だけを範囲ロックする `mlock` のほうが影響が局所的で、ロック量も
    秘密値の総量に比例して見積もれる。

## Consequences

- `SecretBytes` は構築時に `mlock`、破棄時に `munlock` を行う。追加依存は無し（`libc` は既存）。
- pub API に `is_locked() -> bool` が増える。libc 型は露出しない。
- fail-open のため、ロック上限の小さい環境でも動作する（ただしスワップ保護は無効化される）。
  アダプタ層は `is_locked()` で degraded を検知し、必要なら利用者に通知できる。
- Linux CI（GitHub Actions）では小さな allocation が既定 `RLIMIT_MEMLOCK` 内に収まり、mlock
  成功パスがテストされる。macOS 実機でも同様。失敗パス（上限超過）は環境依存で安定再現が
  難しいため、`is_locked()` の意味論（空は false / purge 後は false）でロジックを担保する。

## 関連

- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — lib 依存最小の原則
- [DR-0003-secure-kv-core-and-adapters](./DR-0003-secure-kv-core-and-adapters.md) — コア責務にメモリ保護（mlock / zeroize）を含む
- [DR-0005-core-security-dependencies](./DR-0005-core-security-dependencies.md) — zeroize 採用。mlock は別 DR と明記（本 DR がその判断）
- [DR-0006-process-inspection-dependencies](./DR-0006-process-inspection-dependencies.md) — `libc` を既に必須依存として導入済み（本 DR は追加依存なし）
- authsock-warden リポ `src/security/memory.rs` — mlock / munlock を fail-open（warn のみ）で扱う前例
