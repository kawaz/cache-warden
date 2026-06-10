# DR-0005: コアの秘密値ゼロ化に zeroize crate を例外採用する

- Status: Active
- Date: 2026-06-10

## Context

DR-0002 は lib crate `cache-warden` を「依存最小（std のみ目標）」と定めている。
これはライブラリ利用者に孫依存を強制しないための原則である。

一方 DR-0003 はコアの責務に「メモリ保護（mlock / zeroize による秘密値のメモリ上保護）」を
含めた。iteration 1 で実装する秘密値保持型 `SecretBytes` は、drop 時および hard TTL 切れ時に
確実に平文をゼロ化する必要がある。

ここで問題になるのが「確実なゼロ化」の難しさである。素朴に `for b in &mut buf { *b = 0 }` や
`buf.clear()` と書いても、コンパイラは「以後読まれないメモリへの書き込み」を dead store と
判定して最適化で消し去ってよい（Rust/LLVM の最適化はこれを許す）。つまりゼロ化コードが
バイナリから消え、秘密値がメモリに残り得る。これを防ぐには volatile write + compiler fence /
最適化バリアを正しく組む必要があり、ターゲット ABI ごとの落とし穴も多い。自作は誤りやすく、
誤っても表面上は動いてしまうため検知も困難である。

## Decision

秘密値の確実なゼロ化に限り、`zeroize` crate を lib crate の例外依存として採用する。

- `zeroize = "1"`（採用時点の最新は 1.8.2、stable Rust のみで動作）。
- 利用範囲は `SecretBytes`（および将来の秘密値保持型）の内部実装に限定する。`Zeroize` /
  `ZeroizeOnDrop` を内部で用い、pub API には zeroize 型を露出させない（孫依存の伝播を避ける）。
- `zeroize_derive` feature は使わず、手書きで drop / zeroize を実装する（依存と
  proc-macro コンパイルコストを最小化するため）。
- mlock は本 iteration ではスコープ外。将来 mlock を入れる際は `libc` 依存が必要になるが、
  それは別 DR で判断する（feature gate での optional 化を想定）。
- これ以外の新規依存（ランタイム / dev-dependency とも）は追加しない。テストも std と
  既存 dev-dependency（tempfile）の範囲で書く。

## Alternatives Considered

- 案 A: 自作の volatile write でゼロ化する
  - 不採用理由: `core::ptr::write_volatile` + `core::sync::atomic::compiler_fence` を
    正しく組めば原理上は可能だが、(1) 最適化に消されない保証をターゲットごとに検証する負担、
    (2) `Vec` 再確保時に古いバッファが残る問題（capacity 変更で旧領域がコピー後放置される）、
    (3) panic 経路でのゼロ化漏れ、など正しく作るのが難しい。誤ってもテストで検知しづらく、
    秘密値漏洩という影響の大きさに対して自作のリスクが見合わない。zeroize はまさにこの領域の
    デファクトであり、小型で広くレビューされている（well-vetted）。

- 案 B: `secrecy` crate を使う
  - 不採用理由: `secrecy` は `SecretBox` 等の高レベルラッパを提供するが、内部で zeroize に
    依存しており、こちらが欲しい「最小の確実なゼロ化プリミティブ」より抽象が一段高い。
    redact 表示・expose アクセサ・command/static の再生成可否などコア固有の API は自前で
    設計したいので、土台は zeroize の薄いプリミティブだけにとどめる方が制御しやすい。

- 案 C: 依存ゼロを貫き、ゼロ化を諦める（ベストエフォートの clear のみ）
  - 不採用理由: DR-0003 がメモリ保護をコアの責務に挙げている。秘密値キャッシュという製品の
    根幹なので、「最適化で消えるかもしれない clear」では責務を果たせない。

## Consequences

- lib crate `cache-warden` は「std のみ目標」から逸脱し、`zeroize` 1 つを runtime 依存に持つ。
  これは秘密値ドメインの根幹要件（確実なゼロ化）に対する意図的な例外であり、DR-0002 の原則を
  覆すものではない（孫依存最小の精神は維持: zeroize は依存ゼロの小型 crate）。
- 将来 mlock / anti-debug を入れる際の追加依存（libc 等）は本 DR の射程外。都度 DR で判断する。
- pub API に zeroize 型を出さないため、利用者側に zeroize への依存は伝播しない。

## 関連

- [DR-0002-workspace-structure](./DR-0002-workspace-structure.md) — lib 依存最小の原則（本 DR が例外を 1 つ追加）
- [DR-0003-secure-kv-core-and-adapters](./DR-0003-secure-kv-core-and-adapters.md) — コア責務にメモリ保護（zeroize）を含む
- authsock-warden リポ `src/keystore/secret.rs` — zeroize による秘密値保持の前例
