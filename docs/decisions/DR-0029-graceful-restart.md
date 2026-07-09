# DR-0029: graceful restart — kv 秘密状態を引き継ぐ無 storm 再起動

- Status: Accepted (2026-07-09 kawaz 承認。fail-safe の cold start 退化は「悪化ではない」として許容)
- Date: 2026-07-09
- 関連: issue `2026-06-14-graceful-restart-state-handoff` (動機と secure handoff 大枠合意) /
  DR-0021 (signal/shutdown、本 DR はその次段) / DR-0019 (launchd 登録) /
  DR-0020 (codesign / .app / TCC) / DR-0007 (mlock / PT_DENY_ATTACH) /
  issue `2026-06-14-ssh-agent-provider-architecture` (handoff 対象の整理で参照)

## Context

daemon の再起動は in-memory cache (SecretBytes / TTL / pin / auth / backoff 状態) を
全消しし、全エントリが op TouchID サイクルへ引き戻される (storm)。cache-warden の
存在意義 = 「op の硬直的な TouchID サイクルから独立して per-item に auth サイクルを
制御する」なので、再 fetch = 存在意義の放棄に等しい (issue「動機」節)。

再起動が発生する契機は binary 入れ替え (brew upgrade) に限らない:

| 契機 | 現状の帰結 |
|---|---|
| brew upgrade (binary 入れ替え) | 再起動 → storm。リリースウェーブのたびに実害観測済み |
| config 変更の反映 | **config reload 機構は現存しない** (authsock keyfile filter の内部 reload のみ)。反映手段が再起動しかなく、同じ storm |
| 手動再起動 (トラブル対処等) | 同上 |

secure handoff の大枠 (旧プロセス主導 / 匿名 socketpair / 後継バイナリ検証 /
メモリ衛生 / 二相コミット) は issue §2 で 2026-06-14 に合意済み。本 DR はその上で
**未決 4 点を確定**する: (a) launchd 統合、(b) handoff wire format、(c) 二相コミット
プロトコル、(d) 接続中クライアントの drain。

### 新事実: launchd `KeepAlive=true` と「旧主導 fork+exec → 旧 exit」の衝突

plist は `KeepAlive=true` (service.rs、DR-0019)。issue §2-1 の合意案
(nginx 型: 旧が新 daemon を fork+exec し、二相コミット後に旧が exit) をそのまま
実行すると:

1. 旧 (launchd 管理下の PID) が exit → launchd が異常終了とみなし**別インスタンスを respawn**
2. respawn されたインスタンスは後継が bind 済みの socket と衝突 → bind 失敗 → exit
3. KeepAlive が再 respawn → **crash loop**。後継は launchd 管理外の孤児

= §2-1 は launchd 常駐という前提と両立しない。設計の組み直しが必要 (§2 の他の
合意要素は保てる。下記「方式」参照)。

## Decision (提案)

### 1. 方式: 同一 PID exec + state-holder child (案 C)

```
launchd 管理下の daemon (PID=P, 旧バイナリ)
  │ ① trigger 受信 (control socket: RestartGraceful)
  │ ② accept 停止 → in-flight drain (deadline 5s) →
  │    全 listener fd を close + socket path を unlink   ← fd 衛生 (後述)
  │ ③ 全 handoff 状態を 1 つの mlock buffer へ事前直列化 (§2)
  │ ④ socketpair(AF_UNIX) 生成。fork/exec 前に親側で仕込みを完了:
  │    - 新プロセス側 end: CLOEXEC を外す (exec を跨いで継承)
  │    - 両 end に SO_RCVTIMEO 設定 (holder/new 双方の read timeout を
  │      poll/select なしで実現)
  │    - SIGPIPE を SIG_IGN (disposition は fork/exec を跨いで継承され、
  │      holder の write が EPIPE エラーとして返る = zeroize 経路を飛ばさない)
  │ ⑤ fork() ──────────────► state-holder child (PID=C)
  │                             fork 直後に (全て async-signal-safe syscall):
  │                             1. ptrace(PT_DENY_ATTACH) (DR-0007 と同じ防御、必須)
  │                             2. mlock(buffer) 再適用 (Linux は memory lock を
  │                                fork で継承しない (mlock(2))。macOS も継承を
  │                                前提にせず無条件に再適用)
  │                             3. 自分の socketpair end 以外の fd を全 close
  │                                (belt-and-suspenders; ② で listener は閉鎖済)
  │                             以降は write / read / explicit_bzero / _exit のみ
  │ ⑥ exec 対象を検証 (§3: 起動時記録の自パス固定 + 署名の自己一致) → execve
  ▼
launchd 管理下の daemon (PID=P のまま, 新バイナリ)
  │ ⑦ 継承 fd (env `CACHE_WARDEN_HANDOFF_FD` で番号通知) から state を受領 (§2)
  │ ⑧ 全受領 (entry_count 分読了) + mlock + listener bind + serve 開始
  │    → socketpair へ COMMIT 送信 (§5)
  ▼                                 └► holder: buffer zeroize → _exit(0)
  通常 serve 継続
```

採用理由 (案 A/B との比較は「検討した代替案」):

- **launchd と一切対話しない**: PID が変わらないので launchd から見えるのは
  「同じ job が動き続けている」だけ。KeepAlive / ExitTimeOut / respawn の
  レースが構造的に存在しない
- **合意済み §2-2 (匿名 socketpair = 構造的 private channel) を保てる**:
  パス名を持たない fd 継承チャネルなので第三者の connect / なりすましが不可能。
  peer 認証機構が不要
- **endpoint fd 継承 (issue 層 1) は将来オプション**: MVP は ② で close →
  新プロセスが re-bind (§6)。全クライアントが per-request 接続なので数百 ms の
  断は実用上無害。listening fd 継承は wire format を変えず追加可能
- **TCC の連続性**: 標準登録経路 (.app + `AssociatedBundleIdentifiers`、DR-0020)
  では TCC は Bundle ID ベースで、同一パスの execve は同一性を乱さない。
  bare binary 登録 (dev 用) は元々パスベース TCC であり、パスが同一なので
  現状より悪化はしないが、**連続性の保証は .app 経路に限る** (DR-0020 の
  制約のまま。過大主張しない)

#### fork 安全性 (multithreaded tokio プロセスでの fork)

fork() は multithreaded プロセスでは child 側で async-signal-safe な操作しか
保証されない (他スレッドが握っていた lock が凍結されるため malloc 等は deadlock
リスク)。対策を設計で吸収する:

- **holder の全操作を async-signal-safe syscall に限定**: `ptrace` / `mlock` /
  `close` / `read` / `write` / `explicit_bzero` (メモリ書き潰し) / `_exit`。
  timeout は **fork 前に親が設定した SO_RCVTIMEO** で実現するため、poll/select/
  alarm 等を child で呼ぶ必要がない
- 直列化 (= malloc を伴う) は **fork 前に親側で完了** (③)。child は既成の
  buffer を fd に流すだけ
- **シグナル**: holder は DR-0021 のマスク (SIGINT/SIGTERM block) を継承する。
  これは意図的にそのままにする (転送中に TERM で殺されて秘密が漏れる/失われる
  事故を防ぐ)。holder の生存時間は SO_RCVTIMEO により **必ず有界** (最悪
  send timeout + COMMIT timeout で ~90s)。SIGKILL はいつでも効く (その場合
  zeroize は走らないが、mlock 済みページは kernel が解放時に他プロセスへ
  ゼロ埋めなしで渡すことはない — 下記メモリ表)
- tokio runtime / 他スレッドの状態には一切触れない。親は fork 直後に execve
  するので親側の post-fork 制約はない

#### fd 衛生 (codex 指摘: fail-safe の成立条件)

fork は open fd を全て複製し、CLOEXEC は exec しない holder には無力。holder が
listener fd を握ったままだと、新プロセスの re-bind が「既存 socket が生きている」
double-start guard (server.rs `bind_control_socket`) に阻まれ、cold start すら
holder timeout まで遅延する。よって **listener の close + unlink は fork より前
(②) に親が完了させる**ことを必須とし、holder 側の全 close (⑤-3) は二重の保険と
位置付ける。

### 2. handoff wire format (詰めどころ b)

- socketpair 上の stream。フレーミングを明示定義する:

```
header  = magic(8B) + format_version(u32) + entry_count(u32)
entry   = len(u32) + payload(len B)          × entry_count 回
COMMIT  = 1 frame (new → holder、全受領 + bind 完了後)
```

- **受領完了の判定 = entry_count 個の entry を読み切ること** (EOF 終端に
  依存しない)。途中 EOF / len 不整合 / read timeout は ABORT (§5)
- 新バイナリが format_version を解釈できない場合は即 ABORT (互換保証は
  「新は旧 version を読める」方向のみ)
- entry payload は serde バイナリ (candidate: `postcard`。依存追加を避けるなら
  serde_json でも可 — どちらも mlock buffer 内で安全性同等、**実装時に選ぶ**)
- 1 entry = `key (NS/KEY)` + `secret bytes` + `Ttl 状態 (loaded_at/extended_at を
  wall clock 絶対時刻で運び、受領側で monotonic 基準へ再アンカー)` + `pin 状態` +
  `FailureRecord (backoff)` + `ValueMeta` + `Definition (ValueSource)` +
  **per-entry アクセス制約 record** (下記)
- **per-entry アクセス制約は引き継ぎ必須**: 「set 実行元プロセスの子孫のみ get 可」
  のような set 時に記録される制約 (現行の process policy 状態、将来の
  kv-get-peer-identity-guard record) はエントリに付随する動的状態であり、落とすと
  fail-closed なら該当エントリが誰からも読めずキャッシュとして死に、fail-open なら
  機密性の約束が restart で silently 解除される — どちらも不可。identity record
  (PID + proc_uniqueid 等) は daemon restart がクライアントを殺さない以上
  restart 後も有効な参照なので、record をバイト列のまま直列化して運び、新プロセス
  で同一に評価する。config 由来の `kv_process_policies` は config 再読込で再構築
  されるため運ばない (動的 record と静的 config の線引き)
- 対象は **kv 全エントリ** (op:// / static / command 由来を問わない。issue の
  「source 種別で絞れるという当初観察は誤り」の結論に従う)。公開鍵 registry は
  非秘密なので運ばず新側で再構築。upstream proxy は状態を持たず対象外

### 3. exec 対象の検証 (詰めどころ a の一部、§2-3 の macOS 適合)

- **exec するパスは「起動時に記録した自身の実行パス (current_exe)」に固定**する。
  plist の再読みや PATH 探索はしない — 「稼働中バイナリと同一パス」を検証項目
  ではなく構造で保証する (brew upgrade はパス据え置きで実体を入れ替えるため、
  同一パスの exec が新バイナリを正しく拾う。plist 改変で別パスへ誘導される
  経路も同時に塞がる)。パスが消えている場合は中止
- **署名は自己一致検証**: 候補バイナリの codesign identity (TeamID + signing
  identifier) が**実行中の自分自身のものと一致**することを要求する。期待値の
  ハードコードや設定より強く、「署名済み upgrade を信頼するなら後継も信頼」
  (issue §2 の trust 整理) をそのまま機械化した形。判定は fail-closed:
  - 自分が署名済み → 候補も同一 identity 必須。不一致 / 未署名は中止
  - 自分が未署名 (dev build) → identity 比較は不能。owner (自 uid) +
    非 world-writable + 同一パスのみ確認し、**警告を出して続行** (DR-0019 §2.5
    の「開発をブロックしない」と同じ倒し方。dev 経路のリスクは開発者自身に
    閉じる)
- macOS に fexecve は無いため「open した fd を検証してそのまま exec」は不可。
  検証 → execve の TOCTOU は残るが、**macOS はカーネルが exec 時に codesign を
  再強制**するため bounded (issue §2-3 の許容判断のまま)。Linux は codesign が
  無いため owner/perms + 同一パス (+将来 hash pin) で代替
- 検証失敗時は handoff を中止して現行プロセスが serve 継続 (listener close 前に
  検証を行う順序にすれば完全無害。実装では ① 直後 = ② の前に検証する)

### 4. drain (詰めどころ d)

現行の全クライアントは per-request 接続 (authsock は 1 request/conn、control は
短命 round_trip、upstream 転送は request 毎接続)。よって:

- accept を止め、**in-flight request の完了を短い deadline (例 5s) で待つ**だけ
- deadline 超過分は切断してよい (クライアントは ssh/git の retry 単位で回復)
- 長寿命接続の「引き継ぎ」は不要 — issue 詰めどころ (a) はこれで閉じる

### 5. 二相コミット (詰めどころ c) — ABORT / timeout / SIGPIPE 込みの全経路

| 事象 | holder の挙動 | new の挙動 | 帰結 |
|---|---|---|---|
| 正常 | state 送信 → COMMIT 待ち (read, SO_RCVTIMEO=60s) → 受信 | 全受領 → mlock → bind → serve → COMMIT 送信 | zeroize → `_exit(0)`。無 storm 達成 |
| new が version 非対応 / パース失敗 | write 継続中に EPIPE (SIGPIPE は IGN 済) or COMMIT read が EOF | 自分の end を close (= ABORT 通知) → cold start で serve 継続 | holder: zeroize → `_exit(2)` |
| new が受領中に crash | 同上 (EPIPE / EOF) | launchd KeepAlive が respawn → cold start | 同上 |
| COMMIT timeout (60s) | read が EAGAIN → zeroize → `_exit(3)` | (遅延していた場合) serve は継続済み。cache は new 側に受領済なら影響なし | 秘密を抱えた孤児 holder は残らない |
| holder 側 write timeout | zeroize → `_exit(3)` | read timeout → cold start | 同上 |
| holder が SIGKILL | zeroize 不能で即死 | read EOF → cold start | mlock 済ページの解放は kernel 管理 (他プロセスに非ゼロで渡らない) |

- ABORT に専用メッセージは設けない: **「相手側 end の close」が唯一の ABORT
  信号** (メッセージ追加は失敗経路を増やすだけで、close は crash 時にも
  kernel が保証してくれる)
- holder の exit code (0/2/3) は launchd に監視されない (holder は job ではない)
  が、新プロセスが waitpid で回収して結果を log する

### fail-safe の再定義 (issue §2-5 からの変更点、要合意)

§2-5 の「失敗したら旧が稼働継続」は案 C では exec 後に旧が存在しないため提供
できない。失敗時の帰結は上表の通り**全経路で「cold start (= 現状の非 graceful
restart と同じ)」に退化**する。②〜⑥ (exec 前) の失敗は全て中止 → 旧継続。
「現状より悪くなる経路がない」ことは fd 衛生 (§1) が前提条件 — これを満たさない
実装は cold start ではなく「holder timeout まで bind 不能」になるため、
**e2e テストで「handoff 失敗時に新プロセスが即 bind できる」ことを仕様として固定**する。

### メモリ上の平文コピーの一覧と後始末 (codex 指摘: CoW を含む全 lifetime)

| コピー | 生成 | 消滅 | 保護 |
|---|---|---|---|
| 旧 Store 内 SecretBytes 群 | 稼働中 | execve のアドレス空間破棄 | mlock (swap 不可)。exec 破棄後の物理ページは kernel が他プロセスへ渡す前にゼロ埋めする (zero-on-allocate) ため対外リークなし |
| 親の直列化 buffer (③) | fork 前 | execve のアドレス空間破棄 | 同上。**親は exec 前に zeroize しない**: fork 後の親側 zeroize は CoW でページ複製を誘発し、平文コピーを一時的に増やすため逆効果 (rationale として明記) |
| holder の buffer (CoW 共有 → 独立) | fork | COMMIT/timeout/ABORT 後に explicit_bzero → `_exit` | 再 mlock (⑤-2) + PT_DENY_ATTACH (⑤-1) |
| new の受信 buffer | ⑦ | エントリごとに即 SecretBytes(mlock) 化し、受信 buffer は都度 zeroize | mlock |

### 脅威モデルの差分 (issue §2 の同一 uid 整理との整合)

holder は「全秘密を単一の連続 buffer」で持つため、稼働 daemon の分散状態より
攻撃成功時の回収が容易になる。この差分は以下で相殺し、issue の残リスク整理
(「同一 uid は元々メモリ読取可能、PT_DENY_ATTACH で緩和」) と同水準に保つ:

- PT_DENY_ATTACH を holder 起動即適用 (**必須要件**。旧 Q4 を Decision に昇格)
- mlock 再適用で swap 経由の永続化を防止
- 生存時間は SO_RCVTIMEO で有界 (~90s 上限)
- fd 衛生により holder は socketpair 以外の入出力経路を持たない

### 6. スコープ / ロールアウト

- **opt-in** (issue 合意のまま): config `[daemon] graceful_restart = true` が
  無ければ従来どおり。trust (後継が旧の全秘密を継ぐ) を受け入れない利用者は
  非 graceful restart を使う
- trigger は control socket の新 request `RestartGraceful` (CLI:
  `cache-warden daemon restart [--graceful]`)。brew upgrade 連携
  (`justfile on-success-release` からの呼び出し) は後続
- **MVP = kv handoff + re-bind** (listening fd 継承なし)。fd 継承は format_version
  を変えずに追加できる (fd 番号は env 通知であり wire format 外) ため後続で可
- **config reload は本 DR のスコープ外だが恩恵は受ける**: config 変更の反映 =
  `daemon restart --graceful` で storm なしに新 config で再起動できる
  (同一バイナリの exec)。「restart なしの in-place reload」は必要になったら
  別 DR (トリガー頻度次第。graceful restart が十分安ければ不要かもしれない)

## 検討した代替案

### 案 A: nginx 型 (旧が新を fork+exec、旧 exit) — issue §2-1 の原案

launchd `KeepAlive=true` と衝突 (Context 参照)。KeepAlive を外す / handoff 中だけ
unload する回避は、常駐監視という KeepAlive の価値を落とすか launchd 状態遷移の
レースを増やすため不採用。

### 案 B: launchd 再起動 + peer 検証付き state 請求

`launchctl kickstart -k` で新を launchd 起動し、新が旧 (SIGTERM 猶予中) の
handoff socket へ接続して状態を請求。issue §2-1 が「新が要求」型を却下した理由
(要求元認証がソケットに触れる誰でも試せる) は、peer の codesign 同一性検証
(= `macos-process-inspect` crate の守備範囲) で技術的には解消できる。

不採用 (今回) の理由: (1) パス名付き socket + peer 認証は「構造的 private」な
匿名 socketpair より攻撃面が広い (検証ロジックのバグ = 秘密全量流出)、
(2) SIGTERM 猶予 (ExitTimeOut) 内に転送を終える時間レースを抱える、
(3) macos-process-inspect への依存が増える。案 C の fork 安全性制約が実装で
破綻した場合の fallback 候補として残す。

### 案 D: disk への暗号化 persist (handoff 不要化)

秘密をディスクに置かない (mlock/zeroize、DR-0007) という根本方針に反するため
不採用。鍵をどこに置くかの無限後退も解けない。

## Open Questions (実装前に潰す / 実装中に確定)

- Q1: 直列化形式の最終選定 (postcard vs 長さプレフィックス JSON)。エントリ数
  実測 (dogfood は現状 10 数鍵) では性能差は誤差の見込み → 依存を増やさない側に
  倒すのが有力
- Q2: `Capability` トークン (DR-0024) は**アダプタのロールトークン**であって
  エントリに紐付かないため、運ばず新側で再発行する (adapter が旧 cap を握り
  続ける経路が無いことの実装時確認のみ)。per-entry のアクセス制約 record とは
  別物で、後者は §2 の通り引き継ぎ必須
- Q3: macOS の fork における mlock 継承の実機確認 (設計は「継承されない」前提で
  無条件再適用なので、結果がどちらでも設計は変わらない — 確認は findings 記録用)
- Q4 (旧 Q3): 環境変数 `CACHE_WARDEN_HANDOFF_FD` が launchd の
  EnvironmentVariables と衝突しないことの確認のみ

## 実装フェーズ (目安)

1. Phase 1: 直列化 + socketpair + fork/exec + 二相コミット (MVP、re-bind 方式)
   — e2e: (a) 実 daemon で `restart --graceful` → 全エントリの TTL/pin/backoff が
   保存され TouchID が発火しないこと (coreauthd ログで検証)、(b) **handoff 失敗
   注入時に新プロセスが即 bind して cold start できること** (fail-safe の仕様固定)
2. Phase 2: brew upgrade 連携 (`on-success-release` から graceful 経路を叩く)
3. Phase 3 (任意): listening fd 継承で断ゼロ化
