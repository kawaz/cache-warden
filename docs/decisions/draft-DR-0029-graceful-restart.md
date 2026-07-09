# DR-0029: graceful restart — kv 秘密状態を引き継ぐ無 storm 再起動

- Status: Draft (kawaz レビュー待ち)
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
合意要素は保てる。下記案 C 参照)。

## Decision (提案)

### 1. 方式: 同一 PID exec + state-holder child (案 C)

```
launchd 管理下の daemon (PID=P, 旧バイナリ)
  │ ① trigger 受信 (control socket: RestartGraceful)
  │ ② accept 停止 + in-flight drain (§4)
  │ ③ 全 handoff 状態を 1 つの mlock buffer へ事前直列化 (§2)
  │ ④ socketpair(AF_UNIX) 生成、CLOEXEC を外す
  │ ⑤ fork() ──────────────► state-holder child (PID=C)
  │                             - 秘密 buffer と socketpair 片端を保持
  │                             - fork 後は write/read/_exit のみ (malloc しない)
  │ ⑥ exec 対象を検証 (§3) して execve(自 plist の ProgramArguments[0])
  ▼
launchd 管理下の daemon (PID=P のまま, 新バイナリ)
  │ ⑦ 継承 fd (env/argv で番号通知) から state を受領
  │ ⑧ 全受領 + mlock + serve 開始 → socketpair へ COMMIT 送信 (§5)
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
- **endpoint fd 継承 (issue 層 1) がほぼ無償で付いてくる**: listening fd も
  CLOEXEC を外して exec を跨げば新プロセスがそのまま使える。ただし MVP では
  fd 継承を必須にしない (§6: クライアントは全て per-request 接続なので
  unlink→re-bind の数百 ms 断で実用上十分)
- **TCC/FDA の同一性が保たれる**: 同一 PID・同一バイナリパス (.app 内) での
  exec なので、責任主体の連続性が最も乱れにくい (DR-0020 の Bundle ID 永続化と
  整合)

#### fork 安全性 (multithreaded tokio プロセスでの fork)

fork() は multithreaded プロセスでは child 側で async-signal-safe な操作しか
保証されない (他スレッドが握っていた lock が凍結されるため malloc 等は deadlock
リスク)。対策を設計で吸収する:

- **child がやることを write ループ + zeroize + `_exit` のみに限定**する。
  直列化 (= malloc を伴う) は **fork 前に親側で完了** (③)。child は既成の
  buffer を fd に流すだけ
- tokio runtime / 他スレッドの状態には一切触れない
- 親は fork 直後に execve するので親側の post-fork 制約はない

### 2. handoff wire format (詰めどころ b)

- socketpair 上の一方向 stream: `magic + format_version(u32)` ヘッダ +
  エントリ列。**version を最初に置き、新バイナリが旧 version を読めない場合は
  即 ABORT** (新旧バイナリの format 互換は「新は旧を読める」方向のみ保証)
- ペイロードは serde + 既存依存で完結するバイナリ形式 (candidate: `postcard`。
  依存追加を避けるなら control socket と同じ serde_json + 長さプレフィックス
  でも可 — 秘密が JSON 文字列化される時間が延びるだけで、どちらも mlock
  buffer 内なので安全性は同等。**実装時にサイズ/速度で選ぶ**)
- 1 エントリ = `key (NS/KEY)` + `secret bytes` + `Ttl 状態 (loaded_at/extended_at
  を絶対時刻で)` + `pin 状態` + `FailureRecord (backoff)` + `ValueMeta` +
  `Definition (ValueSource)` 。時刻は wall clock (UNIX epoch) で運び、受領側で
  monotonic 基準へ再アンカーする
- 対象は **kv 全エントリ** (op:// / static / command 由来を問わない。issue の
  「source 種別で絞れるという当初観察は誤り」の結論に従う)。公開鍵 registry は
  非秘密なので運ばず新側で再構築。upstream proxy は状態を持たず対象外
- buffer 全体を両端で mlock、受領側は即 SecretBytes 化、holder は COMMIT 受信後
  zeroize (§2-4 のメモリ衛生合意のまま)

### 3. exec 対象の検証 (詰めどころ a の一部、§2-3 の macOS 適合)

- exec するパスは **plist に焼いた ProgramArguments[0]** (= stable-which 0.4 の
  durable 判定を通ったパス、DR-0019 §2.5)。cwd 相対や PATH 探索はしない
- macOS に fexecve は無いため「open した fd を検証してそのまま exec」は不可。
  代替: execve 前に `csops`/codesign 検証 (TeamID 一致) + owner/perms 確認 →
  execve。TOCTOU は残るが、**macOS はカーネルが exec 時に codesign を再強制**
  するため bounded (issue §2-3 の許容判断のまま)。Linux は owner/perms
  (+将来 hash pin) で代替
- 検証失敗時は handoff を中止して現行プロセスが serve 継続 (exec 前なので
  完全无害)

### 4. drain (詰めどころ d)

現行の全クライアントは per-request 接続 (authsock は 1 request/conn、control は
短命 round_trip、upstream 転送は request 毎接続)。よって:

- accept を止め、**in-flight request の完了を短い deadline (例 5s) で待つ**だけ
- deadline 超過分は切断してよい (クライアントは ssh/git の retry 単位で回復)
- 長寿命接続の「引き継ぎ」は不要 — issue 詰めどころ (a) はこれで閉じる

### 5. 二相コミット (詰めどころ c) と fail-safe の再定義

socketpair 上のメッセージは 2 つだけ:

```
holder → new : <state stream> (③で直列化した全量)
new  → holder: COMMIT (全受領 + mlock + listener bind 完了後)
```

- holder は COMMIT 受信で zeroize + `_exit(0)`。**timeout (例 60s) 内に COMMIT が
  来なければ同様に zeroize + `_exit`** (孤児 holder が秘密を抱えて残留しない)
- **fail-safe の格下げ (issue §2-5 からの変更点、要合意)**: §2-5 の「失敗したら
  旧が稼働継続」は案 C では exec 後に旧が存在しないため提供できない。失敗時の
  帰結は「新プロセスが cold start (= 現状の非 graceful restart と同じ)」。
  つまり **graceful restart の失敗 = 今日の通常再起動に退化**するだけで、
  現状より悪くなる経路はない。②〜⑤ (exec 前) の失敗は全て中止 → 旧継続
- 新バイナリが起動すらできない場合 (リンク切れ等) は launchd KeepAlive が
  respawn を試み続ける = 既存の brew upgrade 失敗時と同じ挙動で、本 DR での
  新規リスクではない

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
- Q2: `Capability` トークン (DR-0024) はプロセス内 opaque なので運ばず新側で
  再発行、で問題ないか (adapter が旧 cap を握り続ける経路が無いことの確認)
- Q3: exec を跨いで環境変数で fd 番号を渡す際、launchd の EnvironmentVariables
  と衝突しない命名 (`CACHE_WARDEN_HANDOFF_FD` 等) の確定のみ
- Q4: PT_DENY_ATTACH (DR-0007) は exec で失効するため新プロセスで再適用する。
  holder child 側にも適用すべきか (holder は秘密を持つ。fork 直後の
  async-signal-safe 制約内で ptrace(2) は呼べる見込み → 適用する方向で実装時確認)

## 実装フェーズ (目安)

1. Phase 1: 直列化 + socketpair + fork/exec + 二相コミット (MVP、re-bind 方式)
   — e2e: 実 daemon で `restart --graceful` → 全エントリの TTL/pin/backoff が
   保存され、TouchID が発火しないこと (coreauthd ログで検証)
2. Phase 2: brew upgrade 連携 (`on-success-release` から graceful 経路を叩く)
3. Phase 3 (任意): listening fd 継承で断ゼロ化
