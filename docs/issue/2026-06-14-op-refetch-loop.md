# SIGN 起因の op fetch が client 切断で完遂せず再 fetch ループになる

- status: **wip — code complete, pending live verification** (2026-06-14)
- 発見: 2026-06-13 (Phase 3 dogfood 切替直後、離席中に観測)
- 元記録: `docs/journal/2026-06-13-handoff-ecdsa-dogfood-stablewhich.md` §A (本 issue で独立昇格)
- 関連: DR-0018 (型付き source、prefetch で起動時 warm 化することで二次的に緩和し得る) / [2026-06-13-op-discovery-blocks-startup.md](./2026-06-13-op-discovery-blocks-startup.md) (起動時 op 同期ブロック、同じ op fetch 経路)
- last_read: 2026-06-22T17:14:30+09:00

## 解決方法 (= code complete、実機検証待ち、2026-06-14)

仮説確定 (= op fetch 失敗時の `store.set` スキップ + backoff 無し → 同 key への次 SIGN_REQUEST で再 fetch ループ) に対し、core `Store` に `failure_backoffs` 機構を追加し、同 key への直近失敗から `[daemon].fetch-failure-backoff` (default 5s) 内の再 fetch を抑止する設計を確立 + 実装した。

- 設計判断: [DR-0022-fetch-failure-backoff.md](../decisions/DR-0022-fetch-failure-backoff.md) (v1 → Codex review → v2 改訂)
- 実装の前提 refactor: [docs/design/lazy-load-op-key-unification-plan.md](../design/lazy-load-op-key-unification-plan.md) (A-3a)
- 失敗種別調査: [docs/findings/2026-06-14-op-cli-failure-categorization.md](../findings/2026-06-14-op-cli-failure-categorization.md) (A-3c)
- 副次問題: [2026-06-14-touchid-blocks-blocking-pool.md](./2026-06-14-touchid-blocks-blocking-pool.md) (= Mutex 保持中の blocking pool ストール、別 issue)
- live 検証手順: [docs/runbooks/op-refetch-loop-live-diagnosis.md](../runbooks/op-refetch-loop-live-diagnosis.md)

実装コミット (= ローカル、未 push):

- `71da8806` refactor(authsock): A-3a — unify op key lazy loading through Store::get_or_regenerate
- `44ea8e57` feat(core): A-3b — fetch failure backoff (DR-0022)

残作業:

- live 検証 (= runbook の §5/§6 を kawaz 在席で実機実行): backoff が効くこと + 接続元 rate driver の特定
- CLI 出力 (`status` / `kv list`) に `backoff_until_secs` を表示する追加実装 (= A-3d、wire 側は実装済)
- TouchID dismiss / timeout の stderr 観測 (= A-3c で在席要として残った確認、DR-0024 候補)

実機検証 OK で push 後、本 issue を `pending-sublimation` → delete (DR + runbook + findings に sublimation 済)。

## 現象

離席中に TouchID が ~20 連発。通常起動 (在席で確認) は op discovery で 1 回だけ。daemon ログに `authsock connection error: Broken pipe` が連発。

## 推定メカニズム (要 live 裏取り)

> **更新 (2026-06-14)**: 元 journal の推定「peer 切断で fetch / cache 書き込みがキャンセル」は **コード review でほぼ否定** (下記)。下記は新仮説。

### コード review (2026-06-14) で否定された旧仮説

- handler は `spawn_blocking` 内で `Mutex` (std) を取り、**Mutex 内で `ensure_loaded` → `runner.run` (op fetch) → auth → `store.set` まで完遂してから Mutex 解放**。peer への `write_all` はそのさらに後。
- 同 key への並行 SIGN_REQUEST は Mutex 直列化で実質 singleflight = 1 回目の fetch 完了後、2 個目以降は `state_of()` で Active を見て fetch skip。
- → **peer 切断は write_all で観測されるだけで、fetch 結果は既に store に入っている**。「peer 切断で値が残らない」は成立しない。

(調査メモ: `crates/cache-warden-cli/src/daemon/authsock.rs` の `handle_connection` / `sign_request` / `sign_local_with_ctx` / `ensure_loaded` / `lazy_load_op_key` ・ `crates/cache-warden/src/store.rs` の `set` / `regenerate`)

### 新仮説 (= 次に裏取りすべき)

1. **op fetch 自体が失敗してキャッシュに残っていない**
   - 離席中、`op` CLI 自身が出す biometric prompt (TouchID) が dismiss / timeout → `op` exit 非ゼロ → `runner.run` が `Err` → `store.set` 呼ばれず → 次の SIGN_REQUEST でまた `HardExpired` を見て fetch → また op が TouchID 出す = ループ
   - cache-warden の `[auth]` (CommandAuthenticator) でなく **op 側の TouchID** が連発している可能性
2. **接続元が SIGN_REQUEST を機械的に連発**している (= ループの起動力)
   - fetch 失敗時の short-term backoff が無いと、相手の retry 速度がそのまま TouchID 連発速度になる
3. **副次問題 (本 issue とは別だが要記録)**: Mutex 保持中に TouchID 待ち (数秒〜分) が走っている = 同 key は救われるが **別 key 含む全 SIGN が blocking pool で詰まる**。TouchID 中 daemon が事実上ストール

= 「一度 fetch すれば以降ヒット」が成り立たないのは `store.set` が呼ばれないからで、peer 切断は無関係。loop の self-limit は op 認証成功一発で破れる。

## 影響

- dogfood Phase 3 再開の主リスク。離席中の TouchID storm = 体感の使い物にならなさ + op セッション枯渇。
- DR-0018 prefetch (起動時 warm 化) があっても hard-ttl 失効後の再 fetch で同じことが起こり得る (G: hard-ttl 頻度と連動)。

## 要調査

### live 診断 (在席で再現したとき)

- `lsof -p <daemon-pid>` / `lsof /path/to/agent-*.sock.cw` で **何が `.cw` socket に繰り返し接続しているか** を特定。
  前セッションは daemon を止めてしまい live 証拠を失った。
- `fs_usage -w -f filesys <pid>` / `dtruss -p <pid>` の併用。
- 接続元 PID が判ったらその起動パスと frequency を控える。

### コード追加調査 (live なしで進められる)

旧仮説のコード review は済 (上記)。次は **op fetch 失敗経路** を読む:

- `lazy_load_op_key` の `runner.run` が `Err` を返したとき、`store.set` が飛ばされて `HardExpired` のままになる経路を確定。
- stderr に診断 1 行が出るか (= journal `parity-phase2.md` の op JSON バグ修正で追加した「署名時 fetch 失敗の stderr 診断」と同じ系)。「`authsock connection error: Broken pipe`」とは別ログのはず — 両者がどこで出るかを混同しないように特定。
- fetch 失敗時の retry / backoff は現状なしのはず (要確認)。
- 別経路: `__authsock_op:*` 内部鍵の lazy 経路と通常 KV 鍵の lazy 経路の差異 (DR-0018 prefetch 未実装の今、内部鍵側にしか eager 経路が無い可能性)。

## 対応案 (新仮説に対応、コード追加調査 + live 診断後に確定)

旧 A 案 (fetch detach) は不要 (peer 切断が原因でないため)。旧 B 案 (singleflight) も Mutex 直列化で既に実質効いているので直接の解にはならない。新仮説に対する案:

- **新 C 案**: fetch 失敗時の **short-term negative cache / backoff** を入れる。同一 key への直近失敗から N 秒は新規 fetch を叩かず `agent refused` を即返す (= TouchID 連発を rate limit。N は秒〜10秒オーダーが妥当か)。離席中のループを止める。
- **新 D 案**: TouchID 中の **Mutex 粒度を細かくする** (副次問題 §3 対応)。`ensure_loaded` の op fetch 区間を Mutex 外で実行し、in-flight set を per-key Notify で coalesce する。本筋ではないが daemon ストール改善に効く。
- **新 E 案**: 接続元 (rate driver) が特定できたら **そちら側を直す** (= ssh client 設定 / 不要 retry 抑止)。cache-warden 側の defensive 修正と独立に効く。

C / E は独立に効き、両方やる価値あり。D は副次。

## fix 後の検証

- live 再現条件 (= 離席中接続元) を **再現できる単独テストハーネス**を作って fix の前後で TouchID 計数を比較。
- fake op + fake client (broken pipe を意図して起こす) で unit test 化 (= journal §2026-06-12-parity-phase2.md の op JSON バグと同じ流儀)。
- 在席で本番 daemon に対して 1 回実走、CI には fake で乗せる。

## 関連

- journal `2026-06-13-handoff-ecdsa-dogfood-stablewhich.md` §A — 元記録
- [2026-06-13-op-discovery-blocks-startup.md](./2026-06-13-op-discovery-blocks-startup.md) — 同じ op fetch 経路の別 issue
- DR-0018 — prefetch / typed source (起動時 warm 化が二次的に緩和)
- DR-0011 — TTL 2 分離 (hard-ttl 失効が本 issue の再 fetch 起点になり得る、G と連動)
