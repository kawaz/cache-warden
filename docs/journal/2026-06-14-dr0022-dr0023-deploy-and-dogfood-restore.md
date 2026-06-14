# DR-0022 + DR-0023 設計 + 実装 + push + dogfood 復活 (一日サマリ)

- Date: 2026-06-14
- 担当: Claude Code (kawaz は離席が長く、nonstop モードで進行)

## セッション目標

- ABCD 順で進める (= kawaz 指示): A (op-refetch loop) → B (op discovery 起動ブロック) → C (FDA 移植、在席要) → D (stable-which 0.4.0、外部依存待ち)
- A 系 + B 系のコード変更 + dogfood 復活 + 実機検証は本セッションのスコープ

## 完了した内容

### 設計判断 (DR 起票)

- **DR-0022 (秘密値 fetch 失敗時の short-term backoff)**: 起票 → Codex adversarial review v1 → Critical 2 件 + Warning 5 件反映 → review v2 → Critical 2 件 (Store::set 副作用 / A-3a scope) + Warning 5 件反映で改訂。最終形:
  - `failure_backoffs: BTreeMap<String, FailureRecord>` を core `Store` の第 3 マップに配置 (= entry / definition と並列)
  - 分類は TTL/pin と別カテゴリ (= source 実行の retry policy / circuit breaker)
  - `Store::set` は failure_backoffs を触らない (= adapter からの static 値投入で意図しない reset を回避)
  - lifetime = definitions と一致
  - 前提条件: `lazy_load_op_key` を `Store::get_or_regenerate` 経由に統一する refactor (= A-3a)
- **DR-0023 (op discovery 起動遅延)**: Phase 1 (= `spawn_blocking` + `select!` で shutdown signal 並行 await) Accepted、Phase 2 (= lazy + background refresh) は Provider 再設計と一体化候補で Proposed

### 実装 (= 6 commits、push 後 v0.21.0)

| commit | 内容 |
|---|---|
| `d0fa46af` | docs: op-refetch loop 系の問題分析と設計判断を整理 (DR-0022 起票、issue 起票、副次問題分離、live 診断 runbook、INDEX) |
| `71da8806` | refactor(authsock): A-3a — `lazy_load_op_key` を `Store::get_or_regenerate` 経由に統一 |
| `73c5c909` | fix(clippy): A-3a 中に判明した pre-existing 警告解消 |
| `44ea8e57` | feat(core): A-3b — fetch failure backoff (DR-0022)、`failure_backoffs` 別マップ + `Outcome::Backoff` variant + config + 可観測性 |
| `165c8eec` | feat(daemon): B-3 — DR-0023 Phase 1 op discovery 非同期化 |
| `0831b1e1` | feat(cli): A-3d — status output に `backoff_until_secs` を表示 |

加えて findings 訂正 + version bump commit で v0.21.0 が release.yml 経由で brew cask に配信。

### dogfood 復活

- 稼働中 daemon が exit 78 で死亡、`.app` 自体も brew uninstall 状態
- `just push` → release.yml success → `brew install --cask kawaz/tap/cache-warden` で復活 → `cache-warden daemon register` で plist 反映 + bootout/bootstrap で再起動 (pid 92877)
- discovery 完了 272 秒 (= kawaz の 6 鍵 TouchID 許諾の累積時間)
- `.cw` socket 3 つ listen 開始
- `~/.ssh/config` の IdentityAgent を `.cw` に切り替え (3 箇所 = kawaz Host * / emerada / syun)
- 隔離 ssh test 1 回で `exit 0` 確認 (= sign 成功、TouchID 追加なし = biometric session 効果)

## 残作業 (kawaz 復帰後)

1. **backoff 動作の実機検証 (runbook §6 の 3 回シナリオ)**: biometric session 切れた状態で TouchID dismiss → 即再 ssh で backoff active 観測 → 5s 後で TouchID 再要求 観測
2. **TouchID dismiss / timeout の op stderr 観測** (A-3c follow-up): 区別可能なら DR-0024 (per-category backoff) として起票
3. **C (FDA 移植) の進行判断**: 実機 FDA トグル必須、kawaz 在席で 1 回切り替えながら実装
4. **D (stable-which 0.4.0)**: 0.4.0 リリース + DR-016 durability 確定待ち、peer session 経由で connect
5. **`docs/issue/2026-06-14-op-refetch-loop.md` の sublimation**: backoff 動作検証が成功したら delete (= DR-0022 + runbook + findings に sublimation 済)

## 学び・教訓 (kawaz が後で参照する用)

### 設計面
- **Codex 2 ラウンド review は強力**: 1 ラウンド目で見えなかった「entry 配置 vs failure_backoffs マップ」「Store::set の副作用」「A-3a scope」を 2 ラウンド目で発見。重要 DR は最低 2 ラウンド回す価値あり
- **A-3a (lazy load 統一) を前提条件にしてよかった**: core 一本化を構造的に保証、暫定重複の罠を回避

### 運用面
- **私のミス 1: A-3c で「在席不要範囲」と判断したが、`op` は item 不在判定の前に session 確立用 TouchID を要求**。Sonnet が叩いた 10-20 回が kawaz の reflective 全許可で見えていなかった。memory `feedback-op-cli-touchid-requirement` に教訓
- **私のミス 2: `IdentitiesOnly=yes` で agent test を組んだ**。`IdentitiesOnly=yes` は agent の鍵を無視する設定 = agent 経由 test では使ってはいけない。memory `feedback-ssh-test-isolation` に追記
- **私のミス 3: 71da8806 commit に docs (DR-0022 v2, 計画書, findings) が混入**。Sonnet 委譲時に jj working copy を `jj new` でクリーンにせず委譲した結果。次回以降は委譲前に working copy 確定が筋

### TouchID storm の構造 (= kawaz が見た 25 回の内訳推測)
- `just push` の jj signing: 8-9 commits × 1Password biometric session (operation per sign) = 8-15 回
- cache-warden v0.21.0 起動時の op discovery: 6 鍵 × biometric session 確立 = 6 回
- = 14-21 回が想定範囲、25 回は範囲内のばらつき
- **改善余地**: jj signing batch 化 / 1Password biometric session 設定 (= 一定時間内は再要求しない設定) は別 issue 化候補

## 関連

- [DR-0022](../decisions/DR-0022-fetch-failure-backoff.md) (v1 → Codex review × 2 → 最終)
- [DR-0023](../decisions/DR-0023-op-discovery-startup-latency.md)
- [docs/issue/2026-06-14-op-refetch-loop.md](../issue/2026-06-14-op-refetch-loop.md) (= 解決対象 issue、status: code-complete pending live verification)
- [docs/issue/2026-06-14-touchid-blocks-blocking-pool.md](../issue/2026-06-14-touchid-blocks-blocking-pool.md) (= 副次問題、本セッションでは扱わず)
- [docs/findings/2026-06-14-op-cli-failure-categorization.md](../findings/2026-06-14-op-cli-failure-categorization.md)
- [docs/design/lazy-load-op-key-unification-plan.md](../design/lazy-load-op-key-unification-plan.md) (= A-3a 計画書)
- [docs/runbooks/op-refetch-loop-live-diagnosis.md](../runbooks/op-refetch-loop-live-diagnosis.md)
- 前 journal: [2026-06-13-handoff-ecdsa-dogfood-stablewhich.md](./2026-06-13-handoff-ecdsa-dogfood-stablewhich.md)
