# TouchID 待ち中の Mutex 保持が blocking pool を直列化する (副次問題)

- status: open / idea 段階
- 派生: 2026-06-14 [2026-06-14-op-refetch-loop.md](./2026-06-14-op-refetch-loop.md) の追加調査中に副次的に判明
- 関連: DR-0008 (単一 daemon)、DR-0009 (control socket)、`crates/cache-warden-cli/src/daemon/authsock.rs:sign_local_with_ctx` / `ensure_loaded` / `lazy_load_op_key`

## 現象 (コード根拠から推測)

SIGN_REQUEST 処理は `spawn_blocking` で blocking pool に乗せ、その中で **`store` の `std::sync::Mutex` を取って `ensure_loaded` → `runner.run` (op fetch、TouchID 待ち = 数秒〜分) → auth → `store.set` を一気通貫で実行してから Mutex を解放** する構造になっている。

このため:

- 同じ KV 鍵への並行 SIGN_REQUEST は Mutex 直列化により効果的に singleflight 状態になる (= op-refetch loop の旧仮説否定の根拠でもある)。
- 一方で **異なる KV 鍵への並行 SIGN_REQUEST も、Mutex を取りにきた瞬間に block** する。
- 加えて blocking pool は worker 数が有限 (tokio default = 512、ただし TouchID 待ちで全 worker が長時間張り付くと枯渇しうる)。
- → **op fetch (TouchID) 中、別の SIGN_REQUEST は応答できず実質ストール**。普段は 1Password 認証セッションが効いているので体感問題にならないが、認証が外れた瞬間の n 鍵 (e.g. 起動直後 / hard-ttl 切れタイミング) でストールが顕在化する。

## 影響

- 単独では「離席中 TouchID 連発」(op-refetch loop) の主因ではない。**主因は fetch 失敗時の `store.set` スキップ + backoff 無し** (本体 issue 参照)。
- しかし副次的に: 認証セッション切れ後の最初の SIGN が n 個並行で来た場合、daemon が事実上 1 個ずつ直列で TouchID を出すことになり UX 悪化 + 上流クライアントが timeout で諦める二次効果が起きうる。
- 起動時の op discovery (`2026-06-13-op-discovery-blocks-startup.md`) と同じカテゴリの構造問題 (= op CLI 同期実行が daemon の応答性を奪う)。

## 対応案 (本 issue の解は未確定)

### 案 X: per-key Mutex (= 鍵レベル粒度)
- store 全体の Mutex でなく per-key の Mutex / Notify に分割。異なる鍵の SIGN_REQUEST は並行進行可能。
- ⚠️ 設計が複雑化。同 key 並行は別途 in-flight tracker が必要。

### 案 Y: fetch を Mutex 外で実行 (= in-flight tracker + late insert)
- `state_of()` で HardExpired を見たら **Mutex を一度解放** → `runner.run` を Mutex 外で実行 → 取り直して `store.set`。
- 同 key 並行は `Arc<Notify>` ベースの in-flight tracker で coalesce (= singleflight)。
- ⚠️ Mutex の出入りが増える、TOCTOU 的にちらつくケースを抑える設計コスト。

### 案 Z: 構造維持 + blocking pool worker 数上限を意識した運用
- 対応しない、副次問題として放置 (本体問題が解決すれば実用上問題ない、として割り切る)。
- ⚠️ 起動時 op discovery 問題と同じ root cause なので、graceful restart 設計 (`2026-06-14-graceful-restart-state-handoff.md`) や Provider 再設計 (`2026-06-14-ssh-agent-provider-architecture.md`) で一括して構造を入れ替える方が筋良い可能性。

## スコープ

本 issue は **派生 issue として記録のみ**。本体 (op-refetch loop) の修正完了後に再評価する。

graceful restart や Provider 再設計の文脈で構造変更が入るなら、その流れで吸収するのが筋。単独修正で済ますなら案 Y が最小侵襲。
