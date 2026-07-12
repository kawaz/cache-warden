# authsock SIGN 経路への approver dialog 統合

issue `2026-07-12-authsock-sign-guard-dialog-decision` の裁定 (kv.get の guarded
reveal path と authsock SIGN 経路の dialog 非対称をどう扱うか) を受けて、SIGN
経路にも approver dialog (人間承認) を統合した (commit `52b95386`)。

## kawaz 裁定の経緯

Block 3a レビューの MEDIUM-4 指摘で、guard 通過後の挙動が非対称であることが
判明した: kv.get は guard 通過後に常に approver dialog を挟むが、authsock
SIGN は guard の機械評価のみで dialog を経由しない。issue では 3 案
(a: SIGN でも dialog を出す / b: 非対称を既知の限界として明記 / c: socket 単位
opt-in) を並べ、AI 側は「SSH client 側の応答待ち timeout (数秒で諦める実装が
多い) との整合が課題」という懸念から案 (b) を推奨していた。

kawaz の裁定は案 (a): 「socket 介して相手を確認するほぼ同じ構図なので共通化」。
AI 側の timeout 懸念は **過大評価だった**と率直に認める必要がある — SSH
client は agent への SIGN_REQUEST 応答を同期で待つ設計であり、1Password SSH
agent が TouchID confirm を挟んでいるのと同じ構図で実用に耐える (サーバ側
`LoginGraceTime` の既定 120 秒に対し `APPROVER_REQUEST_TIMEOUT` は 90 秒で
収まる)。1Password という実例が既に運用されているにもかかわらず、それを
参照せずに一般論で timeout リスクを見積もったのが AI 側の判断ミス。

## 共通化の設計判断

kv.get 経路と SIGN 経路で「何を共有し、何を分離するか」を明確に切り分けた:

- **共有した部分**: `ApprovalOutcome` (outcome 分類) と
  `ApproverSlot::await_dialog_outcome` (`wait_ready` → `request` → outcome
  分類という dialog await の骨格)。両経路とも「lock を解放してから人間の
  数秒〜十数秒の操作を待つ」という構造は同一
- **分離した部分**: `first_pass` / `finalize` は経路ごとに個別実装のまま
  残した。pre-gate の中身 (kv.get は reserved-namespace/process-policy、SIGN
  は `[authsock.sockets.*].keys` 由来の DR-0012 gate)、応答形式 (kv.get は
  `AuthFailed`、SIGN は `SSH_AGENT_FAILURE` 空 payload)、診断文言が経路ごとに
  異なり、無理に一体化すると両経路の意味論を壊す (どちらかに合わせて
  丸めると片方の contract が壊れる) と判断したため

## ハマり所 → 解決策

### (1) finalize の staleness 窓 — registry 再解決の漏れかけ

kv.get の 2 pass 設計 (Block 3a) をそのまま SIGN に持ち込もうとした際、
「dialog 待ち中に guard record が差し替わる」ケースは kv.get と同様に
re-evaluate すれば塞げると考えていた。しかし SIGN 経路には kv.get に無い
**第 2 の staleness 入力**がある: SIGN は blob (署名対象の公開鍵相当) から
`kv_key` / `source` を **registry** で解決してから guard を引く構造なので、
guard record だけでなく **registry の解決結果自体**も dialog 待ち中に
変わり得る (rotate / hot-swap で registry entry が消える・別 key に
差し替わる)。guard record の再評価だけでは、この registry 側の変化を
見逃したまま古い解決結果で署名してしまう穴が残る。

**解決**: finalize で guard record の再評価に加えて **registry も
再解決**し、dialog 待ち中の rotate/hot-swap を fail-closed で弾く構成にした。
kv.get 側のコードをそのままコピーするのではなく、「SIGN 固有の入力は何か」を
洗い出してから 2nd pass の再検証範囲を決める必要があった。

### (2) production 経路の `#[cfg(test)]` 降格で test shim の複製ロジックを検証しかけた

guard 評価ロジックを実装する過程で、production の評価器と test 用の shim が
別々に guard 判定ロジックを持つ形になりかけた。この状態だと、テストは
「production の挙動」ではなく「test shim が production の判定を正しく
真似できているか」を検証する構図になってしまい、production 側にバグが
あってもテストは気づけない (shim 側も同じバグを踏襲していれば green のまま)。

**解決**: guard 評価を `eval_sign_guard` 1 箇所に一本化し、production も
test もこの単一実装を呼ぶ形にした (first_pass / finalize / test shim の
3 重複を解消)。テストが検証する対象を「production が実際に実行するコード
パス」に固定し直したことで、shim の複製ロジックを検証してしまう構図を解消。

## 検証

`cargo fmt --check` / `cargo clippy --workspace --all-targets -- -D warnings` /
`cargo test --workspace` すべて green。SIGN 経路のテスト 8 本追加 (approved
署名成功 / 非 approved 全 outcome / helper_down / record 差し替え / registry
消滅 / 拒否時 dialog 非発火 / dialog block 中の並行 get 進行)。**1963 tests
green**。Fable 敵対的レビュー通過 (MEDIUM 2 件は修正済み)。

## 関連

- draft-DR-0031 §8 / §Security / 「SIGN dialog 統合 (2026-07-13)」節
- draft-DR-0030 §4 (authsock SIGN の guard 裁定)
- issue archive `2026-07-12-authsock-sign-guard-dialog-decision.md`
- `docs/journal/2026-07-12-phase-1-6-block-3a-dialog-wiring.md` (kv.get 側の
  2 pass 設計の先行実装)
