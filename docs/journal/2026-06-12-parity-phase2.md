# parity-phase2: authsock-warden パリティ実機検証 (Phase 2) と op fetch バグ発見

- Date: 2026-06-12

## 何をしたか

DR-0004 Phase 2 を runbook (`docs/runbooks/parity-verification.md`) に沿って実施。
warden を無傷で稼働させたまま cache-warden を `.cw` socket 3 本で並走させ、挙動を突き合わせた。
**実バグを 1 件発見して修正 (v0.16.2)** — これがパリティ検証の最大の成果。

## 結果

| 検証 | 結果 |
|---|---|
| 2.0 config 文法 (`config show`) | exit 0、3 socket 列挙 ✓ |
| 2.1 並走起動 | `.cw` socket 3 本 bind、op 発見 6 鍵、warden 無傷 ✓ |
| 2.2 鍵列挙 (`ssh-add -L`) | 3 env ともバイト一致 (emerada 1 / kawaz 2 / syun 1 鍵) ✓ |
| 2.3 フィルタ | 一致。draft の filters **OR 解釈が正**と確定 ✓ |
| 2.4 allowed_processes 空 = 全通過 | 一致 ✓ |
| 2.5 署名 | kawaz: `Hi kawaz!` / emerada: `Hi kawaz123!` で一致、syun: 両者同一の Permission denied (鍵が GitHub 用でない、挙動一致) ✓ |
| 2.6 TouchID 回数 | **統制再試験で確定** ✓: **1 daemon 起動 = 認可プロンプト 1 回** (op item list の認可。公開鍵 fetch ×6 はその認可済みセッションに乗り無音)。**以降は fresh な秘密鍵 fetch・署名とも 0 回** (kawaz 監視下で計数)。プロンプト頻度は op セッションポリシー側が支配し warden と同一構造。検証中に「たくさん出た」体感は同日の daemon 再起動 ×4 + 診断用 op 呼び出しの累積で説明がつく |

## 発見したバグ: op 秘密鍵 fetch の quoted 出力問題 (v0.16.2 で修正)

- **症状**: cw socket への署名要求が全て `agent refused operation`。daemon ログに痕跡なし
- **切り分けの経緯**: sandbox 仮説 (Bash ツール起動由来) → 外れ。op の単体動作 → 正常。
  **warden と cache-warden の op 呼び出し argv 比較**で確定
- **根本原因**: warden は `op item get --fields private_key --reveal --format json` で
  JSON の `.value` を抽出するが、移植は `--format json` を落としてプレーン出力を期待。
  実 op (2.34.0) のプレーン出力は**複数行 field を二重引用符で包む** (shape のみ実測:
  `"` 始まり・10 物理行) ため PEM パースが失敗。port plan Iteration 4 の
  「CommandRunner との相性確認」という未検証 TODO がそのまま実バグだった
- **fake op の限界**: E2E の fake はプレーン PEM を吐いていたので検出不能だった。
  修正で fake を実形状 (JSON) に合わせ、quoted プレーン出力の失敗を回帰テストで固定
- **修正の設計**: op 鍵は command 定義 (argv → stdout = 秘密値) として KV に配線されている
  ため、JSON 抽出を **cache-warden 自身の隠しサブコマンド** (`__authsock-op-private-key`)
  に閉じ込めた。定義 argv が自バイナリを指し、サブコマンドが op を JSON で呼んで
  `.value` を plain PEM として吐く。regenerate も同じ argv 再実行で JSON 経路が効き、
  コアの CommandRunner 契約は不変。warden の実運用実績がある JSON セマンティクスを
  そのまま再現する (= `op read` 直叩き案より未知数が少ない) 判断
- **観測性の補修**: 署名時 fetch 失敗の stderr 診断 1 行 (秘密値なし) を追加。
  「agent refused だけでログ無沈黙」が今回の調査を長引かせた教訓

## 検証時のハマり所

- **ssh は `SSH_AUTH_SOCK` でなく `-o IdentityAgent=` で socket 指定** (kawaz の
  `~/.ssh/config` の `Host *` IdentityAgent が env より強い)。`ssh-add` は ssh_config を
  読まないので env で OK — 列挙は env、署名は -o、の使い分け
- daemon 再起動時に旧 daemon の kill 忘れ → 二重起動拒否 (AddrInUse) は正しく発火
- 補完テストの orphan daemon (cw-comptest-*) が 3 個残留していた → 掃除。
  テストスクリプトの daemon 後始末は要改善候補

## 残り / 次

- [x] 2.6 TouchID 確認 → **Phase 2 完了** (2026-06-12)
- [ ] Phase 3 (実 `SSH_AUTH_SOCK` を cw 側へ可逆切替) に進むか、並走観察期間を置くかは kawaz 判断
- 注意: 並走 daemon は現在 Claude セッションからの手動起動 = **セッション終了で死ぬ**。
  観察期間を置く / Phase 3 に進むなら launchd 常駐化が先 (`daemon register` は未実装なので
  手書き plist。warden の plist が雛形になる)

## 関連

- [docs/runbooks/parity-verification.md](../runbooks/parity-verification.md) — 手順の正本
- [DR-0004](../decisions/DR-0004-authsock-warden-succession.md) — 移行パス
- v0.16.2 — op fetch 修正リリース
