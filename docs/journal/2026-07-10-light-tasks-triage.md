# 2026-07-10 軽作業消化 (issue 棚卸し + 未 push 58 コミットの push 前検証)

kawaz 外出中の自律作業。DR-0030/0031 レビュー等の kawaz 判断待ち事項には触れず、
在席不要の軽作業のみ実施した。

## issue 棚卸し (未解決 10 件、しきい値 5 件超過の警告対応)

kawaz 判断待ちの 5 件 (DR-0030/0031 関連 2 件、crate 移行、blocking-pool、
op-discovery) を除く 3 件を read して方針を確定した。**close できるものは無かった**:

| issue | 判定 | 理由 |
|---|---|---|
| 2026-07-06-daemon-register-help-output-oneshot | open のまま (観察待ち) | 調査済み。一回性事象で残仮説 (argv 誤り / PATH 上の別バイナリ) は次回 version upgrade 時の再現待ち。今できるコード修正は無い |
| 2026-06-15-changelog-md-adoption | pending-sublimation のまま | 意図的 pending。`--generate-notes` で短期ニーズ充足済み、1.0 pre-release 準備時に revisit する設計判断が本文に明記済み |
| 2026-06-14-ssh-agent-provider-architecture | idea のまま | Provider 再設計のビジョン記録。DR 化には kawaz との設計議論が必要で、touchid-blocks-blocking-pool の「案 Y vs Provider 吸収」判断とも連動する。単独で進めない |

= 10 件の内訳は「kawaz 判断待ち 5 + 観察待ち 1 + 意図的保留 2 + 直近起票の設計 idea 2」で、
放置による腐敗は無い。

## 未 push 58 コミットの push 前検証 (push 判断の材料)

CI が一度も走っていない (未 push のため) 58 コミット head (`a1549337`) に対し:

- **`just ci` (fmt --check + clippy -D warnings + test + release build): 全 pass** (exit 0)
- **`just check-version-bumped`: fail** — Cargo.toml 0.24.0 がリリース済み 0.24.0 と同値。
  push 時は `just bump-version` (patch/minor 選択) が先に必要
- **サニタイズ検査: クリーン** — diff 全文 (68 files, +9515/-618) を業務固有名詞
  (identifiers-* の単語リスト)、`/Users/kawaz` 絶対パス、secret 兆候 (private key /
  api key / password リテラル) で grep、ヒット 0

= push 判断が下りたら「bump-version → just push」だけで出せる状態。bump level は
crate 新設 (macos-process-inspect) + API 変更を含むため minor が妥当と思われる
(最終判断は kawaz)。
