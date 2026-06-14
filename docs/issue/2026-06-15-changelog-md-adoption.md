# CHANGELOG.md 採用検討 (= リリースノート / breaking change 履歴の明示経路)

- status: open / 設計判断待ち (= kawaz の運用方針確認)
- 記録: 2026-06-15 (= DR-0024 G-2 実装中のペルソナ視点発掘で析出)
- 関連: DR-0024 §Consequences (= 「CHANGELOG / commit message に明示」記述あり) / DR-0025 §Consequences (= 「CHANGELOG.md に明示」記述あり) / release.yml (= 現状 trigger は `Cargo.toml` paths)

## 問題

DR-0024 / DR-0025 のような minor breaking change (= pre-1.0 で minor bump、API surface 変化、library consumer 影響あり) を user に伝える経路として **CHANGELOG.md が存在しない**:

- `ls CHANGELOG*` → no file
- release.yml は `gh release create` で release body を生成しているが、生成元データが何かは未確認 (= release notes generator か commit log か)
- DR (= `docs/decisions/DR-*.md`) は設計判断記録、user 向けではない
- README.md は機能紹介 + 使い方、change 履歴は載らない

問題:
- DR-0024 で `Store::new()` 削除 (= breaking、ただ pre-1.0)、`StoreBuilder` canonical 化、全 secret API に `&Capability` 引数追加 — user (= library consumer) が migration を判断できる情報源がない
- DR-0025 で `list()` / `keys()` deprecated、`list_filtered` 追加 — 同様

## 現状確認

実際にどう運用されてるか調査が必要:
- `gh release view v0.21.0 --repo kawaz/cache-warden` で過去 release の body 確認
- `release.yml` の release create step で body 生成手法確認 (= gh CLI の自動生成 / 自作 script / commit log 抽出 / 等)

```bash
gh release view v0.21.0 --repo kawaz/cache-warden  # 既存 release の body 確認
grep -n "gh release" .github/workflows/release.yml  # release body 生成箇所
```

調査結果次第で本 issue の方向が決まる:
- **case A**: release body が `gh release create --generate-notes` で自動生成済 → CHANGELOG.md 重複、本 issue 不要
- **case B**: release body が手書き or 簡素 → CHANGELOG.md 採用余地あり

## 採用候補

### 案 1: CHANGELOG.md 採用 (= Keep a Changelog 様式)

```markdown
# Changelog

## [Unreleased]

### Added
- DR-0024: capability-based access gate L1 (`Capability`, `StoreBuilder`, etc.)
- DR-0025: `list_filtered` + `ItemRef`

### Changed (= breaking)
- `Store::new()` → `Store::builder()`
- 全 secret-handling API に `&Capability` 引数必須化
- `set_failure_backoff()` → `StoreBuilder::failure_backoff()`

### Deprecated
- `Store::list()` / `Store::keys()` → `list_filtered` 推奨

## [0.21.0] - 2026-06-14
- DR-0022 failure backoff
- DR-0023 op discovery 非同期化
```

- Pros: user (= library consumer) に breaking change を一覧表示、migration ガイド埋め込み可
- Cons: 手動メンテ必要 (= bump-version task と同期する必要)、kawaz の time cost

### 案 2: release body 自動生成で代用 (= 現状維持)

`gh release create --generate-notes` で PR / commit titles から自動生成。kawaz のメンテコスト 0。

- Pros: メンテゼロ、bump-version → release.yml で完結
- Cons: breaking change の structured 表示は弱い (= commit body / DR ref が並列に並ぶ)、library consumer の migration 視点では追いにくい

### 案 3: release body を release.yml で構造化 (= CHANGELOG.md なし + 生成だけ自動化)

release.yml の `gh release create` step で commit log + DR file から structured body を生成。`docs/decisions/DR-*.md` の `Status: Accepted` を grep して該当 commit を引く形。

- Pros: 手書きゼロ、DR から自動引用
- Cons: 実装コスト (= release.yml 拡張)、scope creep リスク

### 案 4: scope 外 (= 何もしない)

- Pros: kawaz のメンテコスト 0、現状のリリース運用に余計な仕事を増やさない
- Cons: library consumer (= 仮の将来) が migration 判断する経路を持たない

## 判断軸

- **library consumer の存在見込み**: 現状 `cache-warden` crate を depend する外部リポは未確認 (= DR-0024 §Consequences で `pre-1.0 + 外部依存ゼロ` と整理済)、案 4 でも実害ない
- **将来 1.0 publishing 時の準備**: 1.0 直前で CHANGELOG 整備するなら早いほうがいい (= 各 release 時に書き溜める習慣)
- **kawaz の運用負担**: 手書き CHANGELOG は memory taxing、bump-version task に紐付けるとなおコスト
- **DR との関係**: DR は decision record、CHANGELOG は user-visible change record — 役割が違うので両方持つのが筋良いが scope は分ける

## 推奨

**案 2 + 案 1 の段階導入** を推奨:

1. **短期**: 案 2 (= 現状の release body 自動生成) で運用継続。kawaz は今すぐ何もしなくていい
2. **中期 (= 1.0 直前)**: 案 1 に移行。`CHANGELOG.md` の `## [Unreleased]` を bump-version 時にローテーション。手書きは設計判断単位 (= DR ごと) の 1 行で OK
3. **長期 (= ecosystem 拡大時)**: 案 3 のような自動化、release.yml で `docs/decisions/DR-*.md` の `Status: Accepted` から自動引用

## 実装スコープ (= 案 1 採用時)

1. `CHANGELOG.md` 新規 (= Keep a Changelog v1.1 様式、ja/en 両方 or 英語のみ判断)
2. justfile の bump-version task に「`CHANGELOG.md` の `[Unreleased]` を新 version section に rotate」を追加
3. README.md / README-ja.md からのリンク追加 (= 「change log は CHANGELOG.md を参照」)
4. (任意) release.yml の `gh release create --notes-file CHANGELOG.md` 経路

## 次のアクション

1. **kawaz に確認**: 上記 4 案のどれを採用するか (= 案 2 即決でも案 1 中期でも OK)
2. case A (= release body 自動生成済) なら本 issue close、case B なら案 1 着手判断
3. 案 1 採用なら別 PR で実装、本 session の DR-0024 / DR-0025 commit に `[Unreleased]` section を addendum で追加可

## 関連

- DR-0024 §Consequences (= 「CHANGELOG / commit message に明示」、本 issue 起票の trigger 文言)
- DR-0025 §Consequences (= 「`CHANGELOG.md` に明示」、同上)
- `release.yml` (= release body 生成箇所、現状確認対象)
- `justfile bump-version` task (= 案 1 採用時の改修対象)
- 参考: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- 参考: [Semantic Versioning 2.0.0](https://semver.org/) (= pre-1.0 minor breaking の扱い)
