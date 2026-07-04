# local-issue tooling 周りの整備 (fork bug 観測 / ローカル skill 削除)

## local-issue plugin の fork $ARGUMENTS bug を追観測 → 上流に追記

triage 棚卸し作業中、`local-issue:read` (2 回) が no-op、`local-issue:update` が
`--status wip` をフィルタと誤解釈して単一 issue スコープを逸脱 (13 件全件 triage を
実行) する現象を観測した。fork に session context は届くが `$ARGUMENTS` が
substitution されていない疑い。

- **上流に起票済み**: kawaz/claude-local-issue `docs/issue/2026-07-03-skill-tool-fork-invocation-drops-arguments.md`
  (hyoui セッションの既存 issue に 2026-07-04 追観測として追記、commit de455c7)
- 利用側 workaround: read/update の契約 (last_read 記録 / path 限定 commit / 単一
  issue スコープ) を手動で踏んで代替した

## `.claude/skills/local-issue-list/` (ローカル簡易 list skill) を削除

- 由来: VCS 未管理 (`~/.config/git/ignore` の `local-*` パターンに偶然マッチして
  ignore されていた)。mtime 2026-06-22。plugin の写しではなく独自の bash 簡易実装
- 問題: frontmatter 形式 (migrate 後の正本形式) をパースできず、status 空 /
  概要 `---` を表示する壊れた状態だった
- 依存箇所: リポ内 grep でゼロ (justfile / hooks / docs から参照なし)
- 判断: plugin (`local-issue:list`) に一本化して削除。**VCS 外ファイルのため削除の
  commit 痕跡は無い** (本 journal が記録)。復元用バックアップはセッション scratchpad
  に退避したが session 終了で消える前提

## triage 棚卸しの結果

`docs/issue/archive/2026-07-03-docs-issue-triage-sweep.md` の close_reason と本文
追記に記録済み (idea3 / open6 / blocked2 / pending-sublimation1 / resolved1 +
followup1)。
