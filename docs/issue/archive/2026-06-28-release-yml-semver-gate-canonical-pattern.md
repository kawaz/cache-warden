---
title: release.yml semver gate を canonical pattern に合わせる (latest-release 並列 check 追加)
status: resolved
category: request
created: 2026-06-28T19:58:11+09:00
last_read:
open_entered: 2026-06-28T19:58:11+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered: 2026-07-04T09:46:53+09:00
discard_reason:
pending_reason:
close_reason: ["done:semver gate 追加 (commit da14588701dd)。canonical との差分: trigger が Cargo.toml のため既 release green-skip を gate より前に配置 (依存変更 push の CI 赤化防止)"]
blocked_by:
origin: bump-semver dogfood
---

# release.yml semver gate を canonical pattern に合わせる (latest-release 並列 check 追加)

## 概要

`gh release view` の重複確認だけで semver compare gate が無い現状を修正し、bump-semver canonical の release.yml (DR-0039) と同じ pattern に書き換える。

## 背景

bump-semver canonical (DR-0039) で release.yml の semver gate pattern が更新された。kawaz/die の dogfood で発覚した「downgrade を release.yml が止められない」事故型 (= `gh release view` 単独 gate で SemVer 比較してない) と同型の hole が本リポにもある。

## 現状 (release.yml L18-32 該当)

`gh release view` の重複確認だけで semver compare gate 無し。version を後退させて push しても release が作成されてしまう。

## 修正方針

bump-semver canonical の release.yml と DR-0039 を参照して、check-version step を以下 pattern に書き換え:

```yaml
FAIL=0
if LATEST_REL=$(bump-semver vcs get latest-release --repository "$REPO" 2>/dev/null); then
  if ! bump-semver compare gt "$CURRENT" "$LATEST_REL" -qq; then
    echo "::error::..."; FAIL=1
  fi
fi
if LATEST_TAG=$(bump-semver vcs get latest-tag --include-prerelease --vcs git 2>/dev/null); then
  if ! bump-semver compare gt "$CURRENT" "$LATEST_TAG" -qq; then
    echo "::error::..."; FAIL=1
  fi
fi
[ "$FAIL" = "1" ] && exit 1
gh release view "v${CURRENT}" --repo "$REPO" >/dev/null 2>&1 || echo "changed=true" >> "$GITHUB_OUTPUT"
```

## 参考

- bump-semver の `.github/workflows/release.yml` (canonical 実装)
- bump-semver の docs/decisions/DR-0039-release-yml-semver-gate-pattern.md (判断記録)
- kawaz/die dogfood 報告 (= 起票の発端): session 911732b3、2026-06-28

## 優先度

高 (= A 型 = downgrade 通る最弱の事故型)。bump-semver v0.43.0 release 後に着手推奨。

## 受け入れ条件

- [x] release.yml の check-version step が `bump-semver compare gt` による semver gate を含む
- [x] latest-release / latest-tag の両方を並列 check する pattern になっている
- [x] downgrade 時に release が止まることを確認 (gate コマンド列を実データでローカル
      シミュレーション: 0.22.2 → BLOCKED / 0.22.3 → 既 release green-skip /
      0.22.4 → PASS。CI 実機確認は次回 version bump push の workflow watch で行う)
