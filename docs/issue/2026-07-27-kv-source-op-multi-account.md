---
title: kv define --source op:// が複数 op アカウント環境で失敗する
status: open
category: bug
created: 2026-07-27T18:17:47+09:00
last_read:
open_entered: 2026-07-27T18:17:47+09:00
wip_entered:
blocked_entered:
pending_entered:
discarded_entered:
resolved_entered:
discard_reason:
pending_reason:
close_reason:
blocked_by:
origin: claude-rules-personal
---

# kv define --source op:// が複数 op アカウント環境で失敗する

## 概要

`cache-warden kv define <KEY> --source "op://Private/<item>/<field>"` は
`define` 自体は成功するが、その後の `kv get` が以下のエラーで失敗する:

```
cache-warden: upstream failed: source command exited with status 1 (252 bytes of stderr, redacted)
```

## 背景

2026-07-27 に実機で観測。切り分け済みの事実:

1. 同じ URI を shell から `op read` すると成功する (値が返る)。
2. daemon と同じ最小 env で実行すると再現する:
   ```
   env -i HOME=$HOME PATH=/opt/homebrew/bin:/usr/bin:/bin op read "op://..."
   → [ERROR] could not read secret: error initializing client: multiple accounts found. Use the --account flag or set the OP_ACCOUNT environment variable to select an account.
   ```
3. daemon プロセス (launchd, gui/501) の env は PATH / HOME / SSH_AUTH_SOCK のみ。`OP_ACCOUNT` は無い。
4. kawaz の環境には op アカウントが 2 つある (zunsystem.1password.com / kawaz.1password.com)。
5. FDA (Full Disk Access) は原因ではない。daemon は `/Applications/CacheWarden.app` から起動しており、op 実行そのものは到達している。

回避策 (実証済み): `--command` 経由なら `--command-env` で `OP_ACCOUNT` を渡せて成功する。

```
cache-warden kv define KEY --command-env OP_ACCOUNT=kawaz.1password.com --command op read "op://Private/<item>/<field>"
→ kv get 成功
```

問題の所在: `--source` URI は内部で `op read <URI>` に落ちるが、そこに env を渡す手段が無い。
`--command-env` は `--command` 専用。

案として以下が考えられる (裏取りしてから採否を決めてほしい、実装判断は当事者に委ねる):

- (a) `--source` にも `--command-env` 相当を効かせる
- (b) config の `[op]` セクション等でデフォルトアカウントを指定できるようにする
- (c) `--source` URI に account を含める記法

検証環境: cache-warden CLI 0.25.0 / daemon 0.24.0 (版差は本件と無関係。`--command` 方式は
0.24 daemon で動作確認済み)、macOS 26.5.2

## 受け入れ条件

- [ ] 複数 op アカウント環境で `kv define --source op://...` → `kv get` が成功する

## TODO

<!-- wip 時のみ -->
