# cache-warden justfile
#
# Task runner. VCS 操作 (commit/push/clean check/diff) と翻訳ペアの
# 鮮度チェックは kawaz/bump-semver の `vcs` サブコマンドに委譲する
# (canonical = kawaz/bump-semver の justfile)。
#
# version の正本は workspace root の Cargo.toml ([workspace.package].version)。
# 各 crate は version.workspace = true で継承する。

set shell := ["bash", "-euo", "pipefail", "-c"]

set script-interpreter := ["bash", "-euo", "pipefail"]

set positional-arguments

# default behaviour: alias for `list`
default: list

# show the recipe list
list:
    @just --list --unsorted

# ---------- atomic (lint / test / build) ----------

# cargo fmt --check + clippy (-D warnings)
check:
    cargo fmt --check --all
    cargo clippy --workspace -- -D warnings

# format 適用
fmt:
    cargo fmt --all

# cargo test (workspace 全体)
test: check
    cargo test --workspace

# build host target -> target/release/cache-warden
build: check
    cargo build --release -p cache-warden-cli

# build then run the local binary, forwarding all args
run *ARGS: build
    ./target/release/cache-warden "$@"

# draft-DR-0031 Phase 1.2: build cache-warden-approver, assemble its
# CacheWardenApprover.app bundle (debug profile) so `LSUIElement=YES` etc. can
# be honored, and exec it. `.app` bundle-lookup happens from the binary path
# (macOS walks up looking for `Contents/Info.plist`), so exec-ing
# `.app/Contents/MacOS/<name>` still gets the Info.plist applied.
[script]
approver-run *ARGS:
    cargo build -p cache-warden-approver
    APP="target/debug/CacheWardenApprover.app"
    rm -rf "$APP"
    mkdir -p "$APP/Contents/MacOS"
    cp crates/cache-warden-approver/Info.plist "$APP/Contents/Info.plist"
    printf 'APPL????' > "$APP/Contents/PkgInfo"
    ln -f target/debug/cache-warden-approver "$APP/Contents/MacOS/cache-warden-approver"
    exec "$APP/Contents/MacOS/cache-warden-approver" "$@"

# check + test + build (CI entry point)
ci: check test build

# ---------- gates (push の内部、利用者が直接叩くことほぼなし) ----------

# working copy is clean (dogfood: bump-semver vcs is clean)
[private]
ensure-clean:
    bump-semver vcs is clean

# translation pair freshness check via `bump-semver vcs outdated`
# 正本 = *-ja.md、翻訳先 = 同 basename の *.md (en)。翻訳先が未作成でも
# missing として fail する (= DESIGN.md を作るまで push は意図的に止まる)。
[private]
check-outdated-translations: ensure-clean
    bump-semver vcs outdated 'glob:**/*-ja.md' '$1/$2.md'

# fail if crate version changed paths が origin/main から進んでいないのに
# product code を触っている場合は push を止める。
# trigger paths = crates/ 配下 (test ファイルは bump 対象から除外)。
check-version-bumped: (_check-version-bumped "crates/")

# (helper) trigger paths に diff があれば version が origin/main より上がっているか検証
[private]
[script]
_check-version-bumped *target_paths:
    if ! bump-semver vcs diff -q main@origin --excludes 'glob:crates/**/tests/**' --excludes 'glob:crates/**/*_test.rs' -- "$@"; then
        # origin 側に version が読めない場合 (version 管理方式の導入前) は比較不能なのでスキップ
        if ref=$(bump-semver get vcs:main@origin:Cargo.toml -qq 2>/dev/null) && [ -n "$ref" ]; then
            bump-semver compare gt Cargo.toml "$ref"
        else
            echo "[check-version-bumped] origin/main の Cargo.toml に version が無いため比較をスキップ"
        fi
    fi

# ---------- release flow ----------

# bump version (default: patch) and create a release commit
# workspace root の Cargo.toml を書き換え、Cargo.lock を再生成してから commit
bump-version level="patch": ensure-clean
    bump-semver "$1" Cargo.toml --write --quiet
    cargo check --quiet
    bump-semver vcs commit -m "Release v$(bump-semver get Cargo.toml)" Cargo.toml Cargo.lock

# push to origin/main with gates
push: ci check-outdated-translations check-version-bumped
    bump-semver vcs push --branch main --jj-bookmark-auto-advance
    @cmux-msg notify --self --text "Monitor で 'just watch' を起動して" 2>/dev/null || true

# push 済み main の CI/Release workflow を SHA-pinned で監視 (全 check 終了で自動 exit)
# watch-workflow.sh は gh-monitor plugin 提供 (PATH に latest scripts/ が通っている前提)
watch:
    watch-workflow.sh --sha $(bump-semver vcs get commit-id --rev main) --on-success release.yml 'just on-success-release' kawaz/cache-warden

# release.yml workflow が success になった時に AI が実行する action
# (watch-workflow の `--on-success release.yml 'just on-success-release'` 経由で
# 通知 event に `[ACTION:release.yml] just on-success-release` が emit される)
on-success-release:
    # tap repo を直接 git pull (= `brew update` 全 tap 巡回より速い)
    git -C "$(brew --repository)/Library/Taps/kawaz/homebrew-tap" pull --ff-only
    brew upgrade --cask kawaz/tap/cache-warden
    cache-warden --version
    just daemon-graceful-restart

# brew upgrade 後に常駐 daemon を in-place で新バイナリへ切り替える (graceful
# restart)。bin / socket / expected_path は隔離テスト用に位置引数で上書き可能
# (例: `just daemon-graceful-restart ./target/release/cache-warden
# /tmp/test.sock ./target/release/cache-warden`)。socket が空なら
# デフォルトソケットを使う (= `--socket` を付けない)。
daemon-graceful-restart bin="cache-warden" socket="" expected_path="/Applications/CacheWarden.app/Contents/MacOS/cache-warden":
    #!/usr/bin/env bash
    set -euo pipefail

    bin="{{bin}}"
    socket="{{socket}}"
    expected_path="{{expected_path}}"

    # socket 指定は関数で吸収する (空配列 + `set -u` は bash 3.2 でエラーに
    # なるため、配列展開ではなく分岐で `--socket` を付ける)。CLI の第 1 引数は
    # コマンド名固定で、`--socket` は残り引数のどこにあっても拾われるので末尾に付ける。
    cw() {
        if [ -n "$socket" ]; then
            "$bin" "$@" --socket "$socket"
        else
            "$bin" "$@"
        fi
    }

    # 1. daemon 生存確認: ping が失敗するなら daemon は稼働していない
    #    (= 次回起動時に新しいバイナリが使われるので何もしなくてよい)
    if ! cw ping >/dev/null 2>&1; then
        echo "[note] daemon は稼働していないため再起動は不要。次回起動時に新しいバイナリが使われます。"
        exit 0
    fi

    # 2. restart 前の状態取得 (pid / version / entries 件数)
    status_before="$(cw status)"
    pid_before="$(echo "$status_before" | sed -nE 's/^daemon: .* \(pid ([0-9]+)\)$/\1/p')"
    version_before="$(echo "$status_before" | sed -nE 's/^daemon: [^ ]+ ([^ ]+) \(pid [0-9]+\)$/\1/p')"
    entries_before="$(echo "$status_before" | grep -c '^  ' || true)"

    if [ -z "$pid_before" ]; then
        echo "[warn] daemon status から pid を取得できませんでした。手動確認してください: cache-warden daemon status"
        exit 0
    fi

    # 3. バイナリパス一致判定
    #    lsof の txt (= 実行イメージ) から絶対パスを取る。ps -o comm= は
    #    argv[0] や短縮名を返すことがあり不確実なため lsof 経路にする。
    #    `-F n` のフィールド出力なら空白を含むパスでも壊れない (awk の
    #    $NF 抽出はパス中の空白で切れる)。最初の txt = 実行バイナリ本体。
    actual_path="$(lsof -a -p "$pid_before" -d txt -F n 2>/dev/null | sed -n 's/^n//p' | head -1)"
    if [ "$actual_path" != "$expected_path" ]; then
        echo "[warn] daemon は想定外のバイナリ (${actual_path:-不明}) で稼働中。graceful restart しても brew で更新したバイナリには切り替わらないためスキップします。手動確認してください。"
        exit 0
    fi

    # 4. restart 実行 (拒否 = 旧バージョン daemon が稼働継続、fallback は手動介入)
    if ! cw daemon restart --graceful; then
        echo "[warn] graceful restart が拒否されました: 旧バージョンの daemon が稼働継続しています。手動で再起動してください: cache-warden daemon register"
        exit 0
    fi

    # 5. 復帰待ち: in-place exec の完了は外部プロセスの状態遷移なので polling でしか
    #    観測できない。0.2 秒間隔・最大 10 秒の bounded poll。
    ready=0
    for _ in $(seq 1 50); do
        if cw ping >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.2
    done
    if [ "$ready" -ne 1 ]; then
        echo "[error] daemon が復帰しません。状態確認: cache-warden daemon status"
        exit 1
    fi

    # 6. restart 後の検証
    status_after="$(cw status)"
    pid_after="$(echo "$status_after" | sed -nE 's/^daemon: .* \(pid ([0-9]+)\)$/\1/p')"
    version_after="$(echo "$status_after" | sed -nE 's/^daemon: [^ ]+ ([^ ]+) \(pid [0-9]+\)$/\1/p')"
    entries_after="$(echo "$status_after" | grep -c '^  ' || true)"

    if [ -z "$pid_after" ]; then
        echo "[warn] restart 後の daemon status から pid を取得できず、状態保持を検証できませんでした。手動確認してください: cache-warden daemon status"
        exit 0
    fi

    if [ "$pid_after" = "$pid_before" ]; then
        echo "[note] graceful restart 完了: pid ${pid_after} 維持, ${version_before} -> ${version_after}, entries ${entries_before} -> ${entries_after} 件保持"
    else
        echo "[warn] pid が変わりました (cold start 退化, ${pid_before} -> ${pid_after})。in-memory cache は失われ再認証が必要です。"
    fi

    if [ "$entries_after" -lt "$entries_before" ]; then
        echo "[warn] entries 件数が減りました (${entries_before} -> ${entries_after})。手動確認してください: cache-warden status"
    fi

# ---------- utility ----------

# display crate version + binary --version output
version:
    echo "crate version: $(bump-semver get Cargo.toml)"
    if [ -x ./target/release/cache-warden ]; then echo "binary: $(./target/release/cache-warden --version)"; fi
    if command -v cache-warden >/dev/null 2>&1; then echo "brew binary: $(cache-warden --version)"; fi
