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
    if ! bump-semver vcs diff -q main@origin -- "$@" --excludes 'glob:crates/**/tests/**' 'glob:crates/**/*_test.rs'; then
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
    @echo "[hint] gh-monitor:watch-workflow --sha $(bump-semver vcs get commit-id --rev main) kawaz/cache-warden"

# ---------- utility ----------

# display crate version + binary --version output
version:
    echo "crate version: $(bump-semver get Cargo.toml)"
    if [ -x ./target/release/cache-warden ]; then echo "binary: $(./target/release/cache-warden --version)"; fi
