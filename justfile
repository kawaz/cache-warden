# cache-warden justfile
#
# Task runner. VCS 操作 (commit/push/clean check/diff) と翻訳ペアの
# 鮮度チェックは kawaz/bump-semver の `vcs` サブコマンドに委譲する
# (canonical = kawaz/bump-semver の justfile)。
#
# version file は Rust workspace の 2 つの crate Cargo.toml。bump-semver は
# basename で形式判定するので `crates/*/Cargo.toml` を一括で書き換えられる。

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
        bump-semver compare gt crates/cache-warden/Cargo.toml vcs:main@origin
    fi

# ---------- release flow ----------

# bump version (default: patch) and create a release commit
# 2 つの crate Cargo.toml を同時に書き換え、Cargo.lock を再生成してから commit
bump-version level="patch": ensure-clean
    bump-semver "$1" crates/cache-warden/Cargo.toml crates/cache-warden-cli/Cargo.toml --write --quiet
    cargo check --quiet
    bump-semver vcs commit -m "Release v$(bump-semver get crates/cache-warden/Cargo.toml)" crates/cache-warden/Cargo.toml crates/cache-warden-cli/Cargo.toml Cargo.lock

# push to origin/main with gates
push: ci check-outdated-translations check-version-bumped
    bump-semver vcs push --branch main --jj-bookmark-auto-advance
    @echo "[hint] gh-monitor:watch-workflow --sha $(bump-semver vcs get commit-id --rev main) kawaz/cache-warden"

# ---------- utility ----------

# display crate version + binary --version output
version:
    echo "crate version: $(bump-semver get crates/cache-warden/Cargo.toml)"
    if [ -x ./target/release/cache-warden ]; then echo "binary: $(./target/release/cache-warden --version)"; fi
